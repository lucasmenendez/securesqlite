# securesqlite

Selective field encryption and blind indexes for SQLite, built on Go's
`database/sql` and `modernc.org/sqlite`.

> **Status: experimental.** The design and implementation have not been
> independently audited. Do not treat this package as a substitute for
> full-database encryption, access control, or domain integrity checks.

## What it is and is not

`securesqlite` encrypts individual values before they reach SQLite and provides
deterministic blind indexes for exact-match lookups. It is not SQLCipher: it
does not encrypt pages or files, does not parse SQL, and does not hide schema,
table names, column names, row counts, sizes, or query patterns.

The package keeps the normal `database/sql` API. A `*securesqlite.DB` embeds a
`*sql.DB`, so existing queries work unchanged. The caller decides which values
to encrypt and which fields to index.

## Requirements

- Go 1.27.4 or newer.
- A local filesystem path for the database; network filesystems and SQLite
  URIs are not supported.
- `CGO_ENABLED=0` is supported and tested.

## Install

```sh
go get github.com/lucasmenendez/securesqlite
```

The only runtime dependency is `modernc.org/sqlite`; cryptography uses the Go
standard library.

## Quick start

```go
package main

import (
	"context"
	"fmt"

	"github.com/lucasmenendez/securesqlite"
)

func main() {
	key, err := securesqlite.LoadKeyFile("secrets/db.key")
	if err != nil {
		panic(err)
	}
	db, err := securesqlite.Open(context.Background(), "data/app.db", key)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	field := securesqlite.Field{Table: "users", Column: "email", Scope: "tenant-1"}
	ciphertext, index, err := db.Protect(field, "user-1", []byte("alice@example.com"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x %x\n", ciphertext, index)
}
```

The example in [`examples/users`](examples/users/main.go) is a complete
init/demo program:

```sh
mkdir -p secrets data
chmod 700 secrets data
(
  umask 077
  set -C
  openssl rand -hex 32 > secrets/db.key
)
go run ./examples/users init
go run ./examples/users demo
```

## Keys

- Generate one random 32-byte key per database with a CSPRNG.
- Never reuse a key across applications or databases.
- Passwords are not keys. Use a password KDF if you need to derive one.
- Keep the key separate from the database and from database backups.

From `openssl`:

```sh
umask 077
set -C
openssl rand -hex 32 > secrets/db.key
```

From Go:

```go
key, err := securesqlite.GenerateKey()
if err != nil {
	return err
}
f, err := os.OpenFile("secrets/db.key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
if err != nil {
	return err
}
_, writeErr := io.WriteString(f, key.Hex()+"\n")
closeErr := f.Close()
if err := errors.Join(writeErr, closeErr); err != nil {
	return err
}
```

`Key.Hex` is a deliberate secret export. `fmt`, `slog`, and `%#v` output are
redacted. There is no zeroization guarantee in Go.

`LoadKeyFile` expects a regular file with exactly 64 hexadecimal characters and
an optional single LF or CRLF. It reads at most 256 bytes, rejects FIFOs and
devices, and never includes file contents in errors. A symlink to a regular file
is allowed for orchestrator-mounted secrets; the file mode is not enforced
because Docker and Kubernetes may mount secrets read-only.

## API

```go
const KeySize = 32

type Key struct{ /* opaque */ }
func GenerateKey() (Key, error)
func ParseKey(encoded string) (Key, error)
func LoadKeyFile(path string) (Key, error)
func (k Key) Hex() string

type Field struct {
	Table  string
	Column string
	Scope  string
}

type DB struct {
	*sql.DB
	// ...
}

func Create(ctx context.Context, path string, key Key, opts ...Option) (*DB, error)
func Open(ctx context.Context, path string, key Key, opts ...Option) (*DB, error)

func WithBusyTimeout(timeout time.Duration) Option
func WithMaxOpenConns(n int) Option
func WithMaxIdleConns(n int) Option
```

`DB` implements `Protector`:

```go
Encrypt(field Field, recordID string, plaintext []byte) ([]byte, error)
Decrypt(field Field, recordID string, ciphertext []byte) ([]byte, error)
Index(field Field, plaintext []byte) ([]byte, error)
Protect(field Field, recordID string, plaintext []byte) (ciphertext, index []byte, err error)
VerifyIndex(field Field, plaintext, index []byte) error
```

### Create vs Open

- `Create` reserves a new file with `O_CREATE|O_EXCL`, initializes metadata, and
  configures WAL. It fails with `ErrAlreadyExists` if the file exists.
- `Open` requires an existing regular file and verifies metadata and the key.
  It never creates a file and never initializes a file that lacks metadata.
- `Open` rejects a final symlink. The parent directory must exist.
- A failed `Create` can leave an empty or partially initialized file. Inspect it
  with `Open` and recover manually; never overwrite it or regenerate the key.

The embedded `db.DB` field is the plain `*sql.DB`. Do not reassign it. A `DB`
must not be copied after initialization. Crypto helpers work after `Close`
because they do not use the pool; SQL methods do not.

### Value limits

| Item | Limit |
|---|---:|
| Plaintext per helper | 16 MiB |
| Table / Column | 1–255 bytes |
| Scope | 0–1024 bytes |
| RecordID | 1–1024 bytes |

Context strings must be valid UTF-8 without NUL or control characters. They are
not normalized, trimmed, or lowercased. `nil` and `[]byte{}` both mean empty
plaintext. SQL NULL handling is the caller's responsibility.

## Usage patterns

### Store and retrieve

```go
field := securesqlite.Field{Table: "users", Column: "email", Scope: tenantID}

ciphertext, index, err := db.Protect(field, user.ID, []byte(email))
if err != nil {
	return err
}
_, err = db.Exec(`INSERT INTO users (id, email, email_index) VALUES (?, ?, ?)`,
	user.ID, ciphertext, index)
```

`user.ID` must exist before encryption and must never change. Do not use a
ROWID assigned after the INSERT.

### Find by exact match

```go
index, err := db.Index(field, []byte(email))
if err != nil {
	return err
}
var id string
var ciphertext, storedIndex []byte
err = db.QueryRow(`SELECT id, email, email_index FROM users WHERE email_index = ?`, index).
	Scan(&id, &ciphertext, &storedIndex)
if err != nil {
	return err
}
plaintext, err := db.Decrypt(field, id, ciphertext)
if err != nil {
	return err
}
if err := db.VerifyIndex(field, plaintext, storedIndex); err != nil {
	return err
}
if string(plaintext) != email {
	return securesqlite.ErrIndexMismatch
}
```

Verification detects a corrupted stored index, but it does not authenticate the
SQL `WHERE` clause, detect omitted rows, or guarantee uniqueness under hostile
writes.

### Normalization

`Index` is exact-match only. If your domain needs case-insensitive or Unicode
normalization, normalize before `Encrypt`/`Index` and use exactly the same
normalized form for inserts, updates, lookups, and verification. The package
does not impose email or Unicode rules.

### Transactions

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
defer tx.Rollback()

ciphertext, index, err := db.Protect(field, userID, []byte(email))
if err != nil {
	return err
}
if _, err := tx.ExecContext(ctx, `UPDATE users SET email = ?, email_index = ? WHERE id = ?`,
	ciphertext, index, userID); err != nil {
	return err
}
return tx.Commit()
```

Crypto helpers acquire no connection, so they are safe while a transaction is
open. Always update ciphertext and its index together.

### Multi-tenant data

Put the tenant in `Field.Scope`. The same plaintext produces different indexes
in different scopes. Use the tenant as a SQL constraint as well:

```sql
UNIQUE (tenant_id, email_index)
```

The scope is not an authorization check. Read it from trusted authentication
context, not from an untrusted row or request field.

## SQLite configuration

The library sets these per connection through the DSN:

| Pragma | Value |
|---|---|
| `foreign_keys` | `ON` |
| `synchronous` | `FULL` |
| `busy_timeout` | `5000` ms by default |
| `temp_store` | `MEMORY` |
| `trusted_schema` | `OFF` |

`journal_mode=WAL` is enabled once after metadata verification and checked to
return `wal`. The defaults can be adjusted with `WithBusyTimeout`,
`WithMaxOpenConns`, and `WithMaxIdleConns`. The default pool is one connection.
A busy timeout does not replace context deadlines.

## Security limitations

This package provides selective confidentiality, not whole-database integrity:

- It does not hide schema, row counts, value sizes, or access patterns.
- Blind indexes reveal equality and frequency within a domain.
- It does not detect replay, rollback, deleted rows, or a complete database
  substitution. Use a different key per database and protect backups.
- It does not authenticate ACLs, roles, balances, public keys, or application
  authorization decisions.
- It cannot protect against a compromised process, host, key, or arbitrary SQL
  execution.
- Do not open SQLite files supplied by untrusted third parties. Metadata
  authentication happens after SQLite has started parsing the file.
- Passwords must be hashed with a password KDF, not encrypted with this package.
- Large documents need their own encrypted storage.

See [`SECURITY.md`](SECURITY.md) and [`FORMAT.md`](FORMAT.md) for details.

## Backup and restore

Backups are an operational procedure, not an API in v1:

1. Stop every process that opens the database.
2. Open with the correct key and run `PRAGMA wal_checkpoint(TRUNCATE)`; verify
   that the result has no busy state and no pending frames.
3. Close the database.
4. Copy the main database file to a new protected location.
5. Store the key separately from the backup, with restricted access.
6. Restore to a new path and validate with `Open`, `PRAGMA integrity_check`,
   `PRAGMA foreign_key_check`, and domain-level decrypt/index checks.

Do not copy a live `.db` file on its own, and do not delete WAL/SHM files
manually.

## Key rotation and migration

There is no online rekey and no keyring in v1. Rotation is an offline full
migration:

1. Stop writers and make a verified backup.
2. Generate a new key.
3. Create a new database.
4. Read, decrypt, and verify every row from the old database.
5. Re-encrypt and recompute indexes with the new database.
6. Validate counts, constraints, and domain invariants.
7. Publish the new database path and key together, reversibly.

Never replace the key of a live database in place.

## Docker

```yaml
services:
  app:
    image: myapp:latest
    environment:
      DB_PATH: /data/app.db
      DB_ENCRYPTION_KEY_FILE: /run/secrets/db_key
    volumes:
      - app_data:/data
    secrets:
      - db_key
secrets:
  db_key:
    file: ./secrets/db.key
volumes:
  app_data:
```

The application should call `LoadKeyFile` and `Open` explicitly. Compose file
secrets are not a KMS. Do not put keys in Dockerfiles, build arguments, data
volumes, or the repository.

## Development

```sh
go fmt ./...
go vet ./...
go test ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build ./...
go test -race ./...
go test -run='^$' -fuzz=FuzzDecrypt -fuzztime=30s .
go test -bench=. -benchmem ./...
```

The GitHub Actions CI runs the matrix on Linux/macOS amd64/macOS arm64/Windows,
plus race, coverage, fuzzing, benchmarks, and `govulncheck`. The Go version is
read from `go.mod`. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution
licensing.

## Releases

Releases are created from merged pull requests:

Create the labels `release`, `release-candidate`, `bump:major`, `bump:minor`,
and `bump:patch` in the repository first.

- Add the `release-candidate` label to create `vX.Y.Z-rcN` (prerelease).
- Add the `release` label to create `vX.Y.Z` and its GitHub Release.
- `release` takes priority if both labels are present.
- `bump:major`, `bump:minor`, and `bump:patch` select the next base for a
  release candidate; the default is patch.
- `bump:*` is ignored for stable releases. A stable release always promotes the
  base of the highest active release candidate.
- `version:X.Y.Z` (or `version:vX.Y.Z`) overrides the calculated version.

Tags and releases are created with the workflow's `GITHUB_TOKEN`; if tag
protection blocks it, configure a GitHub App or PAT with the required bypass.
Release runs are serialized. If rapid merges cause a pending run to be dropped,
rerun the workflow or create the tag/release manually from the merge commit.

## Troubleshooting

- `ErrKeyVerification`: wrong key or modified metadata. Stop and investigate;
  do not reinitialize the database.
- `ErrNotInitialized`: the file has no metadata table. Do not treat it as a
  request to initialize an existing file.
- `ErrAlreadyExists`: `Create` only works on a new path.
- `SQLITE_BUSY`: retry complete, idempotent transactions at the call site; do
  not add silent global retries.
- `journal_mode` is not `wal`: the filesystem may not support WAL. Do not use
  network filesystems.

## License

`securesqlite` is licensed under **AGPL-3.0-only**.

Copyright (C) 2026 Lucas Menendez.

If you run a modified version as a network service, section 13 of the AGPL
requires you to offer the Corresponding Source to users interacting with it
remotely. See [`LICENSE`](LICENSE) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
