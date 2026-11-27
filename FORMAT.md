# SecureSQLite format v1

This document is normative for the on-disk format. Any change to labels, order,
lengths, endianness, or derivation is a format change and requires a new format
version, migration, and updated vectors.

## Constants

| Parameter | Value |
|---|---:|
| Database and ciphertext format version | 1 |
| Master key / derived roots / AES key | 32 bytes |
| Database identity and HKDF salt (`database_id`) | 32 random bytes |
| Per-message salt | 32 random bytes |
| GCM nonce | 12 bytes |
| GCM tag | 16 bytes |
| HMAC output | 32 bytes, untruncated |
| Maximum plaintext per helper | 16 MiB |
| Table / Column | 1–255 bytes each |
| Scope | 0–1024 bytes |
| Record ID | 1–1024 bytes |

Context strings are valid UTF-8 without NUL or control characters. They are not
normalized. `nil` and an empty byte slice both represent empty plaintext.

## Canonical encoding `E`

`E(parts...)` is the ordered concatenation of:

```text
uint32_big_endian(len(part)) || part
```

There is no component count. Each domain has a fixed arity known to both sides.
Version bytes inside `E` are the binary byte `0x01`, not ASCII `1`. The internal
parser must consume all input and reject truncation or trailing bytes.

## Key separation

```text
enc_root = HKDF32(master, database_id, E("securesqlite/v1/encryption"))
idx_key  = HKDF32(master, database_id, E("securesqlite/v1/index"))
meta_key = HKDF32(master, database_id, E("securesqlite/v1/metadata"))
```

`HKDF32` is full HKDF-SHA256 (Extract + Expand) with a 32-byte output. In Go:

```go
hkdf.Key(sha256.New, ikm, salt, info, 32)
```

where `info` is the canonical encoding of the label. `meta_key` is used only
during initialization and verification. Do not derive keys for other purposes
from these roots.

`database_id` is generated once with `crypto/rand`, must not be all zero, and is
both a public identifier and the HKDF salt. Copies and restores preserve it; an
independent database gets a new value.

## Per-message encryption

For every `Encrypt`, generate a new 32-byte `message_salt`:

```text
message_key = HKDF32(enc_root, message_salt, E("securesqlite/v1/message-key"))
```

Use AES-256-GCM with `cipher.NewGCMWithRandomNonce`, which generates a random
12-byte nonce and prefixes it to the ciphertext/tag. Never supply a nonce
manually in production and never cache message keys.

```text
aad = E("securesqlite/v1/aad", 0x01, database_id,
        table, column, scope, record_id, message_salt)

ciphertext = version[1] || message_salt[32] || nonce[12] || encrypted[N] || tag[16]
```

Fixed overhead is **61 bytes**. The version, salt, and nonce are public. GCM
authenticates all of them through the AAD. The record ID must exist before
encryption and must remain immutable.

## Blind indexes

```text
index = HMAC-SHA256(idx_key,
    E("securesqlite/v1/blind-index", database_id, table, column, scope, plaintext))
```

The output is 32 bytes, untruncated. There is no record ID and no random salt, so
equal plaintext in the same domain produces the same index. The record ID is not
part of the index. `VerifyIndex` recomputes the value and compares it with
`hmac.Equal`.

## Metadata

```sql
CREATE TABLE _securesqlite (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    database_id BLOB NOT NULL CHECK (length(database_id) = 32),
    verification BLOB NOT NULL CHECK (length(verification) = 32)
) STRICT;
```

Exactly one row with `id = 1` and `format_version = 1`:

```text
verification = HMAC-SHA256(meta_key,
    E("securesqlite/v1/metadata-verifier", 0x01, database_id))
```

`Open` validates the object is an ordinary table, exactly one row with ID 1, the
supported version, expected SQL types and lengths, a non-zero `database_id`, and
the verification MAC. It does not trust table constraints alone.

## Test vector

Inputs:

```text
key              = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
database_id      = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
table            = users
column           = email
scope            = tenant-1
record_id        = user-1
plaintext        = alice@example.com
message_salt     = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
nonce            = a0a1a2a3a4a5a6a7a8a9aaab
```

Derived values:

```text
enc_root         = 439fd1725958d503c444ea91beae4e5c41abf9ee6b883fa73dc6e477fc1c4052
message_key      = dc3013bffe7bd154e4512c6eb1653e7f0c3e5fe19a1fb83163fcc2b3d3cda590
aad              = 0000001373656375726573716c6974652f76312f616164000000010100000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000005757365727300000005656d61696c0000000874656e616e742d3100000006757365722d3100000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
ciphertext       = 01808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab365c3a12473169cfed2039d6b9cea661e0f651cdc0d090baa107ed0eed0c57fad6
idx_key          = 5c26a6b83ecc8100a8e18a7f5e3a2f6ab3593285b6da6a3d6c23340790e38fd0
blind_index      = d3ca386849e53aaecb4cd23f32a77bce646109b6cea5621c3416dd3fa71734f2
meta_key         = 72ea65f422b203f12a79cd4564512e02d5f948f8332532b6dd7d8a0742a0eaff
verification     = 9cbe3bdf9496adbccb6e4637d0d456acd7a96fa04ef744693ffa8600a22475f8
```

The nonce is fixed only for this vector. Production `Encrypt` always uses a
random nonce through `NewGCMWithRandomNonce`.

`Decrypt` must accept the ciphertext above for the same context and record ID.
The vector is also exercised by the test suite.

## Change policy

- Never reuse a label for another purpose.
- Never change the order, length prefix, or endianness in place.
- A new format version must be explicit, documented here, and accompanied by an
  offline migration procedure. Do not reinterpret existing data silently.
- Blind indexes are bound to the key and `database_id`; rotating either requires
  recomputing all indexes.
