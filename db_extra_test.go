// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func rawSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	p := filepath.ToSlash(path)
	if runtime.GOOS == "windows" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := &url.URL{Scheme: "file", Path: p}
	q := u.Query()
	q.Set("mode", "rwc")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestZeroKey(t *testing.T) {
	var zero Key
	if _, err := Create(context.Background(), filepath.Join(t.TempDir(), "app.db"), zero); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Create error = %v, want ErrInvalidKey", err)
	}
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "app.db"), zero); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Open error = %v, want ErrInvalidKey", err)
	}
}

func TestNilContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	//lint:ignore SA1012 nil contexts are accepted by this API.
	db, err := Create(nil, path, testKey(t)) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Encrypt(testField(), "user-1", []byte("value")); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(context.Background(), dir, testKey(t)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestParentIsFile(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), filepath.Join(parent, "app.db"), testKey(t)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestCreatePermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires a non-root POSIX user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if _, err := Create(context.Background(), filepath.Join(dir, "app.db"), testKey(t)); err == nil {
		t.Fatal("expected a permission error")
	}
}

func TestLoadKeyFilePermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires a non-root POSIX user")
	}
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte(testKeyHex), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("expected a permission error")
	}
}

func TestReadMetadataClosedDB(t *testing.T) {
	db, _ := testDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readMetadata(context.Background(), db); err == nil {
		t.Fatal("expected an error from a closed database")
	}
}

func TestRawMetadataWrongTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong-types.db")
	raw := rawSQLite(t, path)
	if _, err := raw.Exec(`CREATE TABLE _securesqlite (
		id INTEGER PRIMARY KEY,
		format_version TEXT NOT NULL,
		database_id BLOB NOT NULL,
		verification BLOB NOT NULL
	);
	INSERT INTO _securesqlite (id, format_version, database_id, verification)
	VALUES (1, '1', zeroblob(32), zeroblob(32));`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("error = %v, want ErrInvalidMetadata", err)
	}
}

func TestRawMetadataShortBlobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short-blobs.db")
	raw := rawSQLite(t, path)
	if _, err := raw.Exec(`CREATE TABLE _securesqlite (
		id INTEGER PRIMARY KEY,
		format_version INTEGER NOT NULL,
		database_id BLOB NOT NULL,
		verification BLOB NOT NULL
	);
	INSERT INTO _securesqlite (id, format_version, database_id, verification)
	VALUES (1, 1, x'00', x'00');`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("error = %v, want ErrInvalidMetadata", err)
	}
}

func TestRawMetadataNegativeVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "negative-version.db")
	raw := rawSQLite(t, path)
	if _, err := raw.Exec(`CREATE TABLE _securesqlite (
		id INTEGER PRIMARY KEY,
		format_version INTEGER NOT NULL,
		database_id BLOB NOT NULL,
		verification BLOB NOT NULL
	);
	INSERT INTO _securesqlite (id, format_version, database_id, verification)
	VALUES (1, -1, zeroblob(32), zeroblob(32));`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("error = %v, want ErrInvalidMetadata", err)
	}
}

func TestRawMetadataVirtualTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "virtual.db")
	raw := rawSQLite(t, path)
	if _, err := raw.Exec(`CREATE VIRTUAL TABLE _securesqlite USING fts5(
		id, format_version, database_id, verification
	);`); err != nil {
		t.Skipf("FTS5 is not available: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("error = %v, want ErrInvalidMetadata", err)
	}
}

func TestOpenUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires a non-root POSIX user")
	}
	path := filepath.Join(t.TempDir(), "unreadable.db")
	if err := os.WriteFile(path, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); err == nil {
		t.Fatal("expected an open error")
	}
}
