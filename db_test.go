// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCreateOpenRoundTrip(t *testing.T) {
	db, path := testDB(t)
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Encrypt(testField(), "user-1", []byte("alice@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Encrypt(testField(), "user-2", []byte("bob@example.com")); err != nil {
		t.Fatal(err)
	}
}

func TestPragmas(t *testing.T) {
	db, _ := testDB(t, WithBusyTimeout(1500*time.Millisecond), WithMaxOpenConns(2), WithMaxIdleConns(2))
	ctx := context.Background()
	if got := db.Stats().MaxOpenConnections; got != 2 {
		t.Fatalf("MaxOpenConnections = %d, want 2", got)
	}

	var journal string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if journal != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journal)
	}

	conns := make([]*sql.Conn, 0, 2)
	for range 2 {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	for i, conn := range conns {
		checks := []struct {
			pragma string
			want   int
		}{
			{`PRAGMA foreign_keys`, 1},
			{`PRAGMA synchronous`, 2},
			{`PRAGMA busy_timeout`, 1500},
			{`PRAGMA temp_store`, 2},
			{`PRAGMA trusted_schema`, 0},
		}
		for _, check := range checks {
			var got int
			if err := conn.QueryRowContext(ctx, check.pragma).Scan(&got); err != nil {
				t.Fatalf("conn %d %s: %v", i, check.pragma, err)
			}
			if got != check.want {
				t.Fatalf("conn %d %s = %d, want %d", i, check.pragma, got, check.want)
			}
		}
	}
}

func TestCreateExisting(t *testing.T) {
	db, path := testDB(t)
	_ = db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), path, testKey(t)); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("error = %v, want ErrAlreadyExists", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Create modified an existing database")
	}
}

func TestOpenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open created the database file")
	}
}

func TestOpenEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

func TestWrongKey(t *testing.T) {
	db, path := testDB(t)
	_ = db.Close()
	other := testKey(t)
	other.b[0] ^= 0xff
	if _, err := Open(context.Background(), path, other); !errors.Is(err, ErrKeyVerification) {
		t.Fatalf("error = %v, want ErrKeyVerification", err)
	}
}

func TestCloseSemantics(t *testing.T) {
	db, _ := testDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Encrypt(testField(), "user-1", []byte("value")); err != nil {
		t.Fatalf("crypto helpers after Close: %v", err)
	}
	if err := db.Ping(); err == nil {
		t.Fatal("SQL methods still work after Close")
	}
}

func TestZeroDB(t *testing.T) {
	var zero DB
	if _, err := zero.Encrypt(testField(), "user-1", []byte("value")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("zero DB error = %v, want ErrNotInitialized", err)
	}
	var nilDB *DB
	if _, err := nilDB.Index(testField(), []byte("value")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("nil DB error = %v, want ErrNotInitialized", err)
	}
}

func TestOptions(t *testing.T) {
	valid := [][]Option{
		nil,
		{WithBusyTimeout(0)},
		{WithBusyTimeout(60 * time.Second)},
		{WithMaxOpenConns(1)},
		{WithMaxOpenConns(4), WithMaxIdleConns(0)},
	}
	for _, opts := range valid {
		if _, err := newConfig(opts); err != nil {
			t.Fatalf("newConfig(%v) = %v", opts, err)
		}
	}

	invalid := [][]Option{
		{WithBusyTimeout(-time.Millisecond)},
		{WithBusyTimeout(60*time.Second + time.Millisecond)},
		{WithBusyTimeout(time.Millisecond / 2)},
		{WithMaxOpenConns(0)},
		{WithMaxIdleConns(-1)},
		{WithMaxOpenConns(1), WithMaxIdleConns(2)},
		{nil},
	}
	for _, opts := range invalid {
		if _, err := newConfig(opts); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("newConfig(%v) error = %v, want ErrInvalidConfig", opts, err)
		}
	}
}

func TestCreateRejectsBadPaths(t *testing.T) {
	dir := t.TempDir()
	cases := []string{
		"",
		"bad\x00path.db",
		":memory:",
		"file:" + filepath.Join(dir, "x.db"),
		"file://" + filepath.Join(dir, "x.db"),
		"//server/share/x.db",
		filepath.Join(dir, "missing", "x.db"),
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			if _, err := Create(context.Background(), path, testKey(t)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestPathEscaping(t *testing.T) {
	names := []string{"space dir", "hash#dir", "question?dir", "percent%dir", "unicode-ñ"}
	if runtime.GOOS == "windows" {
		names = []string{"space dir", "unicode-ñ"}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "app.db")
			db, err := Create(context.Background(), path, testKey(t))
			if err != nil {
				t.Fatal(err)
			}
			ct, err := db.Encrypt(testField(), "user-1", []byte("value"))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(context.Background(), path, testKey(t))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			pt, err := reopened.Decrypt(testField(), "user-1", ct)
			if err != nil {
				t.Fatal(err)
			}
			if string(pt) != "value" {
				t.Fatalf("plaintext = %q, want value", pt)
			}
		})
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}
	db, path := testDB(t)
	_ = db.Close()
	link := filepath.Join(filepath.Dir(path), "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), link, testKey(t)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestCreateFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	db, path := testDB(t)
	_ = db.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
}

func TestCanceledContext(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(dir, "app.db")
	if _, err := Create(ctx, path, testKey(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Create created a file with a canceled context")
	}
}

func TestWALPersists(t *testing.T) {
	db, path := testDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var mode string
	if err := reopened.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}

func TestMetadataCorruption(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*DB) error
		want    error
	}{
		{
			name: "missing table",
			corrupt: func(db *DB) error {
				_, err := db.Exec(`DROP TABLE _securesqlite`)
				return err
			},
			want: ErrNotInitialized,
		},
		{
			name: "view instead of table",
			corrupt: func(db *DB) error {
				if _, err := db.Exec(`DROP TABLE _securesqlite`); err != nil {
					return err
				}
				_, err := db.Exec(`CREATE VIEW _securesqlite AS SELECT 1 AS id, 1 AS format_version, zeroblob(32) AS database_id, zeroblob(32) AS verification`)
				return err
			},
			want: ErrInvalidMetadata,
		},
		{
			name: "unsupported version",
			corrupt: func(db *DB) error {
				_, err := db.Exec(`UPDATE _securesqlite SET format_version = 2 WHERE id = 1`)
				return err
			},
			want: ErrUnsupportedVersion,
		},
		{
			name: "zero database id",
			corrupt: func(db *DB) error {
				_, err := db.Exec(`UPDATE _securesqlite SET database_id = zeroblob(32) WHERE id = 1`)
				return err
			},
			want: ErrInvalidMetadata,
		},
		{
			name: "bad verification",
			corrupt: func(db *DB) error {
				_, err := db.Exec(`UPDATE _securesqlite SET verification = zeroblob(32) WHERE id = 1`)
				return err
			},
			want: ErrKeyVerification,
		},
		{
			name: "no rows",
			corrupt: func(db *DB) error {
				_, err := db.Exec(`DELETE FROM _securesqlite`)
				return err
			},
			want: ErrInvalidMetadata,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, path := testDB(t)
			if err := tc.corrupt(db); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestImageWithoutMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.db")
	raw := rawSQLite(t, path)
	if _, err := raw.Exec(`CREATE TABLE other (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testKey(t)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

func TestDSNHasNoSecret(t *testing.T) {
	key := testKey(t)
	dsn := buildDSN("/tmp/app.db", defaultConfig())
	if strings.Contains(dsn, key.Hex()) {
		t.Fatal("DSN contains the key")
	}
	if !strings.Contains(dsn, "mode=rw") || !strings.Contains(dsn, "_pragma=") {
		t.Fatalf("unexpected DSN: %s", dsn)
	}
}
