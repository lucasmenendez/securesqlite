// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"context"
	"path/filepath"
	"testing"
)

const testKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func testKey(t testing.TB) Key {
	t.Helper()
	key, err := ParseKey(testKeyHex)
	if err != nil {
		t.Fatalf("ParseKey(test key): %v", err)
	}
	return key
}

func testDB(t testing.TB, opts ...Option) (*DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := Create(context.Background(), path, testKey(t), opts...)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db, path
}

func testField() Field {
	return Field{Table: "users", Column: "email", Scope: "tenant-1"}
}
