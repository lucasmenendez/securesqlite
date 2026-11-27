// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"strconv"
	"testing"
)

func benchDB(b *testing.B) *DB {
	b.Helper()
	db, _ := testDB(b)
	return db
}

func BenchmarkEncrypt(b *testing.B) {
	db := benchDB(b)
	plaintext := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := db.Encrypt(testField(), "user-1", plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	db := benchDB(b)
	plaintext := make([]byte, 1024)
	ciphertext, err := db.Encrypt(testField(), "user-1", plaintext)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := db.Decrypt(testField(), "user-1", ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIndex(b *testing.B) {
	db := benchDB(b)
	plaintext := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := db.Index(testField(), plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProtect(b *testing.B) {
	db := benchDB(b)
	plaintext := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := db.Protect(testField(), "user-1", plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteInsert(b *testing.B) {
	db := benchDB(b)
	if _, err := db.Exec(`CREATE TABLE bench (id TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT`); err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		ciphertext, err := db.Encrypt(testField(), "user-1", plaintext)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO bench (id, value) VALUES (?, ?)`, strconv.Itoa(i), ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}
