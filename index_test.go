// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"bytes"
	"errors"
	"testing"
)

func TestIndexDeterministic(t *testing.T) {
	db, _ := testDB(t)
	first, err := db.Index(testField(), []byte("alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.Index(testField(), []byte("alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("index is not deterministic")
	}
	if len(first) != 32 {
		t.Fatalf("index length = %d, want 32", len(first))
	}
}

func TestIndexDomainSeparation(t *testing.T) {
	db, _ := testDB(t)
	base, err := db.Index(testField(), []byte("alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	fields := []Field{
		{Table: "other", Column: "email", Scope: "tenant-1"},
		{Table: "users", Column: "name", Scope: "tenant-1"},
		{Table: "users", Column: "email", Scope: "tenant-2"},
		{Table: "users", Column: "email"},
	}
	for _, field := range fields {
		index, err := db.Index(field, []byte("alice@example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, index) {
			t.Fatalf("field %+v produced the same index", field)
		}
	}

	otherDB, _ := testDB(t)
	index, err := otherDB.Index(testField(), []byte("alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, index) {
		t.Fatal("different databases produced the same index")
	}
}

func TestVerifyIndex(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	plaintext := []byte("alice@example.com")
	index, err := db.Index(field, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.VerifyIndex(field, plaintext, index); err != nil {
		t.Fatal(err)
	}
	if err := db.VerifyIndex(field, []byte("bob@example.com"), index); !errors.Is(err, ErrIndexMismatch) {
		t.Fatalf("wrong plaintext error = %v, want ErrIndexMismatch", err)
	}
	if err := db.VerifyIndex(field, plaintext, index[:31]); !errors.Is(err, ErrIndexMismatch) {
		t.Fatalf("short index error = %v, want ErrIndexMismatch", err)
	}
	tampered := append([]byte(nil), index...)
	tampered[0] ^= 1
	if err := db.VerifyIndex(field, plaintext, tampered); !errors.Is(err, ErrIndexMismatch) {
		t.Fatalf("tampered index error = %v, want ErrIndexMismatch", err)
	}
}

func TestIndexInputLimits(t *testing.T) {
	db, _ := testDB(t)
	if _, err := db.Index(testField(), make([]byte, maxPlaintextSize+1)); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("error = %v, want ErrValueTooLarge", err)
	}
	if _, err := db.Index(Field{Table: "users"}, []byte("value")); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("error = %v, want ErrInvalidField", err)
	}
	if err := db.VerifyIndex(testField(), []byte("value"), make([]byte, 32)); !errors.Is(err, ErrIndexMismatch) {
		t.Fatalf("error = %v, want ErrIndexMismatch", err)
	}
}

func TestIndexNilDB(t *testing.T) {
	var db *DB
	if _, err := db.Index(testField(), []byte("value")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
	if err := db.VerifyIndex(testField(), []byte("value"), make([]byte, 32)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}
