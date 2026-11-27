// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func FuzzDecrypt(f *testing.F) {
	dir := f.TempDir()
	db, err := Create(context.Background(), filepath.Join(dir, "app.db"), testKey(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = db.Close() })

	valid, err := db.Encrypt(testField(), "user-1", []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add(make([]byte, ciphertextOverhead))
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		plaintext, err := db.Decrypt(testField(), "user-1", data)
		if err != nil {
			if len(plaintext) != 0 {
				t.Fatal("plaintext returned with an error")
			}
			return
		}
		if len(data) > maxCiphertextSize {
			t.Fatal("oversized input decrypted")
		}
	})
}

func FuzzParseKey(f *testing.F) {
	f.Add(testKeyHex)
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(t *testing.T, encoded string) {
		key, err := ParseKey(encoded)
		if err != nil {
			return
		}
		if key.Hex() != encoded && key.Hex() != stringLower(encoded) {
			t.Fatal("ParseKey accepted a key it cannot round trip")
		}
	})
}

func FuzzField(f *testing.F) {
	f.Add("users", "email", "tenant")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, table, column, scope string) {
		_ = validateField(Field{Table: table, Column: column, Scope: scope})
	})
}

func FuzzRecordID(f *testing.F) {
	f.Add("user-1")
	f.Add("")
	f.Fuzz(func(t *testing.T, recordID string) {
		_ = validateRecordID(recordID)
	})
}

func FuzzCiphertextRoundTrip(f *testing.F) {
	db, _ := testDB(f)
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ciphertext, err := db.Encrypt(testField(), "user-1", plaintext)
		if err != nil {
			if errors.Is(err, ErrValueTooLarge) {
				return
			}
			t.Fatal(err)
		}
		got, err := db.Decrypt(testField(), "user-1", ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(plaintext) {
			t.Fatal("round trip mismatch")
		}
	})
}

func stringLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
