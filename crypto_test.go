// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"text", []byte("alice@example.com")},
		{"binary", []byte{0, 1, 2, 0xff, 0xfe}},
		{"large", make([]byte, maxPlaintextSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := db.Encrypt(field, "user-1", tc.plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != ciphertextOverhead+len(tc.plaintext) {
				t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), ciphertextOverhead+len(tc.plaintext))
			}
			if len(tc.plaintext) == 0 && len(ciphertext) != 61 {
				t.Fatalf("empty ciphertext length = %d, want 61", len(ciphertext))
			}
			plaintext, err := db.Decrypt(field, "user-1", ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, tc.plaintext) {
				t.Fatal("round trip mismatch")
			}
		})
	}
}

func TestEncryptRandomized(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	first, err := db.Encrypt(field, "user-1", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.Encrypt(field, "user-1", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two encryptions of the same plaintext are identical")
	}
}

func TestEncryptUniqueSalts(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	seen := make(map[string]bool)
	for range 100 {
		ciphertext, err := db.Encrypt(field, "user-1", []byte("value"))
		if err != nil {
			t.Fatal(err)
		}
		salt := string(ciphertext[1 : 1+messageSaltSize])
		if seen[salt] {
			t.Fatal("duplicate message salt")
		}
		seen[salt] = true
	}
}

func TestDecryptTampering(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	const recordID = "user-1"
	ciphertext, err := db.Encrypt(field, recordID, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{
			name: "version",
			mutate: func(b []byte) []byte {
				b[0] = 2
				return b
			},
			want: ErrUnsupportedVersion,
		},
		{
			name: "salt",
			mutate: func(b []byte) []byte {
				b[1] ^= 1
				return b
			},
			want: ErrAuthentication,
		},
		{
			name: "nonce",
			mutate: func(b []byte) []byte {
				b[1+messageSaltSize] ^= 1
				return b
			},
			want: ErrAuthentication,
		},
		{
			name: "ciphertext",
			mutate: func(b []byte) []byte {
				b[1+messageSaltSize+gcmNonceSize] ^= 1
				return b
			},
			want: ErrAuthentication,
		},
		{
			name: "tag",
			mutate: func(b []byte) []byte {
				b[len(b)-1] ^= 1
				return b
			},
			want: ErrAuthentication,
		},
		{
			name: "truncated",
			mutate: func(b []byte) []byte {
				return b[:ciphertextOverhead-1]
			},
			want: ErrInvalidCiphertext,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.mutate(append([]byte(nil), ciphertext...))
			plaintext, err := db.Decrypt(field, recordID, tampered)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if len(plaintext) != 0 {
				t.Fatal("plaintext returned on error")
			}
		})
	}
}

func TestDecryptWrongContext(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	ciphertext, err := db.Encrypt(field, "user-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	contexts := []struct {
		name     string
		field    Field
		recordID string
	}{
		{"table", Field{Table: "other", Column: field.Column, Scope: field.Scope}, "user-1"},
		{"column", Field{Table: field.Table, Column: "name", Scope: field.Scope}, "user-1"},
		{"scope", Field{Table: field.Table, Column: field.Column, Scope: "tenant-2"}, "user-1"},
		{"record", field, "user-2"},
	}
	for _, tc := range contexts {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Decrypt(tc.field, tc.recordID, ciphertext); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("error = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestDecryptWrongDatabase(t *testing.T) {
	db, _ := testDB(t)
	ciphertext, err := db.Encrypt(testField(), "user-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := testDB(t)
	if _, err := other.Decrypt(testField(), "user-1", ciphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error = %v, want ErrAuthentication", err)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	db, _ := testDB(t)
	ciphertext, err := db.Encrypt(testField(), "user-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	otherKey := testKey(t)
	otherKey.b[0] ^= 0xff
	otherDB := dbWithRoots(t, otherKey, db.databaseID)
	if _, err := otherDB.Decrypt(testField(), "user-1", ciphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error = %v, want ErrAuthentication", err)
	}
}

func TestDecryptSizeLimits(t *testing.T) {
	db, _ := testDB(t)
	if _, err := db.Decrypt(testField(), "user-1", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("nil error = %v, want ErrInvalidCiphertext", err)
	}
	tooLarge := make([]byte, maxCiphertextSize+1)
	if _, err := db.Decrypt(testField(), "user-1", tooLarge); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("large error = %v, want ErrValueTooLarge", err)
	}
}

func TestEncryptInputLimits(t *testing.T) {
	db, _ := testDB(t)
	if _, err := db.Encrypt(testField(), "user-1", make([]byte, maxPlaintextSize+1)); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("error = %v, want ErrValueTooLarge", err)
	}
	if _, err := db.Encrypt(Field{Table: "users"}, "user-1", []byte("value")); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("error = %v, want ErrInvalidField", err)
	}
	if _, err := db.Encrypt(testField(), "", []byte("value")); !errors.Is(err, ErrInvalidRecordID) {
		t.Fatalf("error = %v, want ErrInvalidRecordID", err)
	}
}

func TestProtect(t *testing.T) {
	db, _ := testDB(t)
	field := testField()
	plaintext := []byte("alice@example.com")
	ciphertext, index, err := db.Protect(field, "user-1", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 32 {
		t.Fatalf("index length = %d, want 32", len(index))
	}
	got, err := db.Decrypt(field, "user-1", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("Protect round trip mismatch")
	}
	if err := db.VerifyIndex(field, plaintext, index); err != nil {
		t.Fatal(err)
	}
	expected, err := db.Index(field, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(index, expected) {
		t.Fatal("Protect index differs from Index")
	}
}

func TestProtectNoPartialResult(t *testing.T) {
	db, _ := testDB(t)
	ciphertext, index, err := db.Protect(Field{Table: "users"}, "user-1", []byte("value"))
	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("error = %v, want ErrInvalidField", err)
	}
	if ciphertext != nil || index != nil {
		t.Fatal("Protect returned partial results")
	}
}

func TestDeriveRoots(t *testing.T) {
	key := testKey(t)
	var id [32]byte
	id[0] = 1
	enc1, idx1, err := deriveRoots(key, id)
	if err != nil {
		t.Fatal(err)
	}
	enc2, idx2, err := deriveRoots(key, id)
	if err != nil {
		t.Fatal(err)
	}
	if enc1 != enc2 || idx1 != idx2 {
		t.Fatal("derivation is not deterministic")
	}
	if enc1 == idx1 {
		t.Fatal("encryption and index roots are equal")
	}

	var otherID [32]byte
	otherID[0] = 2
	enc3, idx3, err := deriveRoots(key, otherID)
	if err != nil {
		t.Fatal(err)
	}
	if enc1 == enc3 || idx1 == idx3 {
		t.Fatal("different database IDs produced the same roots")
	}
}

func TestConcurrentHelpers(t *testing.T) {
	db, _ := testDB(t)
	const workers = 16
	const iterations = 25
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				plaintext := []byte("concurrent-value")
				ciphertext, err := db.Encrypt(testField(), "user-1", plaintext)
				if err != nil {
					errs <- err
					return
				}
				got, err := db.Decrypt(testField(), "user-1", ciphertext)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, plaintext) {
					errs <- errors.New("round trip mismatch")
					return
				}
				index, err := db.Index(testField(), plaintext)
				if err != nil {
					errs <- err
					return
				}
				if err := db.VerifyIndex(testField(), plaintext, index); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestFixedVectorDecrypt(t *testing.T) {
	// The fixed vector is documented in FORMAT.md. Decrypt must accept the
	// format produced with cipher.NewGCM and a fixed nonce.
	db := vectorDB(t)
	ciphertext := fixedCiphertext(t)
	plaintext, err := db.Decrypt(fixedField(), fixedRecordID, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != fixedPlaintext {
		t.Fatalf("plaintext = %q, want %q", plaintext, fixedPlaintext)
	}
}

func TestEncryptNilDB(t *testing.T) {
	var db *DB
	if _, err := db.Encrypt(testField(), "user-1", []byte("value")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
	if _, err := db.Decrypt(testField(), "user-1", []byte("value")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
	if _, _, err := db.Protect(testField(), "user-1", []byte("value")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

func TestContextCancellationAfterOpen(t *testing.T) {
	db, _ := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.Encrypt(testField(), "user-1", []byte("value")); err != nil {
		t.Fatalf("helpers do not take a context: %v", err)
	}
	_ = ctx
}
