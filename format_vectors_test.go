// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"testing"
)

const (
	fixedKeyHex         = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	fixedDatabaseIDHex  = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	fixedMessageSaltHex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	fixedNonceHex       = "a0a1a2a3a4a5a6a7a8a9aaab"
	fixedPlaintext      = "alice@example.com"
	fixedTable          = "users"
	fixedColumn         = "email"
	fixedScope          = "tenant-1"
	fixedRecordID       = "user-1"
)

func fixedKey(t testing.TB) Key {
	t.Helper()
	key, err := ParseKey(fixedKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func fixedDatabaseID(t testing.TB) [32]byte {
	t.Helper()
	var id [32]byte
	copy(id[:], decodeFixedHex(t, fixedDatabaseIDHex))
	return id
}

func fixedField() Field {
	return Field{Table: fixedTable, Column: fixedColumn, Scope: fixedScope}
}

func decodeFixedHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dbWithRoots(t testing.TB, key Key, databaseID [32]byte) *DB {
	t.Helper()
	encRoot, idxKey, err := deriveRoots(key, databaseID)
	if err != nil {
		t.Fatal(err)
	}
	return &DB{
		DB:          &sql.DB{},
		encRoot:     encRoot,
		idxKey:      idxKey,
		databaseID:  databaseID,
		initialized: true,
	}
}

func vectorDB(t testing.TB) *DB {
	t.Helper()
	return dbWithRoots(t, fixedKey(t), fixedDatabaseID(t))
}

func fixedCiphertext(t testing.TB) []byte {
	t.Helper()
	db := vectorDB(t)
	salt := decodeFixedHex(t, fixedMessageSaltHex)
	nonce := decodeFixedHex(t, fixedNonceHex)
	messageKey, err := derive32(db.encRoot[:], salt, labelInfo(labelMessageKey))
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(messageKey[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad := aadFor(db.databaseID, fixedField(), fixedRecordID, salt)
	sealed := aead.Seal(nil, nonce, []byte(fixedPlaintext), aad)
	out := make([]byte, 0, ciphertextOverhead+len(fixedPlaintext))
	out = append(out, versionOne...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out
}

func TestDocumentedFormatVectors(t *testing.T) {
	db := vectorDB(t)
	salt := decodeFixedHex(t, fixedMessageSaltHex)
	messageKey, err := derive32(db.encRoot[:], salt, labelInfo(labelMessageKey))
	if err != nil {
		t.Fatal(err)
	}
	metaKey, err := deriveMetadataKey(fixedKey(t), fixedDatabaseID(t))
	if err != nil {
		t.Fatal(err)
	}
	index, err := db.Index(fixedField(), []byte(fixedPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"enc_root", hex.EncodeToString(db.encRoot[:]), "439fd1725958d503c444ea91beae4e5c41abf9ee6b883fa73dc6e477fc1c4052"},
		{"message_key", hex.EncodeToString(messageKey[:]), "dc3013bffe7bd154e4512c6eb1653e7f0c3e5fe19a1fb83163fcc2b3d3cda590"},
		{"aad", hex.EncodeToString(aadFor(db.databaseID, fixedField(), fixedRecordID, salt)), "0000001373656375726573716c6974652f76312f616164000000010100000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000005757365727300000005656d61696c0000000874656e616e742d3100000006757365722d3100000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"},
		{"ciphertext", hex.EncodeToString(fixedCiphertext(t)), "01808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab365c3a12473169cfed2039d6b9cea661e0f651cdc0d090baa107ed0eed0c57fad6"},
		{"idx_key", hex.EncodeToString(db.idxKey[:]), "5c26a6b83ecc8100a8e18a7f5e3a2f6ab3593285b6da6a3d6c23340790e38fd0"},
		{"blind_index", hex.EncodeToString(index), "d3ca386849e53aaecb4cd23f32a77bce646109b6cea5621c3416dd3fa71734f2"},
		{"meta_key", hex.EncodeToString(metaKey[:]), "72ea65f422b203f12a79cd4564512e02d5f948f8332532b6dd7d8a0742a0eaff"},
		{"verification", hex.EncodeToString(metadataVerification(metaKey, fixedDatabaseID(t))), "9cbe3bdf9496adbccb6e4637d0d456acd7a96fa04ef744693ffa8600a22475f8"},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %s, want %s", check.name, check.got, check.want)
		}
	}
}

func TestFormatVectors(t *testing.T) {
	db := vectorDB(t)
	salt := decodeFixedHex(t, fixedMessageSaltHex)
	messageKey, err := derive32(db.encRoot[:], salt, labelInfo(labelMessageKey))
	if err != nil {
		t.Fatal(err)
	}
	aad := aadFor(db.databaseID, fixedField(), fixedRecordID, salt)
	ciphertext := fixedCiphertext(t)
	index, err := db.Index(fixedField(), []byte(fixedPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	metaKey, err := deriveMetadataKey(fixedKey(t), fixedDatabaseID(t))
	if err != nil {
		t.Fatal(err)
	}
	verification := metadataVerification(metaKey, fixedDatabaseID(t))

	t.Logf("key                 = %s", fixedKeyHex)
	t.Logf("database_id         = %s", fixedDatabaseIDHex)
	t.Logf("database_id_zero    = %v", isZeroBytes(db.databaseID[:]))
	t.Logf("table/column/scope  = %s/%s/%s", fixedTable, fixedColumn, fixedScope)
	t.Logf("record_id           = %s", fixedRecordID)
	t.Logf("plaintext           = %s", fixedPlaintext)
	t.Logf("message_salt        = %s", fixedMessageSaltHex)
	t.Logf("nonce               = %s", fixedNonceHex)
	t.Logf("enc_root            = %x", db.encRoot)
	t.Logf("message_key         = %x", messageKey)
	t.Logf("aad                 = %x", aad)
	t.Logf("ciphertext          = %x", ciphertext)
	t.Logf("idx_key             = %x", db.idxKey)
	t.Logf("blind_index         = %x", index)
	t.Logf("meta_key            = %x", metaKey)
	t.Logf("verification        = %x", verification)
}
