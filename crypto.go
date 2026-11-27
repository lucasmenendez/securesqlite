// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func derive32(ikm, salt []byte, info string) ([32]byte, error) {
	var out [32]byte
	key, err := hkdf.Key(sha256.New, ikm, salt, info, len(out))
	if err != nil {
		return out, fmt.Errorf("securesqlite: derive key: %w", err)
	}
	copy(out[:], key)
	clear(key)
	return out, nil
}

func labelInfo(label string) string {
	return string(canonical([]byte(label)))
}

func deriveRoots(master Key, databaseID [32]byte) (encRoot, idxKey [32]byte, err error) {
	encRoot, err = derive32(master.b[:], databaseID[:], labelInfo(labelEncryption))
	if err != nil {
		return encRoot, idxKey, err
	}
	idxKey, err = derive32(master.b[:], databaseID[:], labelInfo(labelIndex))
	return encRoot, idxKey, err
}

func deriveMetadataKey(master Key, databaseID [32]byte) ([32]byte, error) {
	return derive32(master.b[:], databaseID[:], labelInfo(labelMetadata))
}

func metadataVerification(metaKey [32]byte, databaseID [32]byte) []byte {
	mac := hmac.New(sha256.New, metaKey[:])
	mac.Write(canonical([]byte(labelMetadataVerifier), versionOne, databaseID[:]))
	return mac.Sum(nil)
}

func aadFor(databaseID [32]byte, field Field, recordID string, messageSalt []byte) []byte {
	return canonical(
		[]byte(labelAAD),
		versionOne,
		databaseID[:],
		[]byte(field.Table),
		[]byte(field.Column),
		[]byte(field.Scope),
		[]byte(recordID),
		messageSalt,
	)
}

// Encrypt encrypts plaintext for the given field and immutable record ID.
func (db *DB) Encrypt(field Field, recordID string, plaintext []byte) ([]byte, error) {
	if err := db.ensureInitialized(); err != nil {
		return nil, err
	}
	if err := validateField(field); err != nil {
		return nil, err
	}
	if err := validateRecordID(recordID); err != nil {
		return nil, err
	}
	if err := validatePlaintext(plaintext); err != nil {
		return nil, err
	}

	var messageSalt [messageSaltSize]byte
	if _, err := rand.Read(messageSalt[:]); err != nil {
		return nil, fmt.Errorf("securesqlite: generate message salt: %w", err)
	}
	messageKey, err := derive32(db.encRoot[:], messageSalt[:], labelInfo(labelMessageKey))
	if err != nil {
		return nil, err
	}
	defer clear(messageKey[:])

	block, err := aes.NewCipher(messageKey[:])
	if err != nil {
		return nil, fmt.Errorf("securesqlite: create cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("securesqlite: create GCM: %w", err)
	}

	aad := aadFor(db.databaseID, field, recordID, messageSalt[:])
	sealed := aead.Seal(nil, nil, plaintext, aad)

	out := make([]byte, 0, ciphertextOverhead+len(plaintext))
	out = append(out, versionOne...)
	out = append(out, messageSalt[:]...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt decrypts a ciphertext produced by Encrypt for the same field and
// record ID. It never returns plaintext when authentication fails.
func (db *DB) Decrypt(field Field, recordID string, ciphertext []byte) ([]byte, error) {
	if err := db.ensureInitialized(); err != nil {
		return nil, err
	}
	if err := validateField(field); err != nil {
		return nil, err
	}
	if err := validateRecordID(recordID); err != nil {
		return nil, err
	}
	if len(ciphertext) < ciphertextOverhead {
		return nil, ErrInvalidCiphertext
	}
	if len(ciphertext) > maxCiphertextSize {
		return nil, ErrValueTooLarge
	}
	if ciphertext[0] != versionOne[0] {
		return nil, ErrUnsupportedVersion
	}

	var messageSalt [messageSaltSize]byte
	copy(messageSalt[:], ciphertext[1:1+messageSaltSize])
	sealed := ciphertext[1+messageSaltSize:]

	messageKey, err := derive32(db.encRoot[:], messageSalt[:], labelInfo(labelMessageKey))
	if err != nil {
		return nil, err
	}
	defer clear(messageKey[:])

	block, err := aes.NewCipher(messageKey[:])
	if err != nil {
		return nil, fmt.Errorf("securesqlite: create cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("securesqlite: create GCM: %w", err)
	}

	aad := aadFor(db.databaseID, field, recordID, messageSalt[:])
	plaintext, err := aead.Open(nil, nil, sealed, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// Protect encrypts plaintext and computes its blind index. It returns no
// partial results if either operation fails.
func (db *DB) Protect(field Field, recordID string, plaintext []byte) (ciphertext, index []byte, err error) {
	ciphertext, err = db.Encrypt(field, recordID, plaintext)
	if err != nil {
		return nil, nil, err
	}
	index, err = db.Index(field, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, index, nil
}
