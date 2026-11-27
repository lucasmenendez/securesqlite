// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Index computes a deterministic keyed blind index for exact-match lookups.
// The index is domain-separated by database, table, column, and scope; it does
// not include the record ID or a random salt.
func (db *DB) Index(field Field, plaintext []byte) ([]byte, error) {
	if err := db.ensureInitialized(); err != nil {
		return nil, err
	}
	if err := validateField(field); err != nil {
		return nil, err
	}
	if err := validatePlaintext(plaintext); err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, db.idxKey[:])
	mac.Write(canonical(
		[]byte(labelBlindIndex),
		db.databaseID[:],
		[]byte(field.Table),
		[]byte(field.Column),
		[]byte(field.Scope),
		plaintext,
	))
	return mac.Sum(nil), nil
}

// VerifyIndex recomputes the blind index and compares it in constant time.
// It does not authenticate SQL results or detect rows that were omitted.
func (db *DB) VerifyIndex(field Field, plaintext, index []byte) error {
	expected, err := db.Index(field, plaintext)
	if err != nil {
		return err
	}
	if len(index) != sha256.Size || !hmac.Equal(index, expected) {
		return ErrIndexMismatch
	}
	return nil
}
