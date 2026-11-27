// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	maxPlaintextSize   = 16 << 20 // 16 MiB
	maxCiphertextSize  = maxPlaintextSize + ciphertextOverhead
	messageSaltSize    = 32
	gcmNonceSize       = 12
	gcmTagSize         = 16
	ciphertextOverhead = 1 + messageSaltSize + gcmNonceSize + gcmTagSize
)

// Field identifies an encrypted value. Table and Column are stable logical
// labels, not necessarily physical schema names. Scope is optional and can be
// used for tenant separation.
type Field struct {
	Table  string
	Column string
	Scope  string
}

func validateField(field Field) error {
	if reason := contextStringError(field.Table, 1, 255); reason != "" {
		return fmt.Errorf("%w: table %s", ErrInvalidField, reason)
	}
	if reason := contextStringError(field.Column, 1, 255); reason != "" {
		return fmt.Errorf("%w: column %s", ErrInvalidField, reason)
	}
	if reason := contextStringError(field.Scope, 0, 1024); reason != "" {
		return fmt.Errorf("%w: scope %s", ErrInvalidField, reason)
	}
	return nil
}

func validateRecordID(recordID string) error {
	if reason := contextStringError(recordID, 1, 1024); reason != "" {
		return fmt.Errorf("%w: %s", ErrInvalidRecordID, reason)
	}
	return nil
}

func contextStringError(value string, min, max int) string {
	if len(value) < min {
		return "is too short"
	}
	if len(value) > max {
		return "is too long"
	}
	if !utf8.ValidString(value) {
		return "is not valid UTF-8"
	}
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return "contains control characters"
		}
	}
	return ""
}

func validatePlaintext(plaintext []byte) error {
	if len(plaintext) > maxPlaintextSize {
		return ErrValueTooLarge
	}
	return nil
}
