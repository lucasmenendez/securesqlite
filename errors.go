// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import "errors"

// Sentinel errors returned by the package. Use errors.Is to test them.
var (
	ErrInvalidKey         = errors.New("securesqlite: invalid key")
	ErrInvalidField       = errors.New("securesqlite: invalid field")
	ErrInvalidRecordID    = errors.New("securesqlite: invalid record ID")
	ErrValueTooLarge      = errors.New("securesqlite: value too large")
	ErrInvalidCiphertext  = errors.New("securesqlite: invalid ciphertext")
	ErrAuthentication     = errors.New("securesqlite: authentication failed")
	ErrKeyVerification    = errors.New("securesqlite: key verification failed")
	ErrUnsupportedVersion = errors.New("securesqlite: unsupported format version")
	ErrNotInitialized     = errors.New("securesqlite: database not initialized")
	ErrInvalidMetadata    = errors.New("securesqlite: invalid metadata")
	ErrAlreadyExists      = errors.New("securesqlite: database already exists")
	ErrIndexMismatch      = errors.New("securesqlite: index mismatch")
	ErrInvalidConfig      = errors.New("securesqlite: invalid configuration")
)
