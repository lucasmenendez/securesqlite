// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

// Package securesqlite provides selective field encryption and blind indexes
// on top of database/sql and SQLite.
//
// It is not SQLCipher and does not encrypt database pages or files. The caller
// chooses which values to protect. Ciphertexts and indexes are ordinary BLOBs
// and SQL NULL handling remains the caller's responsibility.
//
// The package is experimental until an independent security review has been
// completed.
package securesqlite
