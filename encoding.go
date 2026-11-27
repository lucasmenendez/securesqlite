// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import "encoding/binary"

// Protocol labels. These are part of the on-disk format and must not be reused
// for another purpose.
const (
	labelEncryption       = "securesqlite/v1/encryption"
	labelIndex            = "securesqlite/v1/index"
	labelMetadata         = "securesqlite/v1/metadata"
	labelMessageKey       = "securesqlite/v1/message-key"
	labelAAD              = "securesqlite/v1/aad"
	labelBlindIndex       = "securesqlite/v1/blind-index"
	labelMetadataVerifier = "securesqlite/v1/metadata-verifier"
)

var versionOne = []byte{1}

// canonical encodes parts as ordered uint32 big-endian length prefixes followed
// by the bytes. There is no component count; every caller knows its arity.
func canonical(parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += 4 + len(p)
	}
	out := make([]byte, 0, size)
	var length [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(p)))
		out = append(out, length[:]...)
		out = append(out, p...)
	}
	return out
}
