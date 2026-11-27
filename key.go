// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// KeySize is the size in bytes of a master key.
const KeySize = 32

const redactedKey = "securesqlite.Key([REDACTED])"

// Key is an opaque master key. Its zero value and an all-zero key are invalid.
// Key deliberately exposes no marshaling and redacts itself in fmt and slog
// output. Hex is the only explicit export.
type Key struct {
	b [KeySize]byte
}

// GenerateKey returns a random master key generated with crypto/rand.
func GenerateKey() (Key, error) {
	var key Key
	for {
		if _, err := rand.Read(key.b[:]); err != nil {
			return Key{}, fmt.Errorf("securesqlite: generate key: %w", err)
		}
		if !key.isZero() {
			return key, nil
		}
	}
}

// ParseKey parses exactly 64 ASCII hexadecimal characters. Upper and lower
// case are accepted; no prefix, whitespace, or newline is allowed.
func ParseKey(encoded string) (Key, error) {
	if len(encoded) != hex.EncodedLen(KeySize) {
		return Key{}, ErrInvalidKey
	}
	var key Key
	n, err := hex.Decode(key.b[:], []byte(encoded))
	if err != nil || n != KeySize || key.isZero() {
		return Key{}, ErrInvalidKey
	}
	return key, nil
}

// LoadKeyFile reads a master key from a regular file. The file must contain
// exactly 64 hexadecimal characters followed by at most one LF or CRLF. The
// path is trusted configuration; errors never include file contents.
//
// Symlinks to regular files are followed so that orchestrator-mounted secrets
// work. The file mode is not enforced because Docker and Kubernetes may mount
// secrets read-only with a mode other than 0600.
func LoadKeyFile(path string) (Key, error) {
	if path == "" {
		return Key{}, fmt.Errorf("%w: empty key path", ErrInvalidKey)
	}

	// Inspect before opening so a FIFO or device cannot block the caller.
	info, err := os.Lstat(path)
	if err != nil {
		return Key{}, fmt.Errorf("securesqlite: load key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		info, err = os.Stat(path)
		if err != nil {
			return Key{}, fmt.Errorf("securesqlite: load key file: %w", err)
		}
	}
	if !info.Mode().IsRegular() {
		return Key{}, fmt.Errorf("%w: key file is not a regular file", ErrInvalidKey)
	}

	f, err := os.Open(path)
	if err != nil {
		return Key{}, fmt.Errorf("securesqlite: load key file: %w", err)
	}
	defer f.Close()

	info, err = f.Stat()
	if err != nil {
		return Key{}, fmt.Errorf("securesqlite: load key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Key{}, fmt.Errorf("%w: key file is not a regular file", ErrInvalidKey)
	}

	data, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return Key{}, fmt.Errorf("securesqlite: load key file: %w", err)
	}
	if len(data) > 256 {
		return Key{}, ErrInvalidKey
	}
	switch {
	case len(data) == hex.EncodedLen(KeySize):
	case len(data) == 65 && data[64] == '\n':
		data = data[:64]
	case len(data) == 66 && data[64] == '\r' && data[65] == '\n':
		data = data[:64]
	default:
		return Key{}, ErrInvalidKey
	}
	return ParseKey(string(data))
}

// Hex returns the key encoded as lowercase hexadecimal. It is an explicit
// secret export and must never be logged.
func (k Key) Hex() string {
	return hex.EncodeToString(k.b[:])
}

// String redacts the key.
func (k Key) String() string { return redactedKey }

// GoString redacts the key.
func (k Key) GoString() string { return redactedKey }

// Format redacts the key for every fmt verb, including %x and %#v.
func (k Key) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redactedKey)
}

// LogValue redacts the key in log/slog output.
func (k Key) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

func (k Key) isZero() bool {
	return isZeroBytes(k.b[:])
}

func (k Key) validate() error {
	if k.isZero() {
		return ErrInvalidKey
	}
	return nil
}

func isZeroBytes(b []byte) bool {
	var v byte
	for _, c := range b {
		v |= c
	}
	return v == 0
}
