//go:build unix

// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadKeyFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := LoadKeyFile(path); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("error = %v, want ErrInvalidKey", err)
	}
}
