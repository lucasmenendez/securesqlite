// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"testing"
)

func TestCanonical(t *testing.T) {
	got := canonical([]byte("a"), []byte("bc"))
	want := []byte{
		0, 0, 0, 1, 'a',
		0, 0, 0, 2, 'b', 'c',
	}
	if string(got) != string(want) {
		t.Fatalf("canonical = %x, want %x", got, want)
	}
}

func TestCanonicalSeparatesParts(t *testing.T) {
	a := canonical([]byte("a"), []byte("bc"))
	b := canonical([]byte("ab"), []byte("c"))
	if string(a) == string(b) {
		t.Fatal("different part boundaries produced the same encoding")
	}
}

func TestCanonicalEmptyParts(t *testing.T) {
	got := canonical(nil, []byte{})
	want := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if string(got) != string(want) {
		t.Fatalf("canonical = %x, want %x", got, want)
	}
}
