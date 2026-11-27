// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	seen := make(map[string]bool)
	for range 20 {
		key, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if key.isZero() {
			t.Fatal("GenerateKey returned the zero key")
		}
		hexKey := key.Hex()
		if len(hexKey) != 64 {
			t.Fatalf("Hex length = %d, want 64", len(hexKey))
		}
		if seen[hexKey] {
			t.Fatal("GenerateKey returned a duplicate key")
		}
		seen[hexKey] = true
	}
}

func TestParseKey(t *testing.T) {
	key, err := ParseKey(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if key.Hex() != testKeyHex {
		t.Fatalf("Hex = %q, want %q", key.Hex(), testKeyHex)
	}
	upper, err := ParseKey(strings.ToUpper(testKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	if upper != key {
		t.Fatal("uppercase and lowercase keys differ")
	}
}

func TestParseKeyRejects(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"short":         testKeyHex[:63],
		"long":          testKeyHex + "00",
		"zero":          strings.Repeat("00", 32),
		"prefix":        "0x" + testKeyHex[:62],
		"space":         testKeyHex[:32] + " " + testKeyHex[33:],
		"newline":       testKeyHex + "\n",
		"non-hex":       "z" + testKeyHex[1:],
		"unicode digit": "０" + testKeyHex[1:],
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey(input); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestKeyRedaction(t *testing.T) {
	key := testKey(t)
	secret := key.Hex()
	outputs := []string{
		fmt.Sprint(key),
		fmt.Sprintf("%v", key),
		fmt.Sprintf("%x", key),
		fmt.Sprintf("%#v", key),
		fmt.Sprintf("%+v", key),
		key.String(),
		key.GoString(),
	}
	for _, out := range outputs {
		if strings.Contains(out, secret) {
			t.Fatalf("redacted output leaked the key: %q", out)
		}
	}

	type wrapper struct{ Key Key }
	for _, out := range []string{
		fmt.Sprintf("%+v", wrapper{Key: key}),
		fmt.Sprintf("%#v", wrapper{Key: key}),
		fmt.Sprintf("%v", &key),
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("nested redaction leaked the key: %q", out)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("test", "key", key)
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("slog leaked the key: %q", buf.String())
	}
}

func TestLoadKeyFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
	}{
		{"plain", testKeyHex},
		{"lf", testKeyHex + "\n"},
		{"crlf", testKeyHex + "\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".key")
			if err := os.WriteFile(path, []byte(tc.content), 0o444); err != nil {
				t.Fatal(err)
			}
			key, err := LoadKeyFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if key.Hex() != testKeyHex {
				t.Fatalf("key = %q, want test key", key.Hex())
			}
		})
	}
}

func TestLoadKeyFileRejects(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"empty":          "",
		"short":          testKeyHex[:63],
		"long":           testKeyHex + "0",
		"two newlines":   testKeyHex + "\n\n",
		"leading space":  " " + testKeyHex,
		"trailing space": testKeyHex + " ",
		"bad newline":    testKeyHex[:32] + "\n" + testKeyHex[32:],
		"zero":           strings.Repeat("00", 32),
		"non-hex":        strings.Repeat("zz", 32),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".key")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadKeyFile(path)
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("error = %v, want ErrInvalidKey", err)
			}
			if strings.Contains(err.Error(), content) && content != "" {
				t.Fatal("error contains key file contents")
			}
		})
	}
}

func TestLoadKeyFileOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 257)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("error = %v, want ErrInvalidKey", err)
	}
}

func TestLoadKeyFileSymlinkContents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.key")
	if err := os.WriteFile(target, []byte(testKeyHex+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKeyFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if key.Hex() != testKeyHex {
		t.Fatal("wrong key from symlink")
	}
}

func TestLoadKeyFileRejectsDirectory(t *testing.T) {
	if _, err := LoadKeyFile(t.TempDir()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("error = %v, want ErrInvalidKey", err)
	}
}

func TestLoadKeyFileMissing(t *testing.T) {
	if _, err := LoadKeyFile(filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("expected an error")
	}
}
