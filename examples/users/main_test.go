// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucasmenendez/securesqlite"
)

func setupExample(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	for _, dir := range []string{"secrets", "data"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key, err := securesqlite.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("secrets", "db.key")
	if err := os.WriteFile(path, []byte(key.Hex()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunInitAndDemo(t *testing.T) {
	setupExample(t)
	ctx := context.Background()
	if err := run(ctx, []string{"init"}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"demo"}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"demo"}); err == nil {
		t.Fatal("second demo should fail on the fixed primary key")
	}
	if err := run(ctx, []string{"init"}); err == nil {
		t.Fatal("second init should fail because the database exists")
	}
}

func TestRunUsage(t *testing.T) {
	setupExample(t)
	ctx := context.Background()
	if err := run(ctx, nil); err == nil {
		t.Fatal("expected a usage error")
	}
	if err := run(ctx, []string{"unknown"}); err == nil {
		t.Fatal("expected an unknown-command error")
	}
}

func TestRunMissingKey(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := run(context.Background(), []string{"init"}); err == nil {
		t.Fatal("expected a missing key error")
	}
}
