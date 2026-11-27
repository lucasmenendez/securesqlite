// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lucasmenendez/securesqlite"
)

func Example() {
	key, err := securesqlite.GenerateKey()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	dir, err := os.MkdirTemp("", "securesqlite-example")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	db, err := securesqlite.Create(ctx, filepath.Join(dir, "app.db"), key)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer db.Close()

	field := securesqlite.Field{Table: "users", Column: "email"}
	ciphertext, index, err := db.Protect(field, "user-1", []byte("alice@example.com"))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	plaintext, err := db.Decrypt(field, "user-1", ciphertext)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if err := db.VerifyIndex(field, plaintext, index); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(string(plaintext))
	// Output: alice@example.com
}
