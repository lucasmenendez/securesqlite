// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/lucasmenendez/securesqlite"
)

type User struct {
	ID    string
	Name  string
	Email string
}

type UserRepository struct {
	db *securesqlite.DB
}

var (
	nameField  = securesqlite.Field{Table: "users", Column: "name"}
	emailField = securesqlite.Field{Table: "users", Column: "email"}
)

const schema = `CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY NOT NULL,
	name BLOB NOT NULL,
	email BLOB NOT NULL,
	email_index BLOB NOT NULL UNIQUE CHECK (length(email_index) = 32)
) STRICT;`

func (r UserRepository) Create(ctx context.Context, u User) error {
	name, err := r.db.Encrypt(nameField, u.ID, []byte(u.Name))
	if err != nil {
		return err
	}
	email, index, err := r.db.Protect(emailField, u.ID, []byte(u.Email))
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO users
		(id, name, email, email_index) VALUES (?, ?, ?, ?)`,
		u.ID, name, email, index)
	return err
}

func (r UserRepository) FindByEmail(ctx context.Context, email string) (User, error) {
	index, err := r.db.Index(emailField, []byte(email))
	if err != nil {
		return User{}, err
	}
	var u User
	var name, encryptedEmail, storedIndex []byte
	err = r.db.QueryRowContext(ctx, `SELECT id, name, email, email_index
		FROM users WHERE email_index = ?`, index).
		Scan(&u.ID, &name, &encryptedEmail, &storedIndex)
	if err != nil {
		return User{}, err
	}
	plainEmail, err := r.db.Decrypt(emailField, u.ID, encryptedEmail)
	if err != nil {
		return User{}, err
	}
	if err := r.db.VerifyIndex(emailField, plainEmail, storedIndex); err != nil {
		return User{}, err
	}
	if string(plainEmail) != email {
		return User{}, securesqlite.ErrIndexMismatch
	}
	plainName, err := r.db.Decrypt(nameField, u.ID, name)
	if err != nil {
		return User{}, err
	}
	u.Name = string(plainName)
	u.Email = string(plainEmail)
	return u, nil
}

func (r UserRepository) UpdateEmail(ctx context.Context, id, email string) error {
	encrypted, index, err := r.db.Protect(emailField, id, []byte(email))
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE users SET email = ?, email_index = ? WHERE id = ?`,
		encrypted, index, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func run(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: users init|demo")
	}
	key, err := securesqlite.LoadKeyFile("secrets/db.key")
	if err != nil {
		return err
	}
	if args[0] == "init" {
		db, err := securesqlite.Create(ctx, "data/app.db", key)
		if err != nil {
			return err
		}
		defer db.Close()
		_, err = db.ExecContext(ctx, schema)
		return err
	}
	if args[0] != "demo" {
		return errors.New("unknown command")
	}
	db, err := securesqlite.Open(ctx, "data/app.db", key)
	if err != nil {
		return err
	}
	defer db.Close()
	repo := UserRepository{db: db}
	// A fixed ID only for this deterministic, one-time demo.
	// Real applications generate immutable unique IDs before encryption.
	u := User{ID: "demo-001", Name: "Alice", Email: "alice@example.com"}
	if err := repo.Create(ctx, u); err != nil {
		return err
	}
	got, err := repo.FindByEmail(ctx, u.Email)
	if err != nil {
		return err
	}
	if got != u {
		return errors.New("round trip mismatch")
	}
	if err := repo.UpdateEmail(ctx, u.ID, "new@example.com"); err != nil {
		return err
	}
	_, err = repo.FindByEmail(ctx, "new@example.com")
	return err
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		// Demo: avoid printing potentially sensitive underlying SQL errors.
		fmt.Fprintln(os.Stderr, "operation failed")
		os.Exit(1)
	}
	fmt.Println("operation completed")
}
