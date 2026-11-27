// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const usersSchema = `CREATE TABLE users (
	id TEXT PRIMARY KEY NOT NULL,
	name BLOB NOT NULL,
	email BLOB NOT NULL,
	email_index BLOB NOT NULL UNIQUE CHECK (length(email_index) = 32)
) STRICT;`

type user struct {
	ID    string
	Name  string
	Email string
}

var (
	nameField  = Field{Table: "users", Column: "name"}
	emailField = Field{Table: "users", Column: "email"}
)

func insertUser(t *testing.T, db *DB, u user) {
	t.Helper()
	name, err := db.Encrypt(nameField, u.ID, []byte(u.Name))
	if err != nil {
		t.Fatal(err)
	}
	email, index, err := db.Protect(emailField, u.ID, []byte(u.Email))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name, email, email_index) VALUES (?, ?, ?, ?)`,
		u.ID, name, email, index); err != nil {
		t.Fatal(err)
	}
}

func findUserByEmail(t *testing.T, db *DB, email string) (user, error) {
	t.Helper()
	index, err := db.Index(emailField, []byte(email))
	if err != nil {
		return user{}, err
	}
	var u user
	var name, encryptedEmail, storedIndex []byte
	err = db.QueryRow(`SELECT id, name, email, email_index FROM users WHERE email_index = ?`, index).
		Scan(&u.ID, &name, &encryptedEmail, &storedIndex)
	if err != nil {
		return user{}, err
	}
	plainEmail, err := db.Decrypt(emailField, u.ID, encryptedEmail)
	if err != nil {
		return user{}, err
	}
	if err := db.VerifyIndex(emailField, plainEmail, storedIndex); err != nil {
		return user{}, err
	}
	if string(plainEmail) != email {
		return user{}, ErrIndexMismatch
	}
	plainName, err := db.Decrypt(nameField, u.ID, name)
	if err != nil {
		return user{}, err
	}
	u.Name = string(plainName)
	u.Email = string(plainEmail)
	return u, nil
}

func TestUserRepository(t *testing.T) {
	db, _ := testDB(t)
	if _, err := db.Exec(usersSchema); err != nil {
		t.Fatal(err)
	}
	want := user{ID: "user-1", Name: "Alice", Email: "alice@example.com"}
	insertUser(t, db, want)

	got, err := findUserByEmail(t, db, want.Email)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("user = %+v, want %+v", got, want)
	}

	email, index, err := db.Protect(emailField, want.ID, []byte("new@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`UPDATE users SET email = ?, email_index = ? WHERE id = ?`, email, index, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows affected = %d, want 1", n)
	}

	if _, err := findUserByEmail(t, db, want.Email); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old email error = %v, want sql.ErrNoRows", err)
	}
	updated, err := findUserByEmail(t, db, "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Email != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", updated.Email)
	}
}

func TestTransactionCommitAndRollback(t *testing.T) {
	db, _ := testDB(t)
	if _, err := db.Exec(usersSchema); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	name, err := db.Encrypt(nameField, "user-1", []byte("Alice"))
	if err != nil {
		t.Fatal(err)
	}
	email, index, err := db.Protect(emailField, "user-1", []byte("alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, name, email, email_index) VALUES (?, ?, ?, ?)`,
		"user-1", name, email, index); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	rolledBackName, err := db.Encrypt(nameField, "user-2", []byte("Bob"))
	if err != nil {
		t.Fatal(err)
	}
	rolledBackEmail, rolledBackIndex, err := db.Protect(emailField, "user-2", []byte("bob@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, name, email, email_index) VALUES (?, ?, ?, ?)`,
		"user-2", rolledBackName, rolledBackEmail, rolledBackIndex); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count after rollback = %d, want 1", count)
	}
}

func TestMultiTenantIndexes(t *testing.T) {
	db, _ := testDB(t)
	if _, err := db.Exec(`CREATE TABLE tenants (
		id TEXT PRIMARY KEY NOT NULL,
		tenant TEXT NOT NULL,
		email BLOB NOT NULL,
		email_index BLOB NOT NULL,
		UNIQUE (tenant, email_index)
	) STRICT;`); err != nil {
		t.Fatal(err)
	}
	tenantA := Field{Table: "tenants", Column: "email", Scope: "tenant-a"}
	tenantB := Field{Table: "tenants", Column: "email", Scope: "tenant-b"}
	email := []byte("alice@example.com")

	indexA, err := db.Index(tenantA, email)
	if err != nil {
		t.Fatal(err)
	}
	indexB, err := db.Index(tenantB, email)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(indexA, indexB) {
		t.Fatal("tenant scopes produced the same index")
	}

	for i, tc := range []struct {
		id     string
		tenant string
		field  Field
		index  []byte
	}{
		{"a", "tenant-a", tenantA, indexA},
		{"b", "tenant-b", tenantB, indexB},
	} {
		ct, _, err := db.Protect(tc.field, tc.id, email)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO tenants (id, tenant, email, email_index) VALUES (?, ?, ?, ?)`,
			tc.id, tc.tenant, ct, tc.index); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	var found []byte
	if err := db.QueryRow(`SELECT email FROM tenants WHERE tenant = ? AND email_index = ?`, "tenant-a", indexA).Scan(&found); err != nil {
		t.Fatal(err)
	}
	plaintext, err := db.Decrypt(tenantA, "a", found)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, email) {
		t.Fatal("tenant lookup returned the wrong plaintext")
	}
}

func TestPlaintextNotPersisted(t *testing.T) {
	db, path := testDB(t)
	if _, err := db.Exec(usersSchema); err != nil {
		t.Fatal(err)
	}
	marker := "SECURESQLITE_PLAINTEXT_MARKER_7f3a1b2c"
	insertUser(t, db, user{ID: "user-1", Name: marker, Email: marker + "@example.com"})

	check := func() {
		t.Helper()
		matches, err := filepath.Glob(path + "*")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range matches {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(marker)) {
				t.Fatalf("plaintext marker found in %s", name)
			}
		}
	}
	if runtime.GOOS != "windows" {
		check()
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestBackupRestore(t *testing.T) {
	db, path := testDB(t)
	if _, err := db.Exec(usersSchema); err != nil {
		t.Fatal(err)
	}
	insertUser(t, db, user{ID: "user-1", Name: "Alice", Email: "alice@example.com"})

	var busy, logFrames, checkpointed int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		t.Fatal(err)
	}
	if busy != 0 {
		t.Fatalf("wal checkpoint busy = %d, want 0", busy)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(filepath.Dir(path), "backup.db")
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	restored, err := Open(context.Background(), backupPath, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := findUserByEmail(t, restored, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alice" {
		t.Fatalf("name = %q, want Alice", got.Name)
	}

	otherKey := testKey(t)
	otherKey.b[0] ^= 1
	if _, err := Open(context.Background(), backupPath, otherKey); !errors.Is(err, ErrKeyVerification) {
		t.Fatalf("wrong key error = %v, want ErrKeyVerification", err)
	}
}

func TestOfflineRotation(t *testing.T) {
	oldDB, _ := testDB(t)
	if _, err := oldDB.Exec(usersSchema); err != nil {
		t.Fatal(err)
	}
	insertUser(t, oldDB, user{ID: "user-1", Name: "Alice", Email: "alice@example.com"})

	newKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(t.TempDir(), "rotated.db")
	newDB, err := Create(context.Background(), newPath, newKey)
	if err != nil {
		t.Fatal(err)
	}
	defer newDB.Close()
	if _, err := newDB.Exec(usersSchema); err != nil {
		t.Fatal(err)
	}

	var id string
	var name, email, index []byte
	if err := oldDB.QueryRow(`SELECT id, name, email, email_index FROM users`).Scan(&id, &name, &email, &index); err != nil {
		t.Fatal(err)
	}
	plainName, err := oldDB.Decrypt(nameField, id, name)
	if err != nil {
		t.Fatal(err)
	}
	plainEmail, err := oldDB.Decrypt(emailField, id, email)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldDB.VerifyIndex(emailField, plainEmail, index); err != nil {
		t.Fatal(err)
	}
	newName, err := newDB.Encrypt(nameField, id, plainName)
	if err != nil {
		t.Fatal(err)
	}
	newEmail, newIndex, err := newDB.Protect(emailField, id, plainEmail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newDB.Exec(`INSERT INTO users (id, name, email, email_index) VALUES (?, ?, ?, ?)`,
		id, newName, newEmail, newIndex); err != nil {
		t.Fatal(err)
	}
	if err := oldDB.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), newPath, newKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := findUserByEmail(t, reopened, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alice" {
		t.Fatalf("name = %q, want Alice", got.Name)
	}
}
