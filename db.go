// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// Protector is implemented by DB.
type Protector interface {
	Encrypt(field Field, recordID string, plaintext []byte) ([]byte, error)
	Decrypt(field Field, recordID string, ciphertext []byte) ([]byte, error)
	Index(field Field, plaintext []byte) ([]byte, error)
	Protect(field Field, recordID string, plaintext []byte) (ciphertext, index []byte, err error)
	VerifyIndex(field Field, plaintext, index []byte) error
}

// DB is an initialized encrypted-database handle. It embeds *sql.DB and can be
// used anywhere a *sql.DB is expected via db.DB. The embedded field must not be
// reassigned. A DB must not be copied after initialization.
type DB struct {
	*sql.DB

	encRoot     [32]byte
	idxKey      [32]byte
	databaseID  [32]byte
	initialized bool
}

var _ Protector = (*DB)(nil)

// Create initializes a new database at path. It fails with ErrAlreadyExists if
// the file already exists. The parent directory must exist.
func Create(ctx context.Context, path string, key Key, opts ...Option) (*DB, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	abs, err := preparePath(path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("securesqlite: reserve database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("securesqlite: reserve database: %w", err)
	}

	sqlDB, err := openSQLite(ctx, abs, cfg)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = sqlDB.Close()
		}
	}()

	databaseID, err := generateDatabaseID()
	if err != nil {
		return nil, err
	}
	encRoot, idxKey, err := deriveRoots(key, databaseID)
	if err != nil {
		return nil, err
	}
	metaKey, err := deriveMetadataKey(key, databaseID)
	if err != nil {
		return nil, err
	}
	defer clear(metaKey[:])
	verification := metadataVerification(metaKey, databaseID)

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("securesqlite: begin metadata transaction: %w", err)
	}
	txDone := false
	defer func() {
		if !txDone {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, createMetadataTableSQL); err != nil {
		return nil, fmt.Errorf("securesqlite: create metadata: %w", err)
	}
	if _, err := tx.ExecContext(ctx, insertMetadataSQL, formatVersion, databaseID[:], verification); err != nil {
		return nil, fmt.Errorf("securesqlite: insert metadata: %w", err)
	}
	meta, err := readMetadata(ctx, tx)
	if err != nil {
		return nil, err
	}
	if meta.databaseID != databaseID || !hmac.Equal(meta.verification, verification) {
		return nil, ErrInvalidMetadata
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("securesqlite: commit metadata: %w", err)
	}
	txDone = true

	if err := enableWAL(ctx, sqlDB); err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(cfg.maxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.maxIdleConns)

	success = true
	return &DB{
		DB:          sqlDB,
		encRoot:     encRoot,
		idxKey:      idxKey,
		databaseID:  databaseID,
		initialized: true,
	}, nil
}

// Open opens an existing database at path. It never creates a file and never
// initializes an existing file that lacks verified metadata.
func Open(ctx context.Context, path string, key Key, opts ...Option) (*DB, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	abs, err := preparePath(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInitialized
		}
		return nil, fmt.Errorf("securesqlite: inspect database: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: database path is a symlink", ErrInvalidConfig)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: database is not a regular file", ErrInvalidConfig)
	}

	sqlDB, err := openSQLite(ctx, abs, cfg)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = sqlDB.Close()
		}
	}()

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("securesqlite: begin metadata transaction: %w", err)
	}
	meta, readErr := readMetadata(ctx, tx)
	_ = tx.Rollback()
	if readErr != nil {
		return nil, readErr
	}

	metaKey, err := deriveMetadataKey(key, meta.databaseID)
	if err != nil {
		return nil, err
	}
	defer clear(metaKey[:])
	if !hmac.Equal(meta.verification, metadataVerification(metaKey, meta.databaseID)) {
		return nil, ErrKeyVerification
	}
	encRoot, idxKey, err := deriveRoots(key, meta.databaseID)
	if err != nil {
		return nil, err
	}
	if err := enableWAL(ctx, sqlDB); err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(cfg.maxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.maxIdleConns)

	success = true
	return &DB{
		DB:          sqlDB,
		encRoot:     encRoot,
		idxKey:      idxKey,
		databaseID:  meta.databaseID,
		initialized: true,
	}, nil
}

func openSQLite(ctx context.Context, abs string, cfg config) (*sql.DB, error) {
	sqlDB, err := sql.Open("sqlite", buildDSN(abs, cfg))
	if err != nil {
		return nil, fmt.Errorf("securesqlite: open database: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("securesqlite: open database: %w", err)
	}
	return sqlDB, nil
}

func enableWAL(ctx context.Context, db *sql.DB) error {
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&mode); err != nil {
		return fmt.Errorf("securesqlite: enable WAL: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("%w: journal mode is %q, want wal", ErrInvalidConfig, mode)
	}
	return nil
}

func generateDatabaseID() ([32]byte, error) {
	var id [32]byte
	for {
		if _, err := rand.Read(id[:]); err != nil {
			return [32]byte{}, fmt.Errorf("securesqlite: generate database ID: %w", err)
		}
		if !isZeroBytes(id[:]) {
			return id, nil
		}
	}
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (db *DB) ensureInitialized() error {
	if db == nil || db.DB == nil || !db.initialized {
		return ErrNotInitialized
	}
	return nil
}
