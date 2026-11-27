// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const (
	metadataTable = "_securesqlite"
	formatVersion = 1
)

const createMetadataTableSQL = `CREATE TABLE _securesqlite (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	format_version INTEGER NOT NULL CHECK (format_version > 0),
	database_id BLOB NOT NULL CHECK (length(database_id) = 32),
	verification BLOB NOT NULL CHECK (length(verification) = 32)
) STRICT;`

const insertMetadataSQL = `INSERT INTO _securesqlite
	(id, format_version, database_id, verification)
	VALUES (1, ?, ?, ?);`

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type metadataResult struct {
	databaseID   [32]byte
	verification []byte
}

func readMetadata(ctx context.Context, q queryer) (metadataResult, error) {
	var count int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name = ?`, metadataTable).Scan(&count); err != nil {
		return metadataResult{}, fmt.Errorf("securesqlite: read metadata: %w", err)
	}
	if count == 0 {
		return metadataResult{}, ErrNotInitialized
	}
	if count != 1 {
		return metadataResult{}, ErrInvalidMetadata
	}

	var objectType string
	var schemaSQL sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT type, sql FROM sqlite_master WHERE name = ?`, metadataTable).Scan(&objectType, &schemaSQL); err != nil {
		return metadataResult{}, fmt.Errorf("securesqlite: read metadata: %w", err)
	}
	if objectType != "table" || !schemaSQL.Valid {
		return metadataResult{}, ErrInvalidMetadata
	}
	sqlText := strings.ToUpper(strings.TrimSpace(schemaSQL.String))
	if !strings.HasPrefix(sqlText, "CREATE TABLE") {
		return metadataResult{}, ErrInvalidMetadata
	}

	var rows int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM _securesqlite`).Scan(&rows); err != nil {
		return metadataResult{}, fmt.Errorf("securesqlite: read metadata: %w", err)
	}
	if rows != 1 {
		return metadataResult{}, ErrInvalidMetadata
	}

	var idType, versionType, databaseIDType, verificationType string
	var databaseIDLen, verificationLen int
	err := q.QueryRowContext(ctx, `SELECT typeof(id), typeof(format_version),
		typeof(database_id), typeof(verification),
		length(database_id), length(verification)
		FROM _securesqlite WHERE id = 1`).
		Scan(&idType, &versionType, &databaseIDType, &verificationType, &databaseIDLen, &verificationLen)
	if errors.Is(err, sql.ErrNoRows) {
		return metadataResult{}, ErrInvalidMetadata
	}
	if err != nil {
		return metadataResult{}, fmt.Errorf("securesqlite: read metadata: %w", err)
	}
	if idType != "integer" || versionType != "integer" || databaseIDType != "blob" ||
		verificationType != "blob" || databaseIDLen != 32 || verificationLen != 32 {
		return metadataResult{}, ErrInvalidMetadata
	}

	var version int64
	if err := q.QueryRowContext(ctx, `SELECT format_version FROM _securesqlite WHERE id = 1`).Scan(&version); err != nil {
		return metadataResult{}, fmt.Errorf("securesqlite: read metadata: %w", err)
	}
	if version != formatVersion {
		if version > formatVersion {
			return metadataResult{}, ErrUnsupportedVersion
		}
		return metadataResult{}, ErrInvalidMetadata
	}

	var databaseID, verification []byte
	if err := q.QueryRowContext(ctx, `SELECT database_id, verification FROM _securesqlite WHERE id = 1`).Scan(&databaseID, &verification); err != nil {
		return metadataResult{}, fmt.Errorf("securesqlite: read metadata: %w", err)
	}
	if len(databaseID) != 32 || len(verification) != 32 {
		return metadataResult{}, ErrInvalidMetadata
	}

	var result metadataResult
	copy(result.databaseID[:], databaseID)
	if isZeroBytes(result.databaseID[:]) {
		return metadataResult{}, ErrInvalidMetadata
	}
	result.verification = verification
	return result, nil
}
