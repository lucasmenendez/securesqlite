// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateField(t *testing.T) {
	cases := []Field{
		{Table: "users", Column: "email"},
		{Table: "users", Column: "email", Scope: "tenant"},
		{Table: strings.Repeat("t", 255), Column: strings.Repeat("c", 255), Scope: strings.Repeat("s", 1024)},
		{Table: "usuarios", Column: "correo", Scope: "ñ"},
	}
	for _, field := range cases {
		if err := validateField(field); err != nil {
			t.Fatalf("validateField(%+v) = %v", field, err)
		}
	}
}

func TestValidateFieldRejects(t *testing.T) {
	cases := map[string]Field{
		"empty table":      {Column: "email"},
		"empty column":     {Table: "users"},
		"long table":       {Table: strings.Repeat("t", 256), Column: "email"},
		"long column":      {Table: "users", Column: strings.Repeat("c", 256)},
		"long scope":       {Table: "users", Column: "email", Scope: strings.Repeat("s", 1025)},
		"nul table":        {Table: "us\x00ers", Column: "email"},
		"control column":   {Table: "users", Column: "em\x01ail"},
		"del column":       {Table: "users", Column: "em\x7fail"},
		"invalid utf8":     {Table: string([]byte{0xff}), Column: "email"},
		"invalid utf8 col": {Table: "users", Column: string([]byte{0xfe})},
	}
	for name, field := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateField(field); !errors.Is(err, ErrInvalidField) {
				t.Fatalf("error = %v, want ErrInvalidField", err)
			}
		})
	}
}

func TestValidateRecordID(t *testing.T) {
	if err := validateRecordID("user-1"); err != nil {
		t.Fatal(err)
	}
	if err := validateRecordID(strings.Repeat("r", 1024)); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"empty":        "",
		"too long":     strings.Repeat("r", 1025),
		"nul":          "user\x00",
		"control":      "user\x02",
		"invalid utf8": string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRecordID(value); !errors.Is(err, ErrInvalidRecordID) {
				t.Fatalf("error = %v, want ErrInvalidRecordID", err)
			}
		})
	}
}

func TestValidatePlaintext(t *testing.T) {
	if err := validatePlaintext(make([]byte, maxPlaintextSize)); err != nil {
		t.Fatal(err)
	}
	if err := validatePlaintext(make([]byte, maxPlaintextSize+1)); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("error = %v, want ErrValueTooLarge", err)
	}
}
