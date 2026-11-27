// Copyright (C) 2026 Lucas Menendez
// SPDX-License-Identifier: AGPL-3.0-only

package securesqlite

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type config struct {
	busyTimeout  time.Duration
	maxOpenConns int
	maxIdleConns int
}

func defaultConfig() config {
	return config{
		busyTimeout:  5 * time.Second,
		maxOpenConns: 1,
		maxIdleConns: 1,
	}
}

// Option configures Create or Open.
type Option func(*config) error

// WithBusyTimeout sets SQLite's busy timeout for every connection. The value
// must be a whole number of milliseconds between 0 and 60 seconds.
func WithBusyTimeout(timeout time.Duration) Option {
	return func(c *config) error {
		if timeout < 0 || timeout > 60*time.Second || timeout%time.Millisecond != 0 {
			return fmt.Errorf("%w: busy timeout must be a whole number of milliseconds between 0 and 60000", ErrInvalidConfig)
		}
		c.busyTimeout = timeout
		return nil
	}
}

// WithMaxOpenConns sets the maximum number of open connections. The default is
// 1. Values below 1 are rejected.
func WithMaxOpenConns(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: max open connections must be at least 1", ErrInvalidConfig)
		}
		c.maxOpenConns = n
		return nil
	}
}

// WithMaxIdleConns sets the maximum number of idle connections. The default is
// 1. The value must be between 0 and the maximum number of open connections.
func WithMaxIdleConns(n int) Option {
	return func(c *config) error {
		if n < 0 {
			return fmt.Errorf("%w: max idle connections must not be negative", ErrInvalidConfig)
		}
		c.maxIdleConns = n
		return nil
	}
}

func newConfig(opts []Option) (config, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			return config{}, fmt.Errorf("%w: nil option", ErrInvalidConfig)
		}
		if err := opt(&cfg); err != nil {
			return config{}, err
		}
	}
	if cfg.maxIdleConns > cfg.maxOpenConns {
		return config{}, fmt.Errorf("%w: max idle connections exceeds max open connections", ErrInvalidConfig)
	}
	return cfg, nil
}

func preparePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty database path", ErrInvalidConfig)
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%w: database path contains NUL", ErrInvalidConfig)
	}
	if path == ":memory:" || strings.HasPrefix(strings.ToLower(path), "file:") {
		return "", fmt.Errorf("%w: SQLite URIs and in-memory databases are not supported", ErrInvalidConfig)
	}
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		return "", fmt.Errorf("%w: network and URI paths are not supported", ErrInvalidConfig)
	}
	if runtime.GOOS == "windows" && strings.HasPrefix(path, `\\`) {
		return "", fmt.Errorf("%w: UNC paths are not supported", ErrInvalidConfig)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: resolve database path: %v", ErrInvalidConfig, err)
	}
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("%w: parent directory: %v", ErrInvalidConfig, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: parent path is not a directory", ErrInvalidConfig)
	}
	return abs, nil
}

func buildDSN(abs string, cfg config) string {
	p := filepath.ToSlash(abs)
	if runtime.GOOS == "windows" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := &url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", cfg.busyTimeout.Milliseconds()))
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "temp_store(MEMORY)")
	q.Add("_pragma", "trusted_schema(OFF)")
	u.RawQuery = q.Encode()
	return u.String()
}
