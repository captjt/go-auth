package migrations

import (
	"fmt"
	"strings"
)

const CurrentVersion = "2026_02_27_001"

func Statements(d Dialect) ([]string, error) {
	switch d {
	case DialectPostgres:
		return postgresStatements(), nil
	case DialectMySQL:
		return mysqlStatements(), nil
	case DialectSQLite:
		return sqliteStatements(), nil
	default:
		return nil, fmt.Errorf("unsupported dialect %q", d)
	}
}

func GenerateSQLScript(d Dialect) (string, error) {
	stmts, err := Statements(d)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(stmts))
	for _, stmt := range stmts {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		parts = append(parts, trimmed+";")
	}
	return strings.Join(parts, "\n\n"), nil
}

func postgresStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS go_auth_schema_meta (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
		`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
)`,
		`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at BIGINT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS verification_tokens (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    identifier TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    created_at BIGINT NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_lookup ON verification_tokens(kind, identifier, secret_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_expires_at ON verification_tokens(expires_at)`,
		`CREATE TABLE IF NOT EXISTS passkey_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    credential_json TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkey_credentials(user_id)`,
		fmt.Sprintf(`INSERT INTO go_auth_schema_meta(version) VALUES ('%s') ON CONFLICT (version) DO NOTHING`, CurrentVersion),
	}
}

func mysqlStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS go_auth_schema_meta (
    version VARCHAR(64) PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(128) PRIMARY KEY,
    email VARCHAR(320) NOT NULL UNIQUE,
    username VARCHAR(191) UNIQUE,
    name VARCHAR(191) NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    email_verified TINYINT(1) NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at BIGINT NOT NULL,
    ip_address VARCHAR(191) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    INDEX idx_sessions_user_id (user_id),
    CONSTRAINT fk_sessions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS verification_tokens (
    id VARCHAR(128) PRIMARY KEY,
    kind VARCHAR(128) NOT NULL,
    identifier VARCHAR(320) NOT NULL,
    secret_hash VARCHAR(128) NOT NULL,
    payload TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_verification_lookup (kind, identifier, secret_hash),
    INDEX idx_verification_expires_at (expires_at)
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS passkey_credentials (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    credential_json LONGTEXT NOT NULL,
    name VARCHAR(191) NOT NULL DEFAULT '',
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    INDEX idx_passkeys_user_id (user_id),
    CONSTRAINT fk_passkeys_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB`,
		fmt.Sprintf(`INSERT INTO go_auth_schema_meta(version) VALUES ('%s') ON DUPLICATE KEY UPDATE version=version`, CurrentVersion),
	}
}

func sqliteStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS go_auth_schema_meta (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`,
		`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
)`,
		`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS verification_tokens (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    identifier TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_lookup ON verification_tokens(kind, identifier, secret_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_expires_at ON verification_tokens(expires_at)`,
		`CREATE TABLE IF NOT EXISTS passkey_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    credential_json TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
		`CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkey_credentials(user_id)`,
		fmt.Sprintf(`INSERT OR REPLACE INTO go_auth_schema_meta(version, applied_at) VALUES ('%s', CURRENT_TIMESTAMP)`, CurrentVersion),
	}
}
