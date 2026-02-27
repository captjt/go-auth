package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestGenerateSQLScriptContainsCoreTables(t *testing.T) {
	script, err := GenerateSQLScript(DialectSQLite)
	if err != nil {
		t.Fatalf("generate script: %v", err)
	}

	for _, expected := range []string{"users", "sessions", "verification_tokens", "passkey_credentials"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script missing %s", expected)
		}
	}
}

func TestApplySQLiteMigrations(t *testing.T) {
	db, err := sql.Open("sqlite", "file:migrations-test.db?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := Apply(context.Background(), db, DialectSQLite); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	for _, table := range []string{"users", "sessions", "verification_tokens", "passkey_credentials"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatalf("query sqlite_master for %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("expected table %s to exist", table)
		}
	}
}
