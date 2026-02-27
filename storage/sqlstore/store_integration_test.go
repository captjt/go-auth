package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/captjt/go-auth/migrations"
	"github.com/captjt/go-auth/storage"
)

func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_TEST_POSTGRES_DSN not set")
	}
	runSQLIntegration(t, "pgx", dsn, migrations.DialectPostgres, NewPostgres)
}

func TestMySQLIntegration(t *testing.T) {
	dsn := os.Getenv("GOAUTH_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_TEST_MYSQL_DSN not set")
	}
	runSQLIntegration(t, "mysql", dsn, migrations.DialectMySQL, NewMySQL)
}

func runSQLIntegration(
	t *testing.T,
	driver string,
	dsn string,
	dialect migrations.Dialect,
	ctor func(*sql.DB) *Store,
) {
	t.Helper()

	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping database: %v", err)
	}

	if err := migrations.Apply(ctx, db, dialect); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	store := ctor(db)
	seed := time.Now().UTC().UnixNano()
	email := fmt.Sprintf("integration-%d@example.com", seed)
	username := fmt.Sprintf("user%d", seed)
	credentialID := fmt.Sprintf("cred-%d", seed)

	user, err := store.CreateUser(ctx, storage.CreateUserParams{
		Email:        email,
		Username:     username,
		Name:         "Integration",
		PasswordHash: "hash",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := store.FindUserByEmail(ctx, email); err != nil {
		t.Fatalf("find user by email: %v", err)
	}
	if _, err := store.FindUserByUsername(ctx, username); err != nil {
		t.Fatalf("find user by username: %v", err)
	}

	expiresAt := time.Now().UTC().Add(30 * time.Minute)
	session, err := store.CreateSession(ctx, storage.CreateSessionParams{
		UserID:    user.ID,
		TokenHash: fmt.Sprintf("token-%d", seed),
		ExpiresAt: expiresAt,
		IPAddress: "127.0.0.1",
		UserAgent: "integration-test",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, session.TokenHash); err != nil {
		t.Fatalf("find session: %v", err)
	}

	token, err := store.CreateVerificationToken(ctx, storage.CreateVerificationTokenParams{
		Kind:       "integration",
		Identifier: user.ID,
		SecretHash: "secret-hash",
		Payload:    "{}",
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create verification token: %v", err)
	}
	if _, err := store.FindActiveVerificationToken(ctx, storage.FindActiveVerificationTokenParams{
		Kind:       "integration",
		Identifier: user.ID,
		SecretHash: "secret-hash",
		Now:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("find active token: %v", err)
	}
	if err := store.ConsumeVerificationToken(ctx, token.ID, time.Now().UTC()); err != nil {
		t.Fatalf("consume token: %v", err)
	}

	if _, err := store.CreatePasskeyCredential(ctx, storage.CreatePasskeyCredentialParams{
		UserID:       user.ID,
		CredentialID: credentialID,
		PublicKey:    "pk",
		Name:         "Integration Key",
	}); err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	if _, err := store.FindPasskeyCredentialByCredentialID(ctx, credentialID); err != nil {
		t.Fatalf("find passkey: %v", err)
	}
}
