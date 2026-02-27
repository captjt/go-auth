package sqlstore

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/captjt/go-auth/migrations"
	"github.com/captjt/go-auth/storage"
)

func TestSQLiteStoreCRUD(t *testing.T) {
	db, err := sql.Open("sqlite", "file:sqlstore-test.db?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := migrations.Apply(context.Background(), db, migrations.DialectSQLite); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	store := NewSQLite(db)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, storage.CreateUserParams{
		Email:        "alice@example.com",
		Username:     "alice",
		Name:         "Alice",
		PasswordHash: "hash",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := store.FindUserByEmail(ctx, "alice@example.com"); err != nil {
		t.Fatalf("find user by email: %v", err)
	}
	if _, err := store.FindUserByUsername(ctx, "alice"); err != nil {
		t.Fatalf("find user by username: %v", err)
	}

	if _, err := store.UpdateUserUsername(ctx, user.ID, "alice2"); err != nil {
		t.Fatalf("update username: %v", err)
	}

	expiresAt := time.Now().UTC().Add(1 * time.Hour)
	session, err := store.CreateSession(ctx, storage.CreateSessionParams{
		UserID:    user.ID,
		TokenHash: "token-hash",
		ExpiresAt: expiresAt,
		IPAddress: "127.0.0.1",
		UserAgent: "test",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	gotSession, err := store.FindSessionByTokenHash(ctx, session.TokenHash)
	if err != nil {
		t.Fatalf("find session: %v", err)
	}
	if gotSession.UserID != user.ID {
		t.Fatalf("expected session user %s got %s", user.ID, gotSession.UserID)
	}

	vt, err := store.CreateVerificationToken(ctx, storage.CreateVerificationTokenParams{
		Kind:       "email_otp",
		Identifier: user.Email,
		SecretHash: "otp-hash",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create verification token: %v", err)
	}

	foundToken, err := store.FindActiveVerificationToken(ctx, storage.FindActiveVerificationTokenParams{
		Kind:       "email_otp",
		Identifier: user.Email,
		SecretHash: "otp-hash",
		Now:        time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("find active token: %v", err)
	}
	if foundToken.ID != vt.ID {
		t.Fatalf("unexpected token id %s", foundToken.ID)
	}

	if err := store.ConsumeVerificationToken(ctx, vt.ID, time.Now().UTC()); err != nil {
		t.Fatalf("consume token: %v", err)
	}

	if _, err := store.FindActiveVerificationToken(ctx, storage.FindActiveVerificationTokenParams{
		Kind:       "email_otp",
		Identifier: user.Email,
		SecretHash: "otp-hash",
		Now:        time.Now().UTC(),
	}); err != storage.ErrNotFound {
		t.Fatalf("expected not found after consume, got %v", err)
	}

	cred, err := store.CreatePasskeyCredential(ctx, storage.CreatePasskeyCredentialParams{
		UserID:       user.ID,
		CredentialID: "cred-1",
		PublicKey:    "pk",
		Name:         "Laptop",
	})
	if err != nil {
		t.Fatalf("create passkey: %v", err)
	}

	if _, err := store.FindPasskeyCredentialByCredentialID(ctx, cred.CredentialID); err != nil {
		t.Fatalf("find passkey: %v", err)
	}

	creds, err := store.ListPasskeyCredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected one passkey, got %d", len(creds))
	}

	if err := store.UpdatePasskeyCredentialSignCount(ctx, cred.CredentialID, 2); err != nil {
		t.Fatalf("update sign count: %v", err)
	}

	if _, err := store.UpdatePasskeyCredentialName(ctx, user.ID, cred.CredentialID, "Phone"); err != nil {
		t.Fatalf("rename passkey: %v", err)
	}

	if err := store.DeletePasskeyCredential(ctx, user.ID, cred.CredentialID); err != nil {
		t.Fatalf("delete passkey: %v", err)
	}

	if err := store.DeleteSessionByTokenHash(ctx, session.TokenHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}
}
