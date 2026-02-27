package storage

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

type User struct {
	ID            string
	Email         string
	Username      string
	Name          string
	PasswordHash  string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Session struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type VerificationToken struct {
	ID         string
	Kind       string
	Identifier string
	SecretHash string
	Payload    string
	ExpiresAt  time.Time
	UsedAt     *time.Time
	CreatedAt  time.Time
}

type PasskeyCredential struct {
	ID             string
	UserID         string
	CredentialID   string
	PublicKey      string
	CredentialJSON string
	Name           string
	SignCount      int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type CreateUserParams struct {
	Email        string
	Username     string
	Name         string
	PasswordHash string
}

type CreateSessionParams struct {
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
}

type CreateVerificationTokenParams struct {
	Kind       string
	Identifier string
	SecretHash string
	Payload    string
	ExpiresAt  time.Time
}

type FindActiveVerificationTokenParams struct {
	Kind       string
	Identifier string
	SecretHash string
	Now        time.Time
}

type CreatePasskeyCredentialParams struct {
	UserID         string
	CredentialID   string
	PublicKey      string
	CredentialJSON string
	Name           string
	SignCount      int64
}

// Primary is the persistent backend used by go-auth for core entities.
type Primary interface {
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
	FindUserByUsername(ctx context.Context, username string) (User, error)
	FindUserByID(ctx context.Context, id string) (User, error)
	UpdateUserUsername(ctx context.Context, userID, username string) (User, error)

	CreateSession(ctx context.Context, params CreateSessionParams) (Session, error)
	FindSessionByTokenHash(ctx context.Context, tokenHash string) (Session, error)
	DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error

	CreateVerificationToken(ctx context.Context, params CreateVerificationTokenParams) (VerificationToken, error)
	FindActiveVerificationToken(ctx context.Context, params FindActiveVerificationTokenParams) (VerificationToken, error)
	ConsumeVerificationToken(ctx context.Context, id string, usedAt time.Time) error
	DeleteExpiredVerificationTokens(ctx context.Context, now time.Time) error

	CreatePasskeyCredential(ctx context.Context, params CreatePasskeyCredentialParams) (PasskeyCredential, error)
	ListPasskeyCredentialsByUserID(ctx context.Context, userID string) ([]PasskeyCredential, error)
	FindPasskeyCredentialByCredentialID(ctx context.Context, credentialID string) (PasskeyCredential, error)
	DeletePasskeyCredential(ctx context.Context, userID, credentialID string) error
	UpdatePasskeyCredentialName(ctx context.Context, userID, credentialID, name string) (PasskeyCredential, error)
	UpdatePasskeyCredentialSignCount(ctx context.Context, credentialID string, signCount int64) error
}

type Secondary interface {
	// Reserved for future support (session cache, distributed rate limits, etc.)
	Name() string
}
