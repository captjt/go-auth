package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/captjt/go-auth/storage"
)

type dialect int

const (
	dialectPostgres dialect = iota + 1
	dialectMySQL
	dialectSQLite
)

type Store struct {
	db      *sql.DB
	dialect dialect
	seq     uint64
}

func NewPostgres(db *sql.DB) *Store {
	return &Store{db: db, dialect: dialectPostgres}
}

func NewMySQL(db *sql.DB) *Store {
	return &Store{db: db, dialect: dialectMySQL}
}

func NewSQLite(db *sql.DB) *Store {
	return &Store{db: db, dialect: dialectSQLite}
}

func (s *Store) CreateUser(ctx context.Context, params storage.CreateUserParams) (storage.User, error) {
	email := normalizeEmail(params.Email)
	username := normalizeUsername(params.Username)
	if email == "" {
		return storage.User{}, storage.ErrAlreadyExists
	}

	now := time.Now().UTC()
	id := s.newID("usr")
	q := fmt.Sprintf(
		"INSERT INTO users (id, email, username, name, password_hash, email_verified, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
		s.p(1), s.p(2), s.p(3), s.p(4), s.p(5), s.p(6), s.p(7), s.p(8),
	)

	var usernameArg any
	if username != "" {
		usernameArg = username
	}

	_, err := s.db.ExecContext(ctx, q,
		id,
		email,
		usernameArg,
		strings.TrimSpace(params.Name),
		params.PasswordHash,
		0,
		now.UnixMilli(),
		now.UnixMilli(),
	)
	if err != nil {
		if isDuplicateError(err) {
			return storage.User{}, storage.ErrAlreadyExists
		}
		return storage.User{}, err
	}

	return storage.User{
		ID:           id,
		Email:        email,
		Username:     username,
		Name:         strings.TrimSpace(params.Name),
		PasswordHash: params.PasswordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (storage.User, error) {
	q := fmt.Sprintf("SELECT id, email, username, name, password_hash, CASE WHEN email_verified THEN 1 ELSE 0 END, created_at, updated_at FROM users WHERE email = %s", s.p(1))
	return s.scanUserRow(ctx, q, normalizeEmail(email))
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (storage.User, error) {
	normalized := normalizeUsername(username)
	if normalized == "" {
		return storage.User{}, storage.ErrNotFound
	}
	q := fmt.Sprintf("SELECT id, email, username, name, password_hash, CASE WHEN email_verified THEN 1 ELSE 0 END, created_at, updated_at FROM users WHERE username = %s", s.p(1))
	return s.scanUserRow(ctx, q, normalized)
}

func (s *Store) FindUserByID(ctx context.Context, id string) (storage.User, error) {
	q := fmt.Sprintf("SELECT id, email, username, name, password_hash, CASE WHEN email_verified THEN 1 ELSE 0 END, created_at, updated_at FROM users WHERE id = %s", s.p(1))
	return s.scanUserRow(ctx, q, strings.TrimSpace(id))
}

func (s *Store) UpdateUserUsername(ctx context.Context, userID, username string) (storage.User, error) {
	normalized := normalizeUsername(username)
	q := fmt.Sprintf("UPDATE users SET username = %s, updated_at = %s WHERE id = %s", s.p(1), s.p(2), s.p(3))
	var usernameArg any
	if normalized != "" {
		usernameArg = normalized
	}
	_, err := s.db.ExecContext(ctx, q, usernameArg, time.Now().UTC().UnixMilli(), strings.TrimSpace(userID))
	if err != nil {
		if isDuplicateError(err) {
			return storage.User{}, storage.ErrAlreadyExists
		}
		return storage.User{}, err
	}
	return s.FindUserByID(ctx, userID)
}

func (s *Store) CreateSession(ctx context.Context, params storage.CreateSessionParams) (storage.Session, error) {
	now := time.Now().UTC()
	id := s.newID("ses")
	q := fmt.Sprintf("INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
		s.p(1), s.p(2), s.p(3), s.p(4), s.p(5), s.p(6), s.p(7), s.p(8),
	)
	_, err := s.db.ExecContext(ctx, q,
		id,
		strings.TrimSpace(params.UserID),
		strings.TrimSpace(params.TokenHash),
		params.ExpiresAt.UTC().UnixMilli(),
		strings.TrimSpace(params.IPAddress),
		strings.TrimSpace(params.UserAgent),
		now.UnixMilli(),
		now.UnixMilli(),
	)
	if err != nil {
		if isDuplicateError(err) {
			return storage.Session{}, storage.ErrAlreadyExists
		}
		return storage.Session{}, err
	}

	return storage.Session{
		ID:        id,
		UserID:    strings.TrimSpace(params.UserID),
		TokenHash: strings.TrimSpace(params.TokenHash),
		ExpiresAt: params.ExpiresAt.UTC(),
		IPAddress: strings.TrimSpace(params.IPAddress),
		UserAgent: strings.TrimSpace(params.UserAgent),
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *Store) FindSessionByTokenHash(ctx context.Context, tokenHash string) (storage.Session, error) {
	q := fmt.Sprintf("SELECT id, user_id, token_hash, expires_at, ip_address, user_agent, created_at, updated_at FROM sessions WHERE token_hash = %s", s.p(1))
	row := s.db.QueryRowContext(ctx, q, strings.TrimSpace(tokenHash))
	var rec storage.Session
	var expiresAt int64
	var createdAt int64
	var updatedAt int64
	if err := row.Scan(
		&rec.ID,
		&rec.UserID,
		&rec.TokenHash,
		&expiresAt,
		&rec.IPAddress,
		&rec.UserAgent,
		&createdAt,
		&updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return storage.Session{}, storage.ErrNotFound
		}
		return storage.Session{}, err
	}
	rec.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	rec.CreatedAt = time.UnixMilli(createdAt).UTC()
	rec.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return rec, nil
}

func (s *Store) DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error {
	q := fmt.Sprintf("DELETE FROM sessions WHERE token_hash = %s", s.p(1))
	_, err := s.db.ExecContext(ctx, q, strings.TrimSpace(tokenHash))
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	q := fmt.Sprintf("DELETE FROM sessions WHERE expires_at < %s", s.p(1))
	_, err := s.db.ExecContext(ctx, q, now.UTC().UnixMilli())
	return err
}

func (s *Store) CreateVerificationToken(ctx context.Context, params storage.CreateVerificationTokenParams) (storage.VerificationToken, error) {
	now := time.Now().UTC()
	id := s.newID("vt")
	q := fmt.Sprintf("INSERT INTO verification_tokens (id, kind, identifier, secret_hash, payload, expires_at, used_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
		s.p(1), s.p(2), s.p(3), s.p(4), s.p(5), s.p(6), s.p(7), s.p(8),
	)
	_, err := s.db.ExecContext(ctx, q,
		id,
		strings.TrimSpace(params.Kind),
		strings.TrimSpace(params.Identifier),
		strings.TrimSpace(params.SecretHash),
		params.Payload,
		params.ExpiresAt.UTC().UnixMilli(),
		nil,
		now.UnixMilli(),
	)
	if err != nil {
		return storage.VerificationToken{}, err
	}
	return storage.VerificationToken{
		ID:         id,
		Kind:       strings.TrimSpace(params.Kind),
		Identifier: strings.TrimSpace(params.Identifier),
		SecretHash: strings.TrimSpace(params.SecretHash),
		Payload:    params.Payload,
		ExpiresAt:  params.ExpiresAt.UTC(),
		CreatedAt:  now,
	}, nil
}

func (s *Store) FindActiveVerificationToken(ctx context.Context, params storage.FindActiveVerificationTokenParams) (storage.VerificationToken, error) {
	q := fmt.Sprintf(`SELECT id, kind, identifier, secret_hash, payload, expires_at, used_at, created_at
FROM verification_tokens
WHERE kind = %s AND identifier = %s AND secret_hash = %s AND used_at IS NULL AND expires_at >= %s
ORDER BY created_at DESC
LIMIT 1`, s.p(1), s.p(2), s.p(3), s.p(4))
	row := s.db.QueryRowContext(ctx, q,
		strings.TrimSpace(params.Kind),
		strings.TrimSpace(params.Identifier),
		strings.TrimSpace(params.SecretHash),
		params.Now.UTC().UnixMilli(),
	)

	var rec storage.VerificationToken
	var expiresAt int64
	var usedAt sql.NullInt64
	var createdAt int64
	if err := row.Scan(
		&rec.ID,
		&rec.Kind,
		&rec.Identifier,
		&rec.SecretHash,
		&rec.Payload,
		&expiresAt,
		&usedAt,
		&createdAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return storage.VerificationToken{}, storage.ErrNotFound
		}
		return storage.VerificationToken{}, err
	}
	rec.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	rec.CreatedAt = time.UnixMilli(createdAt).UTC()
	if usedAt.Valid {
		t := time.UnixMilli(usedAt.Int64).UTC()
		rec.UsedAt = &t
	}
	return rec, nil
}

func (s *Store) ConsumeVerificationToken(ctx context.Context, id string, usedAt time.Time) error {
	q := fmt.Sprintf("UPDATE verification_tokens SET used_at = %s WHERE id = %s", s.p(1), s.p(2))
	_, err := s.db.ExecContext(ctx, q, usedAt.UTC().UnixMilli(), strings.TrimSpace(id))
	return err
}

func (s *Store) DeleteExpiredVerificationTokens(ctx context.Context, now time.Time) error {
	q := fmt.Sprintf("DELETE FROM verification_tokens WHERE expires_at < %s", s.p(1))
	_, err := s.db.ExecContext(ctx, q, now.UTC().UnixMilli())
	return err
}

func (s *Store) CreatePasskeyCredential(ctx context.Context, params storage.CreatePasskeyCredentialParams) (storage.PasskeyCredential, error) {
	now := time.Now().UTC()
	id := s.newID("pk")
	q := fmt.Sprintf("INSERT INTO passkey_credentials (id, user_id, credential_id, public_key, credential_json, name, sign_count, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
		s.p(1), s.p(2), s.p(3), s.p(4), s.p(5), s.p(6), s.p(7), s.p(8), s.p(9),
	)
	_, err := s.db.ExecContext(ctx, q,
		id,
		strings.TrimSpace(params.UserID),
		strings.TrimSpace(params.CredentialID),
		strings.TrimSpace(params.PublicKey),
		strings.TrimSpace(params.CredentialJSON),
		strings.TrimSpace(params.Name),
		params.SignCount,
		now.UnixMilli(),
		now.UnixMilli(),
	)
	if err != nil {
		if isDuplicateError(err) {
			return storage.PasskeyCredential{}, storage.ErrAlreadyExists
		}
		return storage.PasskeyCredential{}, err
	}
	return storage.PasskeyCredential{
		ID:             id,
		UserID:         strings.TrimSpace(params.UserID),
		CredentialID:   strings.TrimSpace(params.CredentialID),
		PublicKey:      strings.TrimSpace(params.PublicKey),
		CredentialJSON: strings.TrimSpace(params.CredentialJSON),
		Name:           strings.TrimSpace(params.Name),
		SignCount:      params.SignCount,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func (s *Store) ListPasskeyCredentialsByUserID(ctx context.Context, userID string) ([]storage.PasskeyCredential, error) {
	q := fmt.Sprintf("SELECT id, user_id, credential_id, public_key, credential_json, name, sign_count, created_at, updated_at FROM passkey_credentials WHERE user_id = %s ORDER BY created_at DESC", s.p(1))
	rows, err := s.db.QueryContext(ctx, q, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []storage.PasskeyCredential{}
	for rows.Next() {
		var rec storage.PasskeyCredential
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&rec.ID,
			&rec.UserID,
			&rec.CredentialID,
			&rec.PublicKey,
			&rec.CredentialJSON,
			&rec.Name,
			&rec.SignCount,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		rec.CreatedAt = time.UnixMilli(createdAt).UTC()
		rec.UpdatedAt = time.UnixMilli(updatedAt).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) FindPasskeyCredentialByCredentialID(ctx context.Context, credentialID string) (storage.PasskeyCredential, error) {
	q := fmt.Sprintf("SELECT id, user_id, credential_id, public_key, credential_json, name, sign_count, created_at, updated_at FROM passkey_credentials WHERE credential_id = %s", s.p(1))
	row := s.db.QueryRowContext(ctx, q, strings.TrimSpace(credentialID))
	return scanPasskey(row)
}

func (s *Store) DeletePasskeyCredential(ctx context.Context, userID, credentialID string) error {
	q := fmt.Sprintf("DELETE FROM passkey_credentials WHERE user_id = %s AND credential_id = %s", s.p(1), s.p(2))
	res, err := s.db.ExecContext(ctx, q, strings.TrimSpace(userID), strings.TrimSpace(credentialID))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdatePasskeyCredentialName(ctx context.Context, userID, credentialID, name string) (storage.PasskeyCredential, error) {
	q := fmt.Sprintf("UPDATE passkey_credentials SET name = %s, updated_at = %s WHERE user_id = %s AND credential_id = %s", s.p(1), s.p(2), s.p(3), s.p(4))
	res, err := s.db.ExecContext(ctx, q, strings.TrimSpace(name), time.Now().UTC().UnixMilli(), strings.TrimSpace(userID), strings.TrimSpace(credentialID))
	if err != nil {
		return storage.PasskeyCredential{}, err
	}
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return storage.PasskeyCredential{}, storage.ErrNotFound
	}
	return s.FindPasskeyCredentialByCredentialID(ctx, credentialID)
}

func (s *Store) UpdatePasskeyCredentialSignCount(ctx context.Context, credentialID string, signCount int64) error {
	q := fmt.Sprintf("UPDATE passkey_credentials SET sign_count = %s, updated_at = %s WHERE credential_id = %s", s.p(1), s.p(2), s.p(3))
	res, err := s.db.ExecContext(ctx, q, signCount, time.Now().UTC().UnixMilli(), strings.TrimSpace(credentialID))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) scanUserRow(ctx context.Context, q string, arg any) (storage.User, error) {
	row := s.db.QueryRowContext(ctx, q, arg)
	var user storage.User
	var emailVerified int64
	var createdAt int64
	var updatedAt int64
	if err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Name,
		&user.PasswordHash,
		&emailVerified,
		&createdAt,
		&updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return storage.User{}, storage.ErrNotFound
		}
		return storage.User{}, err
	}
	user.EmailVerified = emailVerified != 0
	user.CreatedAt = time.UnixMilli(createdAt).UTC()
	user.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return user, nil
}

func scanPasskey(row *sql.Row) (storage.PasskeyCredential, error) {
	var rec storage.PasskeyCredential
	var createdAt int64
	var updatedAt int64
	if err := row.Scan(
		&rec.ID,
		&rec.UserID,
		&rec.CredentialID,
		&rec.PublicKey,
		&rec.CredentialJSON,
		&rec.Name,
		&rec.SignCount,
		&createdAt,
		&updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return storage.PasskeyCredential{}, storage.ErrNotFound
		}
		return storage.PasskeyCredential{}, err
	}
	rec.CreatedAt = time.UnixMilli(createdAt).UTC()
	rec.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return rec, nil
}

func (s *Store) p(index int) string {
	if s.dialect == dialectPostgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (s *Store) newID(prefix string) string {
	next := atomic.AddUint64(&s.seq, 1)
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UTC().UnixNano(), next)
}

func normalizeEmail(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeUsername(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "duplicate") {
		return true
	}
	if strings.Contains(msg, "unique constraint") {
		return true
	}
	if strings.Contains(msg, "error 1062") {
		return true
	}
	return false
}
