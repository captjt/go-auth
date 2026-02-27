package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/captjt/go-auth/storage"
)

type Store struct {
	mu sync.RWMutex

	usersByID         map[string]storage.User
	userIDByEmail     map[string]string
	userIDByUsername  map[string]string
	sessionsByHash    map[string]storage.Session
	verificationByID  map[string]storage.VerificationToken
	passkeyByCredID   map[string]storage.PasskeyCredential
	passkeyCredsByUID map[string]map[string]storage.PasskeyCredential

	userSeq         uint64
	sessionSeq      uint64
	verificationSeq uint64
	passkeySeq      uint64
}

func New() *Store {
	return &Store{
		usersByID:         map[string]storage.User{},
		userIDByEmail:     map[string]string{},
		userIDByUsername:  map[string]string{},
		sessionsByHash:    map[string]storage.Session{},
		verificationByID:  map[string]storage.VerificationToken{},
		passkeyByCredID:   map[string]storage.PasskeyCredential{},
		passkeyCredsByUID: map[string]map[string]storage.PasskeyCredential{},
	}
}

func (s *Store) CreateUser(_ context.Context, params storage.CreateUserParams) (storage.User, error) {
	email := normalizeEmail(params.Email)
	username := normalizeUsername(params.Username)
	if email == "" {
		return storage.User{}, storage.ErrAlreadyExists
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.userIDByEmail[email]; exists {
		return storage.User{}, storage.ErrAlreadyExists
	}
	if username != "" {
		if _, exists := s.userIDByUsername[username]; exists {
			return storage.User{}, storage.ErrAlreadyExists
		}
	}

	s.userSeq++
	now := time.Now().UTC()
	user := storage.User{
		ID:           formatID("usr", s.userSeq),
		Email:        email,
		Username:     username,
		Name:         strings.TrimSpace(params.Name),
		PasswordHash: params.PasswordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	s.usersByID[user.ID] = user
	s.userIDByEmail[email] = user.ID
	if username != "" {
		s.userIDByUsername[username] = user.ID
	}

	return user, nil
}

func (s *Store) FindUserByEmail(_ context.Context, email string) (storage.User, error) {
	normalized := normalizeEmail(email)
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.userIDByEmail[normalized]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	user, ok := s.usersByID[id]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return user, nil
}

func (s *Store) FindUserByUsername(_ context.Context, username string) (storage.User, error) {
	normalized := normalizeUsername(username)
	if normalized == "" {
		return storage.User{}, storage.ErrNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.userIDByUsername[normalized]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	user, ok := s.usersByID[id]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return user, nil
}

func (s *Store) FindUserByID(_ context.Context, id string) (storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.usersByID[id]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return user, nil
}

func (s *Store) UpdateUserUsername(_ context.Context, userID, username string) (storage.User, error) {
	normalized := normalizeUsername(username)
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.usersByID[userID]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}

	if normalized != "" {
		if existingUserID, exists := s.userIDByUsername[normalized]; exists && existingUserID != userID {
			return storage.User{}, storage.ErrAlreadyExists
		}
	}

	if user.Username != "" {
		delete(s.userIDByUsername, user.Username)
	}
	user.Username = normalized
	user.UpdatedAt = time.Now().UTC()
	s.usersByID[userID] = user
	if normalized != "" {
		s.userIDByUsername[normalized] = user.ID
	}
	return user, nil
}

func (s *Store) CreateSession(_ context.Context, params storage.CreateSessionParams) (storage.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessionSeq++
	now := time.Now().UTC()
	session := storage.Session{
		ID:        formatID("ses", s.sessionSeq),
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt.UTC(),
		IPAddress: params.IPAddress,
		UserAgent: params.UserAgent,
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.sessionsByHash[params.TokenHash] = session
	return session, nil
}

func (s *Store) FindSessionByTokenHash(_ context.Context, tokenHash string) (storage.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessionsByHash[tokenHash]
	if !ok {
		return storage.Session{}, storage.ErrNotFound
	}
	return session, nil
}

func (s *Store) DeleteSessionByTokenHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessionsByHash, tokenHash)
	return nil
}

func (s *Store) DeleteExpiredSessions(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, session := range s.sessionsByHash {
		if session.ExpiresAt.Before(now) {
			delete(s.sessionsByHash, key)
		}
	}
	return nil
}

func (s *Store) CreateVerificationToken(_ context.Context, params storage.CreateVerificationTokenParams) (storage.VerificationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.verificationSeq++
	now := time.Now().UTC()
	vt := storage.VerificationToken{
		ID:         formatID("vt", s.verificationSeq),
		Kind:       strings.TrimSpace(params.Kind),
		Identifier: strings.TrimSpace(params.Identifier),
		SecretHash: strings.TrimSpace(params.SecretHash),
		Payload:    params.Payload,
		ExpiresAt:  params.ExpiresAt.UTC(),
		CreatedAt:  now,
	}
	s.verificationByID[vt.ID] = vt
	return vt, nil
}

func (s *Store) FindActiveVerificationToken(_ context.Context, params storage.FindActiveVerificationTokenParams) (storage.VerificationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	kind := strings.TrimSpace(params.Kind)
	identifier := strings.TrimSpace(params.Identifier)
	secretHash := strings.TrimSpace(params.SecretHash)
	now := params.Now.UTC()

	var found storage.VerificationToken
	for _, token := range s.verificationByID {
		if token.Kind != kind || token.Identifier != identifier || token.SecretHash != secretHash {
			continue
		}
		if token.UsedAt != nil {
			continue
		}
		if token.ExpiresAt.Before(now) {
			continue
		}
		if found.ID == "" || token.CreatedAt.After(found.CreatedAt) {
			found = token
		}
	}
	if found.ID == "" {
		return storage.VerificationToken{}, storage.ErrNotFound
	}
	return found, nil
}

func (s *Store) ConsumeVerificationToken(_ context.Context, id string, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.verificationByID[id]
	if !ok {
		return storage.ErrNotFound
	}
	if token.UsedAt != nil {
		return nil
	}
	t := usedAt.UTC()
	token.UsedAt = &t
	s.verificationByID[id] = token
	return nil
}

func (s *Store) DeleteExpiredVerificationTokens(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, token := range s.verificationByID {
		if token.ExpiresAt.Before(now) {
			delete(s.verificationByID, id)
		}
	}
	return nil
}

func (s *Store) CreatePasskeyCredential(_ context.Context, params storage.CreatePasskeyCredentialParams) (storage.PasskeyCredential, error) {
	credID := strings.TrimSpace(params.CredentialID)
	if credID == "" {
		return storage.PasskeyCredential{}, storage.ErrAlreadyExists
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.passkeyByCredID[credID]; exists {
		return storage.PasskeyCredential{}, storage.ErrAlreadyExists
	}

	s.passkeySeq++
	now := time.Now().UTC()
	cred := storage.PasskeyCredential{
		ID:             formatID("pk", s.passkeySeq),
		UserID:         strings.TrimSpace(params.UserID),
		CredentialID:   credID,
		PublicKey:      strings.TrimSpace(params.PublicKey),
		CredentialJSON: strings.TrimSpace(params.CredentialJSON),
		Name:           strings.TrimSpace(params.Name),
		SignCount:      params.SignCount,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	s.passkeyByCredID[cred.CredentialID] = cred
	if _, ok := s.passkeyCredsByUID[cred.UserID]; !ok {
		s.passkeyCredsByUID[cred.UserID] = map[string]storage.PasskeyCredential{}
	}
	s.passkeyCredsByUID[cred.UserID][cred.CredentialID] = cred

	return cred, nil
}

func (s *Store) ListPasskeyCredentialsByUserID(_ context.Context, userID string) ([]storage.PasskeyCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	credsMap, ok := s.passkeyCredsByUID[strings.TrimSpace(userID)]
	if !ok {
		return []storage.PasskeyCredential{}, nil
	}
	out := make([]storage.PasskeyCredential, 0, len(credsMap))
	for _, cred := range credsMap {
		out = append(out, cred)
	}
	return out, nil
}

func (s *Store) FindPasskeyCredentialByCredentialID(_ context.Context, credentialID string) (storage.PasskeyCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, ok := s.passkeyByCredID[strings.TrimSpace(credentialID)]
	if !ok {
		return storage.PasskeyCredential{}, storage.ErrNotFound
	}
	return cred, nil
}

func (s *Store) DeletePasskeyCredential(_ context.Context, userID, credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.passkeyByCredID[strings.TrimSpace(credentialID)]
	if !ok {
		return storage.ErrNotFound
	}
	if cred.UserID != strings.TrimSpace(userID) {
		return storage.ErrNotFound
	}

	delete(s.passkeyByCredID, cred.CredentialID)
	if byUser, ok := s.passkeyCredsByUID[cred.UserID]; ok {
		delete(byUser, cred.CredentialID)
	}
	return nil
}

func (s *Store) UpdatePasskeyCredentialName(_ context.Context, userID, credentialID, name string) (storage.PasskeyCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.passkeyByCredID[strings.TrimSpace(credentialID)]
	if !ok || cred.UserID != strings.TrimSpace(userID) {
		return storage.PasskeyCredential{}, storage.ErrNotFound
	}
	cred.Name = strings.TrimSpace(name)
	cred.UpdatedAt = time.Now().UTC()
	s.passkeyByCredID[cred.CredentialID] = cred
	if byUser, ok := s.passkeyCredsByUID[cred.UserID]; ok {
		byUser[cred.CredentialID] = cred
	}
	return cred, nil
}

func (s *Store) UpdatePasskeyCredentialSignCount(_ context.Context, credentialID string, signCount int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.passkeyByCredID[strings.TrimSpace(credentialID)]
	if !ok {
		return storage.ErrNotFound
	}
	cred.SignCount = signCount
	cred.UpdatedAt = time.Now().UTC()
	s.passkeyByCredID[cred.CredentialID] = cred
	if byUser, ok := s.passkeyCredsByUID[cred.UserID]; ok {
		byUser[cred.CredentialID] = cred
	}
	return nil
}

func normalizeEmail(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeUsername(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func formatID(prefix string, seq uint64) string {
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UTC().UnixNano(), seq)
}
