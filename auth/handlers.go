package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/storage"
)

func (s *Server) handleOK(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, okResponse{
		Status:  "ok",
		AppName: s.cfg.AppName,
	})
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.openapi)
}

func (s *Server) handleSignUpEmail(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EmailPassword.DisableSignUp {
		writeError(w, http.StatusForbidden, "SIGN_UP_DISABLED", "email sign-up is disabled", nil)
		return
	}

	var req signUpEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	passwordLen := len(req.Password)
	if email == "" || !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "INVALID_EMAIL", "invalid email", nil)
		return
	}
	if passwordLen < s.cfg.EmailPassword.MinPasswordLength || passwordLen > s.cfg.EmailPassword.MaxPasswordLength {
		writeError(w, http.StatusBadRequest, "INVALID_PASSWORD_LENGTH", "password length out of range", map[string]any{
			"min": s.cfg.EmailPassword.MinPasswordLength,
			"max": s.cfg.EmailPassword.MaxPasswordLength,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.cfg.EmailPassword.BCryptCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "PASSWORD_HASH_FAILED", "failed to hash password", nil)
		return
	}

	user, err := s.cfg.PrimaryStore.CreateUser(r.Context(), storage.CreateUserParams{
		Email:        email,
		Name:         strings.TrimSpace(req.Name),
		PasswordHash: string(hash),
	})
	if err == storage.ErrAlreadyExists {
		writeError(w, http.StatusConflict, "USER_EXISTS", "user already exists", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CREATE_USER_FAILED", "failed to create user", nil)
		return
	}

	public := toPublicUser(user)
	if !s.cfg.EmailPassword.AutoSignInOnSignUp {
		writeJSON(w, http.StatusCreated, sessionEnvelope{User: &public, Session: nil})
		return
	}

	session, err := s.createSession(r, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CREATE_SESSION_FAILED", "failed to create session", nil)
		return
	}
	s.setSessionCookie(w, session.RawToken, session.ExpiresAt)

	writeJSON(w, http.StatusCreated, sessionEnvelope{
		Session: &session.Session,
		User:    &public,
	})
}

func (s *Server) handleSignInEmail(w http.ResponseWriter, r *http.Request) {
	var req signInEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "INVALID_CREDENTIALS", "invalid credentials", nil)
		return
	}

	user, err := s.cfg.PrimaryStore.FindUserByEmail(r.Context(), email)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials", nil)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials", nil)
		return
	}

	for _, validator := range s.emailSignInValidators {
		if validator == nil {
			continue
		}
		err := validator(plugin.EmailSignInAttempt{
			Request:       r,
			User:          user,
			TwoFactorCode: strings.TrimSpace(req.TwoFactorCode),
		})
		if err == nil {
			continue
		}
		if deny, ok := err.(*plugin.SignInDenyError); ok {
			status := deny.Status
			if status == 0 {
				status = http.StatusUnauthorized
			}
			code := strings.TrimSpace(deny.Code)
			if code == "" {
				code = "SIGN_IN_DENIED"
			}
			message := strings.TrimSpace(deny.Message)
			if message == "" {
				message = "sign-in denied"
			}
			writeError(w, status, code, message, nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "SIGN_IN_VALIDATION_FAILED", "failed to validate sign-in", nil)
		return
	}

	session, err := s.createSession(r, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CREATE_SESSION_FAILED", "failed to create session", nil)
		return
	}
	s.setSessionCookie(w, session.RawToken, session.ExpiresAt)

	public := toPublicUser(user)
	writeJSON(w, http.StatusOK, sessionEnvelope{
		Session: &session.Session,
		User:    &public,
	})
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	rawToken, err := r.Cookie(s.cfg.Session.CookieName)
	if err == nil && strings.TrimSpace(rawToken.Value) != "" {
		_ = s.cfg.PrimaryStore.DeleteSessionByTokenHash(r.Context(), hashToken(rawToken.Value))
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	session, user, err := s.currentSession(r)
	if err != nil {
		if err == storage.ErrNotFound {
			s.clearSessionCookie(w)
			writeJSON(w, http.StatusOK, sessionEnvelope{Session: nil, User: nil})
			return
		}
		writeError(w, http.StatusInternalServerError, "SESSION_LOOKUP_FAILED", "failed to fetch session", nil)
		return
	}

	if session.ExpiresAt.Before(time.Now().UTC()) {
		_ = s.cfg.PrimaryStore.DeleteSessionByTokenHash(r.Context(), session.TokenHash)
		s.clearSessionCookie(w)
		writeJSON(w, http.StatusOK, sessionEnvelope{Session: nil, User: nil})
		return
	}

	publicU := toPublicUser(user)
	publicS := toPublicSession(session)
	writeJSON(w, http.StatusOK, sessionEnvelope{
		Session: &publicS,
		User:    &publicU,
	})
}

func (s *Server) currentSession(r *http.Request) (storage.Session, storage.User, error) {
	cookie, err := r.Cookie(s.cfg.Session.CookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return storage.Session{}, storage.User{}, storage.ErrNotFound
	}
	hash := hashToken(cookie.Value)
	session, err := s.cfg.PrimaryStore.FindSessionByTokenHash(r.Context(), hash)
	if err != nil {
		return storage.Session{}, storage.User{}, err
	}
	user, err := s.cfg.PrimaryStore.FindUserByID(r.Context(), session.UserID)
	if err != nil {
		return storage.Session{}, storage.User{}, err
	}
	return session, user, nil
}

type createdSession struct {
	Session   publicSession
	RawToken  string
	ExpiresAt time.Time
}

func (s *Server) createSessionAndSetCookie(w http.ResponseWriter, r *http.Request, userID string) error {
	session, err := s.createSession(r, userID)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, session.RawToken, session.ExpiresAt)
	return nil
}

func (s *Server) createSession(r *http.Request, userID string) (createdSession, error) {
	rawToken, hash, err := newSessionToken()
	if err != nil {
		return createdSession{}, err
	}
	expiresAt := time.Now().UTC().Add(s.cfg.Session.Duration)
	rec, err := s.cfg.PrimaryStore.CreateSession(r.Context(), storage.CreateSessionParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: expiresAt,
		IPAddress: requestIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		return createdSession{}, err
	}
	return createdSession{
		Session:   toPublicSession(rec),
		RawToken:  rawToken,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, rawToken string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Session.CookieName,
		Value:    rawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.Session.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Session.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.Session.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func toPublicUser(u storage.User) publicUser {
	return publicUser{
		ID:            u.ID,
		Email:         u.Email,
		Username:      u.Username,
		Name:          u.Name,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func toPublicSession(s storage.Session) publicSession {
	return publicSession{
		ID:        s.ID,
		UserID:    s.UserID,
		ExpiresAt: s.ExpiresAt,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}
