package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins/internal/plugutil"
	"github.com/captjt/go-auth/storage"
)

const (
	registerSessionKind = "passkey_register_session"
	signInSessionKind   = "passkey_signin_session"
)

type Options struct {
	ChallengeTTL  time.Duration
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

type Plugin struct {
	opts     Options
	webAuthn *webauthn.WebAuthn
}

func New(opts Options) *Plugin {
	if opts.ChallengeTTL <= 0 {
		opts.ChallengeTTL = 5 * time.Minute
	}
	if strings.TrimSpace(opts.RPID) == "" {
		opts.RPID = "localhost"
	}
	if strings.TrimSpace(opts.RPDisplayName) == "" {
		opts.RPDisplayName = "go-auth"
	}
	if len(opts.RPOrigins) == 0 {
		opts.RPOrigins = []string{"http://localhost:3000", "http://localhost:8080"}
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "passkey" }

func (p *Plugin) Register(r *plugin.Registry) error {
	svc := r.Services()
	wa, err := p.getWebAuthn()
	if err != nil {
		return err
	}

	registerBegin := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			UserID string `json:"userId"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		userID := resolveUserID(req, svc, body.UserID)
		if userID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId is required", nil)
			return
		}

		user, creds, err := p.loadUserAndCredentials(req, svc, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "user not found", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_USER_LOAD_FAILED", "failed to load user for passkey registration", nil)
			return
		}

		waUser := webAuthnUser{user: user, credentials: creds}
		options, sessionData, err := wa.BeginRegistration(waUser)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_BEGIN_FAILED", "failed to begin passkey registration", nil)
			return
		}

		if err := p.persistSessionData(req, svc, registerSessionKind, userID, sessionData); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_SESSION_STORE_FAILED", "failed to persist passkey registration session", nil)
			return
		}

		plugutil.WriteJSON(w, http.StatusOK, map[string]any{
			"options":   options,
			"expiresAt": time.Now().UTC().Add(p.opts.ChallengeTTL),
		})
	}

	registerFinish := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			UserID     string          `json:"userId"`
			Credential json.RawMessage `json:"credential"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		userID := resolveUserID(req, svc, body.UserID)
		if userID == "" || len(body.Credential) == 0 {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId and credential are required", nil)
			return
		}

		vt, sessionData, err := p.loadSessionData(req, svc, registerSessionKind, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_OR_EXPIRED_CHALLENGE", "invalid or expired passkey registration challenge", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_SESSION_LOAD_FAILED", "failed to load passkey registration session", nil)
			return
		}

		user, creds, err := p.loadUserAndCredentials(req, svc, userID)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_USER_LOAD_FAILED", "failed to load user for passkey registration", nil)
			return
		}
		waUser := webAuthnUser{user: user, credentials: creds}

		finishReq := cloneRequestWithBody(req, body.Credential)
		credential, err := wa.FinishRegistration(waUser, *sessionData, finishReq)
		if err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "PASSKEY_REGISTRATION_FAILED", "passkey attestation verification failed", nil)
			return
		}

		credJSON, err := json.Marshal(credential)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_SERIALIZATION_FAILED", "failed to serialize credential", nil)
			return
		}

		credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
		created, err := svc.PrimaryStore.CreatePasskeyCredential(req.Context(), storage.CreatePasskeyCredentialParams{
			UserID:         userID,
			CredentialID:   credentialID,
			PublicKey:      base64.RawURLEncoding.EncodeToString(credential.PublicKey),
			CredentialJSON: string(credJSON),
			Name:           strings.TrimSpace(credentialID),
			SignCount:      int64(credential.Authenticator.SignCount),
		})
		if err == storage.ErrAlreadyExists {
			plugutil.WriteError(w, http.StatusConflict, "PASSKEY_EXISTS", "passkey already exists", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_CREATE_FAILED", "failed to create passkey", nil)
			return
		}

		_ = svc.PrimaryStore.ConsumeVerificationToken(req.Context(), vt.ID, time.Now().UTC())
		plugutil.WriteJSON(w, http.StatusCreated, map[string]any{"passkey": created})
	}

	signInBegin := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			CredentialID string `json:"credentialId"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}
		credentialID := strings.TrimSpace(body.CredentialID)
		if credentialID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "credentialId is required", nil)
			return
		}

		cred, err := svc.PrimaryStore.FindPasskeyCredentialByCredentialID(req.Context(), credentialID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_PASSKEY", "invalid passkey credential", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_LOOKUP_FAILED", "failed to lookup passkey", nil)
			return
		}

		user, creds, err := p.loadUserAndCredentials(req, svc, cred.UserID)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_USER_LOAD_FAILED", "failed to load user for passkey login", nil)
			return
		}
		waUser := webAuthnUser{user: user, credentials: creds}
		options, sessionData, err := wa.BeginLogin(waUser)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_BEGIN_FAILED", "failed to begin passkey sign-in", nil)
			return
		}

		if err := p.persistSessionData(req, svc, signInSessionKind, credentialID, sessionData); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_SESSION_STORE_FAILED", "failed to persist passkey sign-in session", nil)
			return
		}

		plugutil.WriteJSON(w, http.StatusOK, map[string]any{
			"options":   options,
			"expiresAt": time.Now().UTC().Add(p.opts.ChallengeTTL),
		})
	}

	signInFinish := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			CredentialID string          `json:"credentialId"`
			Credential   json.RawMessage `json:"credential"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}
		credentialID := strings.TrimSpace(body.CredentialID)
		if credentialID == "" || len(body.Credential) == 0 {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "credentialId and credential are required", nil)
			return
		}

		vt, sessionData, err := p.loadSessionData(req, svc, signInSessionKind, credentialID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_OR_EXPIRED_CHALLENGE", "invalid or expired passkey sign-in challenge", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_SESSION_LOAD_FAILED", "failed to load passkey sign-in session", nil)
			return
		}

		credRec, err := svc.PrimaryStore.FindPasskeyCredentialByCredentialID(req.Context(), credentialID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_PASSKEY", "invalid passkey credential", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_LOOKUP_FAILED", "failed to lookup passkey", nil)
			return
		}

		user, creds, err := p.loadUserAndCredentials(req, svc, credRec.UserID)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_USER_LOAD_FAILED", "failed to load user for passkey login", nil)
			return
		}
		waUser := webAuthnUser{user: user, credentials: creds}

		finishReq := cloneRequestWithBody(req, body.Credential)
		verifiedCredential, err := wa.FinishLogin(waUser, *sessionData, finishReq)
		if err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "PASSKEY_ASSERTION_FAILED", "passkey assertion verification failed", nil)
			return
		}

		verifiedCredID := base64.RawURLEncoding.EncodeToString(verifiedCredential.ID)
		nextSignCount := int64(verifiedCredential.Authenticator.SignCount)
		if nextSignCount <= 0 {
			nextSignCount = credRec.SignCount + 1
		}
		_ = svc.PrimaryStore.UpdatePasskeyCredentialSignCount(req.Context(), verifiedCredID, nextSignCount)
		_ = svc.PrimaryStore.ConsumeVerificationToken(req.Context(), vt.ID, time.Now().UTC())

		if svc.CreateSession != nil {
			if err := svc.CreateSession(w, req, user.ID); err != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "CREATE_SESSION_FAILED", "failed to create session", nil)
				return
			}
		}

		plugutil.WriteJSON(w, http.StatusOK, map[string]any{
			"user": map[string]any{
				"id":       user.ID,
				"email":    user.Email,
				"username": user.Username,
				"name":     user.Name,
			},
		})
	}

	list := func(w http.ResponseWriter, req *http.Request) {
		userID := resolveUserID(req, svc, req.URL.Query().Get("userId"))
		if userID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId is required", nil)
			return
		}
		creds, err := svc.PrimaryStore.ListPasskeyCredentialsByUserID(req.Context(), userID)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_LIST_FAILED", "failed to list passkeys", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"passkeys": creds})
	}

	remove := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			UserID       string `json:"userId"`
			CredentialID string `json:"credentialId"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}
		userID := resolveUserID(req, svc, body.UserID)
		if userID == "" || strings.TrimSpace(body.CredentialID) == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId and credentialId are required", nil)
			return
		}

		err := svc.PrimaryStore.DeletePasskeyCredential(req.Context(), userID, body.CredentialID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusNotFound, "PASSKEY_NOT_FOUND", "passkey not found", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_DELETE_FAILED", "failed to delete passkey", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}

	rename := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			UserID       string `json:"userId"`
			CredentialID string `json:"credentialId"`
			Name         string `json:"name"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}
		userID := resolveUserID(req, svc, body.UserID)
		if userID == "" || strings.TrimSpace(body.CredentialID) == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId and credentialId are required", nil)
			return
		}

		rec, err := svc.PrimaryStore.UpdatePasskeyCredentialName(req.Context(), userID, body.CredentialID, body.Name)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusNotFound, "PASSKEY_NOT_FOUND", "passkey not found", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSKEY_RENAME_FAILED", "failed to update passkey", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"passkey": rec})
	}

	for _, ep := range []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/plugins/passkey/register/begin", Summary: "Begin passkey registration challenge", Tags: []string{"Passkey"}, Handler: registerBegin},
		{Method: http.MethodPost, Path: "/plugins/passkey/register/finish", Summary: "Finish passkey registration", Tags: []string{"Passkey"}, Handler: registerFinish},
		{Method: http.MethodPost, Path: "/plugins/passkey/sign-in/begin", Summary: "Begin passkey sign-in challenge", Tags: []string{"Passkey"}, Handler: signInBegin},
		{Method: http.MethodPost, Path: "/plugins/passkey/sign-in/finish", Summary: "Finish passkey sign-in", Tags: []string{"Passkey"}, Handler: signInFinish},
		{Method: http.MethodGet, Path: "/plugins/passkey/list", Summary: "List user passkeys", Tags: []string{"Passkey"}, Handler: list},
		{Method: http.MethodPost, Path: "/plugins/passkey/delete", Summary: "Delete passkey", Tags: []string{"Passkey"}, Handler: remove},
		{Method: http.MethodPost, Path: "/plugins/passkey/rename", Summary: "Rename passkey", Tags: []string{"Passkey"}, Handler: rename},
	} {
		if err := r.Handle(ep); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) getWebAuthn() (*webauthn.WebAuthn, error) {
	if p.webAuthn != nil {
		return p.webAuthn, nil
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: p.opts.RPDisplayName,
		RPID:          p.opts.RPID,
		RPOrigins:     p.opts.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	p.webAuthn = wa
	return wa, nil
}

func (p *Plugin) persistSessionData(req *http.Request, svc plugin.Services, kind, identifier string, session *webauthn.SessionData) error {
	if session == nil {
		return nil
	}
	if existing, _, err := p.loadSessionData(req, svc, kind, identifier); err == nil {
		_ = svc.PrimaryStore.ConsumeVerificationToken(req.Context(), existing.ID, time.Now().UTC())
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}
	_, err = svc.PrimaryStore.CreateVerificationToken(req.Context(), storage.CreateVerificationTokenParams{
		Kind:       kind,
		Identifier: strings.TrimSpace(identifier),
		SecretHash: plugutil.HashSecret(kind + ":" + strings.TrimSpace(identifier)),
		Payload:    string(payload),
		ExpiresAt:  time.Now().UTC().Add(p.opts.ChallengeTTL),
	})
	return err
}

func (p *Plugin) loadSessionData(req *http.Request, svc plugin.Services, kind, identifier string) (storage.VerificationToken, *webauthn.SessionData, error) {
	vt, err := svc.PrimaryStore.FindActiveVerificationToken(req.Context(), storage.FindActiveVerificationTokenParams{
		Kind:       kind,
		Identifier: strings.TrimSpace(identifier),
		SecretHash: plugutil.HashSecret(kind + ":" + strings.TrimSpace(identifier)),
		Now:        time.Now().UTC(),
	})
	if err != nil {
		return storage.VerificationToken{}, nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(vt.Payload), &session); err != nil {
		return storage.VerificationToken{}, nil, err
	}
	return vt, &session, nil
}

func (p *Plugin) loadUserAndCredentials(req *http.Request, svc plugin.Services, userID string) (storage.User, []webauthn.Credential, error) {
	user, err := svc.PrimaryStore.FindUserByID(req.Context(), strings.TrimSpace(userID))
	if err != nil {
		return storage.User{}, nil, err
	}
	recs, err := svc.PrimaryStore.ListPasskeyCredentialsByUserID(req.Context(), user.ID)
	if err != nil {
		return storage.User{}, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(recs))
	for _, rec := range recs {
		if strings.TrimSpace(rec.CredentialJSON) == "" {
			continue
		}
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(rec.CredentialJSON), &cred); err != nil {
			continue
		}
		creds = append(creds, cred)
	}
	return user, creds, nil
}

func resolveUserID(req *http.Request, svc plugin.Services, userID string) string {
	resolved := strings.TrimSpace(userID)
	if resolved != "" {
		return resolved
	}
	if svc.CurrentSession == nil {
		return ""
	}
	session, _, err := svc.CurrentSession(req)
	if err != nil {
		return ""
	}
	return session.UserID
}

func cloneRequestWithBody(req *http.Request, body []byte) *http.Request {
	cloned := req.Clone(req.Context())
	cloned.Body = io.NopCloser(bytes.NewReader(body))
	cloned.ContentLength = int64(len(body))
	cloned.Header.Set("Content-Type", "application/json")
	return cloned
}

type webAuthnUser struct {
	user        storage.User
	credentials []webauthn.Credential
}

func (u webAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u webAuthnUser) WebAuthnName() string {
	if strings.TrimSpace(u.user.Email) != "" {
		return u.user.Email
	}
	return u.user.ID
}

func (u webAuthnUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.user.Name) != "" {
		return u.user.Name
	}
	if strings.TrimSpace(u.user.Username) != "" {
		return u.user.Username
	}
	return u.user.ID
}

func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
