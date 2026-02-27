package twofactor

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins/internal/plugutil"
	"github.com/captjt/go-auth/storage"
)

const (
	twoFactorStateKind        = "two_factor_state"
	twoFactorStateLookupHash  = "two_factor_state_active"
	defaultStateLifetimeYears = 5
)

type Options struct {
	CodeTTL              time.Duration
	CodeLength           int
	ExposeCodeInResponse bool
	StateTTL             time.Duration
	BackupCodeCount      int
	BackupCodeLength     int
	Send                 Sender
}

type Sender func(userID, code string) error

type Plugin struct {
	opts Options
}

type statePayload struct {
	Secret           string   `json:"secret"`
	Enabled          bool     `json:"enabled"`
	BackupCodeHashes []string `json:"backupCodeHashes,omitempty"`
}

func New(opts Options) *Plugin {
	if opts.CodeTTL <= 0 {
		opts.CodeTTL = 5 * time.Minute
	}
	if opts.CodeLength <= 0 {
		opts.CodeLength = 6
	}
	if opts.StateTTL <= 0 {
		opts.StateTTL = time.Duration(defaultStateLifetimeYears) * 365 * 24 * time.Hour
	}
	if opts.BackupCodeCount <= 0 {
		opts.BackupCodeCount = 8
	}
	if opts.BackupCodeLength <= 0 {
		opts.BackupCodeLength = 8
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "two-factor" }

func (p *Plugin) Register(r *plugin.Registry) error {
	svc := r.Services()

	enable := func(w http.ResponseWriter, req *http.Request) {
		userID := userIDFromRequest(req, svc)
		if userID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId is required", nil)
			return
		}

		secret, err := generateTOTPSecret()
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "SECRET_GEN_FAILED", "failed to generate 2FA secret", nil)
			return
		}

		setupCode := currentTOTP(secret, time.Now().UTC())
		backupCodes, backupHashes, err := p.generateBackupCodes()
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "BACKUP_CODE_GEN_FAILED", "failed to generate backup codes", nil)
			return
		}

		if p.opts.Send != nil {
			if err := p.opts.Send(userID, setupCode); err != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "SEND_FAILED", "failed to send setup code", nil)
				return
			}
		}

		state := statePayload{Secret: secret, Enabled: false, BackupCodeHashes: backupHashes}
		if err := p.saveState(req.Context(), svc.PrimaryStore, userID, state); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_STORE_FAILED", "failed to persist 2FA state", nil)
			return
		}

		resp := map[string]any{
			"enabled":         false,
			"secret":          secret,
			"otpauthURL":      otpAuthURL(userID, secret),
			"backupCodes":     backupCodes,
			"backupCodeCount": len(backupCodes),
		}
		if p.opts.ExposeCodeInResponse {
			resp["code"] = setupCode
		}
		plugutil.WriteJSON(w, http.StatusOK, resp)
	}

	verify := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			UserID string `json:"userId"`
			Code   string `json:"code"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		userID := strings.TrimSpace(body.UserID)
		if userID == "" {
			userID = userIDFromRequest(req, svc)
		}
		if userID == "" || strings.TrimSpace(body.Code) == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId and code are required", nil)
			return
		}

		rec, state, err := p.loadState(req.Context(), svc.PrimaryStore, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusNotFound, "STATE_NOT_FOUND", "2FA setup not found", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_LOAD_FAILED", "failed to load 2FA state", nil)
			return
		}

		if !verifyTOTP(state.Secret, strings.TrimSpace(body.Code), time.Now().UTC()) {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid verification code", nil)
			return
		}
		state.Enabled = true
		if err := p.replaceState(req.Context(), svc.PrimaryStore, userID, rec.ID, state); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_STORE_FAILED", "failed to update 2FA state", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"enabled": true})
	}

	validate := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			UserID string `json:"userId"`
			Code   string `json:"code"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}
		userID := strings.TrimSpace(body.UserID)
		if userID == "" {
			userID = userIDFromRequest(req, svc)
		}
		code := strings.TrimSpace(body.Code)
		if userID == "" || code == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId and code are required", nil)
			return
		}

		rec, state, err := p.loadState(req.Context(), svc.PrimaryStore, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusNotFound, "STATE_NOT_FOUND", "2FA is not configured", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_LOAD_FAILED", "failed to load 2FA state", nil)
			return
		}
		if !state.Enabled {
			plugutil.WriteError(w, http.StatusForbidden, "TWO_FACTOR_NOT_ENABLED", "2FA is not enabled", nil)
			return
		}

		if verifyTOTP(state.Secret, code, time.Now().UTC()) {
			plugutil.WriteJSON(w, http.StatusOK, map[string]any{"valid": true, "method": "totp"})
			return
		}

		codeHash := plugutil.HashSecret(code)
		consumed := false
		nextHashes := make([]string, 0, len(state.BackupCodeHashes))
		for _, h := range state.BackupCodeHashes {
			if !consumed && h == codeHash {
				consumed = true
				continue
			}
			nextHashes = append(nextHashes, h)
		}
		if !consumed {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid 2FA code", nil)
			return
		}

		state.BackupCodeHashes = nextHashes
		if err := p.replaceState(req.Context(), svc.PrimaryStore, userID, rec.ID, state); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_STORE_FAILED", "failed to persist backup code consumption", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"valid": true, "method": "backup_code", "remainingBackupCodes": len(nextHashes)})
	}

	regenerateBackupCodes := func(w http.ResponseWriter, req *http.Request) {
		userID := userIDFromRequest(req, svc)
		if userID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId is required", nil)
			return
		}

		rec, state, err := p.loadState(req.Context(), svc.PrimaryStore, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteError(w, http.StatusNotFound, "STATE_NOT_FOUND", "2FA setup not found", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_LOAD_FAILED", "failed to load 2FA state", nil)
			return
		}

		codes, hashes, err := p.generateBackupCodes()
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "BACKUP_CODE_GEN_FAILED", "failed to generate backup codes", nil)
			return
		}
		state.BackupCodeHashes = hashes
		if err := p.replaceState(req.Context(), svc.PrimaryStore, userID, rec.ID, state); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_STORE_FAILED", "failed to persist backup codes", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"backupCodes": codes, "backupCodeCount": len(codes)})
	}

	disable := func(w http.ResponseWriter, req *http.Request) {
		userID := userIDFromRequest(req, svc)
		if userID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId is required", nil)
			return
		}

		rec, _, err := p.loadState(req.Context(), svc.PrimaryStore, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteJSON(w, http.StatusOK, map[string]any{"enabled": false})
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_LOAD_FAILED", "failed to load 2FA state", nil)
			return
		}
		if err := svc.PrimaryStore.ConsumeVerificationToken(req.Context(), rec.ID, time.Now().UTC()); err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_DELETE_FAILED", "failed to disable 2FA", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"enabled": false})
	}

	status := func(w http.ResponseWriter, req *http.Request) {
		userID := userIDFromRequest(req, svc)
		if userID == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "userId is required", nil)
			return
		}

		_, state, err := p.loadState(req.Context(), svc.PrimaryStore, userID)
		if err == storage.ErrNotFound {
			plugutil.WriteJSON(w, http.StatusOK, map[string]any{"configured": false, "enabled": false, "backupCodesRemaining": 0})
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "STATE_LOAD_FAILED", "failed to load 2FA state", nil)
			return
		}
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{
			"configured":           true,
			"enabled":              state.Enabled,
			"backupCodesRemaining": len(state.BackupCodeHashes),
		})
	}

	for _, ep := range []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/plugins/2fa/enable", Summary: "Start two-factor setup", Tags: []string{"TwoFactor"}, Handler: enable},
		{Method: http.MethodPost, Path: "/plugins/2fa/verify", Summary: "Verify and enable two-factor", Tags: []string{"TwoFactor"}, Handler: verify},
		{Method: http.MethodPost, Path: "/plugins/2fa/validate", Summary: "Validate a 2FA login code", Tags: []string{"TwoFactor"}, Handler: validate},
		{Method: http.MethodPost, Path: "/plugins/2fa/backup-codes/regenerate", Summary: "Regenerate backup codes", Tags: []string{"TwoFactor"}, Handler: regenerateBackupCodes},
		{Method: http.MethodPost, Path: "/plugins/2fa/disable", Summary: "Disable two-factor", Tags: []string{"TwoFactor"}, Handler: disable},
		{Method: http.MethodGet, Path: "/plugins/2fa/status", Summary: "Check two-factor status", Tags: []string{"TwoFactor"}, Handler: status},
	} {
		if err := r.Handle(ep); err != nil {
			return err
		}
	}

	r.AddEmailSignInValidator(func(attempt plugin.EmailSignInAttempt) error {
		_, state, err := p.loadState(attempt.Request.Context(), svc.PrimaryStore, attempt.User.ID)
		if err == storage.ErrNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		if !state.Enabled {
			return nil
		}

		code := strings.TrimSpace(attempt.TwoFactorCode)
		if code == "" {
			return &plugin.SignInDenyError{
				Status:  http.StatusUnauthorized,
				Code:    "TWO_FACTOR_REQUIRED",
				Message: "two-factor code is required",
			}
		}

		if verifyTOTP(state.Secret, code, time.Now().UTC()) {
			return nil
		}

		codeHash := plugutil.HashSecret(code)
		consumed := false
		nextHashes := make([]string, 0, len(state.BackupCodeHashes))
		for _, h := range state.BackupCodeHashes {
			if !consumed && h == codeHash {
				consumed = true
				continue
			}
			nextHashes = append(nextHashes, h)
		}
		if !consumed {
			return &plugin.SignInDenyError{
				Status:  http.StatusUnauthorized,
				Code:    "INVALID_TWO_FACTOR_CODE",
				Message: "invalid two-factor code",
			}
		}

		rec, _, err := p.loadState(attempt.Request.Context(), svc.PrimaryStore, attempt.User.ID)
		if err != nil {
			return err
		}
		state.BackupCodeHashes = nextHashes
		if err := p.replaceState(attempt.Request.Context(), svc.PrimaryStore, attempt.User.ID, rec.ID, state); err != nil {
			return err
		}
		return nil
	})
	return nil
}

func (p *Plugin) loadState(ctx context.Context, store storage.Primary, userID string) (storage.VerificationToken, statePayload, error) {
	rec, err := store.FindActiveVerificationToken(ctx, storage.FindActiveVerificationTokenParams{
		Kind:       twoFactorStateKind,
		Identifier: strings.TrimSpace(userID),
		SecretHash: plugutil.HashSecret(twoFactorStateLookupHash),
		Now:        time.Now().UTC(),
	})
	if err != nil {
		return storage.VerificationToken{}, statePayload{}, err
	}

	var state statePayload
	if err := json.Unmarshal([]byte(rec.Payload), &state); err != nil {
		return storage.VerificationToken{}, statePayload{}, err
	}
	return rec, state, nil
}

func (p *Plugin) saveState(ctx context.Context, store storage.Primary, userID string, state statePayload) error {
	if rec, _, err := p.loadState(ctx, store, userID); err == nil {
		_ = store.ConsumeVerificationToken(ctx, rec.ID, time.Now().UTC())
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = store.CreateVerificationToken(ctx, storage.CreateVerificationTokenParams{
		Kind:       twoFactorStateKind,
		Identifier: strings.TrimSpace(userID),
		SecretHash: plugutil.HashSecret(twoFactorStateLookupHash),
		Payload:    string(payload),
		ExpiresAt:  time.Now().UTC().Add(p.opts.StateTTL),
	})
	return err
}

func (p *Plugin) replaceState(ctx context.Context, store storage.Primary, userID, currentTokenID string, state statePayload) error {
	_ = store.ConsumeVerificationToken(ctx, currentTokenID, time.Now().UTC())
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = store.CreateVerificationToken(ctx, storage.CreateVerificationTokenParams{
		Kind:       twoFactorStateKind,
		Identifier: strings.TrimSpace(userID),
		SecretHash: plugutil.HashSecret(twoFactorStateLookupHash),
		Payload:    string(payload),
		ExpiresAt:  time.Now().UTC().Add(p.opts.StateTTL),
	})
	return err
}

func (p *Plugin) generateBackupCodes() ([]string, []string, error) {
	codes := make([]string, 0, p.opts.BackupCodeCount)
	hashes := make([]string, 0, p.opts.BackupCodeCount)
	for i := 0; i < p.opts.BackupCodeCount; i++ {
		code, err := plugutil.RandomDigits(p.opts.BackupCodeLength)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, plugutil.HashSecret(code))
	}
	return codes, hashes, nil
}

func userIDFromRequest(req *http.Request, svc plugin.Services) string {
	queryUserID := strings.TrimSpace(req.URL.Query().Get("userId"))
	if queryUserID != "" {
		return queryUserID
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

func generateTOTPSecret() (string, error) {
	raw, err := plugutil.RandomToken(20)
	if err != nil {
		return "", err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(decoded), "="), nil
}

func currentTOTP(secret string, now time.Time) string {
	return totpAt(secret, now, 30)
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) == 0 {
		return false
	}
	for _, delta := range []int64{-30, 0, 30} {
		if totpAt(secret, now.Add(time.Duration(delta)*time.Second), 30) == code {
			return true
		}
	}
	return false
}

func totpAt(secret string, at time.Time, stepSeconds int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return ""
	}
	counter := uint64(at.UTC().Unix() / stepSeconds)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	h := hmac.New(sha1.New, key)
	_, _ = h.Write(msg)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	otp := binaryCode % 1000000
	return fmt.Sprintf("%06d", otp)
}

func otpAuthURL(userID, secret string) string {
	label := url.QueryEscape("go-auth:" + userID)
	issuer := url.QueryEscape("go-auth")
	return "otpauth://totp/" + label + "?secret=" + url.QueryEscape(secret) + "&issuer=" + issuer + "&digits=6&period=30"
}
