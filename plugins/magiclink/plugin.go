package magiclink

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins/internal/plugutil"
	"github.com/captjt/go-auth/storage"
)

const verificationKind = "magic_link"

type Sender func(email, token string) error

type Options struct {
	TokenTTL              time.Duration
	AutoSignUp            bool
	ExposeTokenInResponse bool
	Send                  Sender
}

type Plugin struct {
	opts Options
}

func New(opts Options) *Plugin {
	if opts.TokenTTL <= 0 {
		opts.TokenTTL = 15 * time.Minute
	}
	if !opts.AutoSignUp {
		opts.AutoSignUp = true
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "magic-link" }

func (p *Plugin) Register(r *plugin.Registry) error {
	svc := r.Services()
	hashCost := svc.BCryptCost
	if hashCost == 0 {
		hashCost = 12
	}

	requestLink := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Email string `json:"email"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		email := plugutil.NormalizeEmail(body.Email)
		if email == "" || !strings.Contains(email, "@") {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_EMAIL", "invalid email", nil)
			return
		}

		token, err := plugutil.RandomToken(24)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "TOKEN_GEN_FAILED", "failed to generate token", nil)
			return
		}

		_, err = svc.PrimaryStore.CreateVerificationToken(req.Context(), storage.CreateVerificationTokenParams{
			Kind:       verificationKind,
			Identifier: email,
			SecretHash: plugutil.HashSecret(token),
			ExpiresAt:  time.Now().UTC().Add(p.opts.TokenTTL),
		})
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "TOKEN_STORE_FAILED", "failed to store token", nil)
			return
		}

		if p.opts.Send != nil {
			if err := p.opts.Send(email, token); err != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "SEND_FAILED", "failed to send magic link", nil)
				return
			}
		}

		resp := map[string]any{"success": true}
		if p.opts.ExposeTokenInResponse {
			resp["token"] = token
		}
		plugutil.WriteJSON(w, http.StatusOK, resp)
	}

	verifyLink := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Email string `json:"email"`
			Token string `json:"token"`
			Name  string `json:"name"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		email := plugutil.NormalizeEmail(body.Email)
		tokenRaw := strings.TrimSpace(body.Token)
		if email == "" || tokenRaw == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "email and token are required", nil)
			return
		}

		rec, err := svc.PrimaryStore.FindActiveVerificationToken(req.Context(), storage.FindActiveVerificationTokenParams{
			Kind:       verificationKind,
			Identifier: email,
			SecretHash: plugutil.HashSecret(tokenRaw),
			Now:        time.Now().UTC(),
		})
		if err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_OR_EXPIRED_TOKEN", "invalid or expired token", nil)
			return
		}
		_ = svc.PrimaryStore.ConsumeVerificationToken(req.Context(), rec.ID, time.Now().UTC())

		user, err := svc.PrimaryStore.FindUserByEmail(req.Context(), email)
		if err == storage.ErrNotFound {
			if !p.opts.AutoSignUp {
				plugutil.WriteError(w, http.StatusUnauthorized, "SIGN_UP_DISABLED", "user does not exist", nil)
				return
			}
			randPassword, _ := plugutil.RandomToken(24)
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(randPassword), hashCost)
			if hashErr != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "PASSWORD_HASH_FAILED", "failed to prepare account", nil)
				return
			}
			created, createErr := svc.PrimaryStore.CreateUser(req.Context(), storage.CreateUserParams{
				Email:        email,
				Name:         strings.TrimSpace(body.Name),
				PasswordHash: string(hash),
			})
			if createErr != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "CREATE_USER_FAILED", "failed to create user", nil)
				return
			}
			user = created
		} else if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "USER_LOOKUP_FAILED", "failed to lookup user", nil)
			return
		}

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

	for _, ep := range []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/plugins/magic-link/request", Summary: "Request a magic link", Tags: []string{"MagicLink"}, Handler: requestLink},
		{Method: http.MethodPost, Path: "/plugins/magic-link/verify", Summary: "Verify and consume magic link token", Tags: []string{"MagicLink"}, Handler: verifyLink},
	} {
		if err := r.Handle(ep); err != nil {
			return err
		}
	}
	return nil
}
