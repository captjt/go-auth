package emailotp

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins/internal/plugutil"
	"github.com/captjt/go-auth/storage"
)

const verificationKind = "email_otp"

type Sender func(email, otp string) error

type Options struct {
	OTPDigits           int
	TokenTTL            time.Duration
	AutoSignUp          bool
	ExposeOTPInResponse bool
	Send                Sender
}

type Plugin struct {
	opts Options
}

func New(opts Options) *Plugin {
	if opts.OTPDigits <= 0 {
		opts.OTPDigits = 6
	}
	if opts.TokenTTL <= 0 {
		opts.TokenTTL = 10 * time.Minute
	}
	if !opts.AutoSignUp {
		opts.AutoSignUp = true
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "email-otp" }

func (p *Plugin) Register(r *plugin.Registry) error {
	svc := r.Services()
	hashCost := svc.BCryptCost
	if hashCost == 0 {
		hashCost = 12
	}

	send := func(w http.ResponseWriter, req *http.Request) {
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

		otp, err := plugutil.RandomDigits(p.opts.OTPDigits)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "OTP_GEN_FAILED", "failed to generate OTP", nil)
			return
		}

		_, err = svc.PrimaryStore.CreateVerificationToken(req.Context(), storage.CreateVerificationTokenParams{
			Kind:       verificationKind,
			Identifier: email,
			SecretHash: plugutil.HashSecret(otp),
			ExpiresAt:  time.Now().UTC().Add(p.opts.TokenTTL),
		})
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "OTP_STORE_FAILED", "failed to store OTP", nil)
			return
		}

		if p.opts.Send != nil {
			if err := p.opts.Send(email, otp); err != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "SEND_FAILED", "failed to send OTP", nil)
				return
			}
		}

		resp := map[string]any{"success": true}
		if p.opts.ExposeOTPInResponse {
			resp["otp"] = otp
		}
		plugutil.WriteJSON(w, http.StatusOK, resp)
	}

	verify := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
			Name  string `json:"name"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		email := plugutil.NormalizeEmail(body.Email)
		otpRaw := strings.TrimSpace(body.OTP)
		if email == "" || otpRaw == "" {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "email and otp are required", nil)
			return
		}

		rec, err := svc.PrimaryStore.FindActiveVerificationToken(req.Context(), storage.FindActiveVerificationTokenParams{
			Kind:       verificationKind,
			Identifier: email,
			SecretHash: plugutil.HashSecret(otpRaw),
			Now:        time.Now().UTC(),
		})
		if err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_OR_EXPIRED_OTP", "invalid or expired OTP", nil)
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
		{Method: http.MethodPost, Path: "/plugins/email-otp/send", Summary: "Send an email OTP", Tags: []string{"EmailOTP"}, Handler: send},
		{Method: http.MethodPost, Path: "/plugins/email-otp/verify", Summary: "Verify OTP and sign in", Tags: []string{"EmailOTP"}, Handler: verify},
	} {
		if err := r.Handle(ep); err != nil {
			return err
		}
	}
	return nil
}
