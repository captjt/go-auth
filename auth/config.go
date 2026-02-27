package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/storage"
)

type Config struct {
	AppName        string
	BasePath       string
	Secret         string
	TrustedOrigins []string

	EmailPassword EmailPasswordConfig
	Session       SessionConfig
	RateLimit     RateLimitConfig

	PrimaryStore   storage.Primary
	SecondaryStore storage.Secondary
	Plugins        []plugin.Plugin
}

type EmailPasswordConfig struct {
	Enabled            bool
	DisableSignUp      bool
	AutoSignInOnSignUp bool
	MinPasswordLength  int
	MaxPasswordLength  int
	BCryptCost         int
}

type SessionConfig struct {
	CookieName    string
	Duration      time.Duration
	SecureCookies bool
}

type RateLimitConfig struct {
	Enabled bool
	Window  time.Duration
	Max     int
}

func (c *Config) withDefaults() Config {
	out := *c
	if strings.TrimSpace(out.AppName) == "" {
		out.AppName = "go-auth"
	}
	if strings.TrimSpace(out.BasePath) == "" {
		out.BasePath = "/auth/v1"
	}

	if out.EmailPassword.MinPasswordLength == 0 {
		out.EmailPassword.MinPasswordLength = 8
	}
	if out.EmailPassword.MaxPasswordLength == 0 {
		out.EmailPassword.MaxPasswordLength = 128
	}
	if out.EmailPassword.BCryptCost == 0 {
		out.EmailPassword.BCryptCost = 12
	}
	if !out.EmailPassword.DisableSignUp && !out.EmailPassword.AutoSignInOnSignUp {
		out.EmailPassword.AutoSignInOnSignUp = true
	}

	if strings.TrimSpace(out.Session.CookieName) == "" {
		out.Session.CookieName = "go_auth_session"
	}
	if out.Session.Duration == 0 {
		out.Session.Duration = 7 * 24 * time.Hour
	}

	if out.RateLimit.Window == 0 {
		out.RateLimit.Window = 10 * time.Second
	}
	if out.RateLimit.Max == 0 {
		out.RateLimit.Max = 100
	}

	out.BasePath = normalizePath(out.BasePath)
	if out.BasePath == "" {
		out.BasePath = "/auth/v1"
	}

	for i := range out.TrustedOrigins {
		out.TrustedOrigins[i] = strings.TrimSpace(out.TrustedOrigins[i])
	}

	return out
}

func (c Config) validate() error {
	if c.PrimaryStore == nil {
		return errors.New("primary store is required")
	}
	if strings.TrimSpace(c.Secret) == "" {
		return errors.New("secret is required")
	}
	if len(c.Secret) < 32 {
		return errors.New("secret must be at least 32 characters")
	}
	if c.EmailPassword.MinPasswordLength <= 0 || c.EmailPassword.MaxPasswordLength < c.EmailPassword.MinPasswordLength {
		return errors.New("invalid password length constraints")
	}
	if c.Session.Duration <= 0 {
		return errors.New("session duration must be positive")
	}
	if c.RateLimit.Enabled && c.RateLimit.Max <= 0 {
		return errors.New("rate limit max must be positive")
	}
	if c.RateLimit.Enabled && c.RateLimit.Window <= 0 {
		return errors.New("rate limit window must be positive")
	}
	return nil
}
