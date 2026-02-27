package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/captjt/go-auth/auth"
	"github.com/captjt/go-auth/migrations"
	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins"
	"github.com/captjt/go-auth/plugins/emailotp"
	"github.com/captjt/go-auth/plugins/magiclink"
	"github.com/captjt/go-auth/plugins/passkey"
	"github.com/captjt/go-auth/plugins/twofactor"
	"github.com/captjt/go-auth/plugins/username"
	"github.com/captjt/go-auth/storage"
	"github.com/captjt/go-auth/storage/memory"
	"github.com/captjt/go-auth/storage/sqlstore"
)

type FileConfig struct {
	AppName        string   `yaml:"appName"`
	BasePath       string   `yaml:"basePath"`
	Secret         string   `yaml:"secret"`
	TrustedOrigins []string `yaml:"trustedOrigins"`

	Database      *DatabaseConfig     `yaml:"database"`
	EmailPassword EmailPasswordConfig `yaml:"emailPassword"`
	Session       SessionConfig       `yaml:"session"`
	RateLimit     RateLimitConfig     `yaml:"rateLimit"`
	Plugins       PluginConfig        `yaml:"plugins"`
}

type DatabaseConfig struct {
	Dialect     string `yaml:"dialect"`
	DSN         string `yaml:"dsn"`
	AutoMigrate bool   `yaml:"autoMigrate"`
}

type EmailPasswordConfig struct {
	Enabled            bool  `yaml:"enabled"`
	DisableSignUp      bool  `yaml:"disableSignUp"`
	AutoSignInOnSignUp *bool `yaml:"autoSignInOnSignUp"`
	MinPasswordLength  int   `yaml:"minPasswordLength"`
	MaxPasswordLength  int   `yaml:"maxPasswordLength"`
	BCryptCost         int   `yaml:"bCryptCost"`
}

type SessionConfig struct {
	CookieName    string `yaml:"cookieName"`
	Duration      string `yaml:"duration"`
	SecureCookies bool   `yaml:"secureCookies"`
}

type RateLimitConfig struct {
	Enabled bool   `yaml:"enabled"`
	Window  string `yaml:"window"`
	Max     int    `yaml:"max"`
}

type PluginConfig struct {
	Username  UsernamePluginConfig  `yaml:"username"`
	MagicLink MagicLinkPluginConfig `yaml:"magicLink"`
	EmailOTP  EmailOTPPluginConfig  `yaml:"emailOtp"`
	Passkey   PasskeyPluginConfig   `yaml:"passkey"`
	TwoFactor TwoFactorPluginConfig `yaml:"twoFactor"`
}

type UsernamePluginConfig struct {
	Enabled           bool `yaml:"enabled"`
	MinUsernameLength int  `yaml:"minUsernameLength"`
	MaxUsernameLength int  `yaml:"maxUsernameLength"`
}

type MagicLinkPluginConfig struct {
	Enabled               bool   `yaml:"enabled"`
	TokenTTL              string `yaml:"tokenTtl"`
	AutoSignUp            *bool  `yaml:"autoSignUp"`
	ExposeTokenInResponse bool   `yaml:"exposeTokenInResponse"`
}

type EmailOTPPluginConfig struct {
	Enabled             bool   `yaml:"enabled"`
	TokenTTL            string `yaml:"tokenTtl"`
	OTPDigits           int    `yaml:"otpDigits"`
	AutoSignUp          *bool  `yaml:"autoSignUp"`
	ExposeOTPInResponse bool   `yaml:"exposeOtpInResponse"`
}

type PasskeyPluginConfig struct {
	Enabled       bool     `yaml:"enabled"`
	ChallengeTTL  string   `yaml:"challengeTtl"`
	RPID          string   `yaml:"rpId"`
	RPDisplayName string   `yaml:"rpDisplayName"`
	RPOrigins     []string `yaml:"rpOrigins"`
}

type TwoFactorPluginConfig struct {
	Enabled              bool   `yaml:"enabled"`
	CodeTTL              string `yaml:"codeTtl"`
	CodeLength           int    `yaml:"codeLength"`
	StateTTL             string `yaml:"stateTtl"`
	BackupCodeCount      int    `yaml:"backupCodeCount"`
	BackupCodeLength     int    `yaml:"backupCodeLength"`
	ExposeCodeInResponse bool   `yaml:"exposeCodeInResponse"`
}

func LoadFile(path string) (FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, err
	}
	var cfg FileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return FileConfig{}, err
	}
	return cfg, nil
}

func BuildAuthConfig(cfg FileConfig) (auth.Config, func() error, error) {
	primary, cleanup, err := buildPrimaryStore(cfg.Database)
	if err != nil {
		return auth.Config{}, nil, err
	}

	autoSignIn := true
	if cfg.EmailPassword.AutoSignInOnSignUp != nil {
		autoSignIn = *cfg.EmailPassword.AutoSignInOnSignUp
	}

	sessionDuration := parseDuration(cfg.Session.Duration, 7*24*time.Hour)
	rateLimitWindow := parseDuration(cfg.RateLimit.Window, 10*time.Second)

	pluginsList := buildPlugins(cfg.Plugins)

	ac := auth.Config{
		AppName:        strings.TrimSpace(cfg.AppName),
		BasePath:       strings.TrimSpace(cfg.BasePath),
		Secret:         strings.TrimSpace(cfg.Secret),
		TrustedOrigins: cfg.TrustedOrigins,
		PrimaryStore:   primary,
		EmailPassword: auth.EmailPasswordConfig{
			Enabled:            cfg.EmailPassword.Enabled,
			DisableSignUp:      cfg.EmailPassword.DisableSignUp,
			AutoSignInOnSignUp: autoSignIn,
			MinPasswordLength:  cfg.EmailPassword.MinPasswordLength,
			MaxPasswordLength:  cfg.EmailPassword.MaxPasswordLength,
			BCryptCost:         cfg.EmailPassword.BCryptCost,
		},
		Session: auth.SessionConfig{
			CookieName:    cfg.Session.CookieName,
			Duration:      sessionDuration,
			SecureCookies: cfg.Session.SecureCookies,
		},
		RateLimit: auth.RateLimitConfig{
			Enabled: cfg.RateLimit.Enabled,
			Window:  rateLimitWindow,
			Max:     cfg.RateLimit.Max,
		},
		Plugins: pluginsList,
	}

	return ac, cleanup, nil
}

func NewServerFromFile(path string) (*auth.Server, func() error, error) {
	fileCfg, err := LoadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg, cleanup, err := BuildAuthConfig(fileCfg)
	if err != nil {
		return nil, cleanup, err
	}
	srv, err := auth.New(cfg)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return nil, nil, err
	}
	return srv, cleanup, nil
}

func buildPrimaryStore(cfg *DatabaseConfig) (storage.Primary, func() error, error) {
	if cfg == nil {
		return memory.New(), func() error { return nil }, nil
	}
	dialect, err := migrations.ParseDialect(cfg.Dialect)
	if err != nil {
		return nil, nil, err
	}
	driverName, err := migrations.DriverName(dialect)
	if err != nil {
		return nil, nil, err
	}
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, nil, fmt.Errorf("database dsn is required")
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	if cfg.AutoMigrate {
		if err := migrations.Apply(ctx, db, dialect); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
	}

	var store storage.Primary
	switch dialect {
	case migrations.DialectPostgres:
		store = sqlstore.NewPostgres(db)
	case migrations.DialectMySQL:
		store = sqlstore.NewMySQL(db)
	case migrations.DialectSQLite:
		store = sqlstore.NewSQLite(db)
	default:
		_ = db.Close()
		return nil, nil, fmt.Errorf("unsupported dialect %q", dialect)
	}

	return store, db.Close, nil
}

func buildPlugins(cfg PluginConfig) []plugin.Plugin {
	result := []plugin.Plugin{}
	if cfg.Username.Enabled {
		result = append(result, plugins.Username(username.Options{
			MinUsernameLength: cfg.Username.MinUsernameLength,
			MaxUsernameLength: cfg.Username.MaxUsernameLength,
		}))
	}
	if cfg.MagicLink.Enabled {
		autoSignUp := true
		if cfg.MagicLink.AutoSignUp != nil {
			autoSignUp = *cfg.MagicLink.AutoSignUp
		}
		result = append(result, plugins.MagicLink(magiclink.Options{
			TokenTTL:              parseDuration(cfg.MagicLink.TokenTTL, 15*time.Minute),
			AutoSignUp:            autoSignUp,
			ExposeTokenInResponse: cfg.MagicLink.ExposeTokenInResponse,
		}))
	}
	if cfg.EmailOTP.Enabled {
		autoSignUp := true
		if cfg.EmailOTP.AutoSignUp != nil {
			autoSignUp = *cfg.EmailOTP.AutoSignUp
		}
		result = append(result, plugins.EmailOTP(emailotp.Options{
			OTPDigits:           cfg.EmailOTP.OTPDigits,
			TokenTTL:            parseDuration(cfg.EmailOTP.TokenTTL, 10*time.Minute),
			AutoSignUp:          autoSignUp,
			ExposeOTPInResponse: cfg.EmailOTP.ExposeOTPInResponse,
		}))
	}
	if cfg.Passkey.Enabled {
		result = append(result, plugins.Passkey(passkey.Options{
			ChallengeTTL:  parseDuration(cfg.Passkey.ChallengeTTL, 5*time.Minute),
			RPID:          strings.TrimSpace(cfg.Passkey.RPID),
			RPDisplayName: strings.TrimSpace(cfg.Passkey.RPDisplayName),
			RPOrigins:     cfg.Passkey.RPOrigins,
		}))
	}
	if cfg.TwoFactor.Enabled {
		result = append(result, plugins.TwoFactor(twofactor.Options{
			CodeTTL:              parseDuration(cfg.TwoFactor.CodeTTL, 5*time.Minute),
			CodeLength:           cfg.TwoFactor.CodeLength,
			StateTTL:             parseDuration(cfg.TwoFactor.StateTTL, 5*365*24*time.Hour),
			BackupCodeCount:      cfg.TwoFactor.BackupCodeCount,
			BackupCodeLength:     cfg.TwoFactor.BackupCodeLength,
			ExposeCodeInResponse: cfg.TwoFactor.ExposeCodeInResponse,
		}))
	}
	return result
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return fallback
	}
	return d
}
