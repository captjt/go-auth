package plugin

import (
	"net/http"

	"github.com/captjt/go-auth/storage"
)

type Endpoint struct {
	Method  string
	Path    string
	Summary string
	Tags    []string
	Handler http.HandlerFunc
}

type Services struct {
	PrimaryStore       storage.Primary
	CreateSession      func(w http.ResponseWriter, r *http.Request, userID string) error
	CurrentSession     func(r *http.Request) (storage.Session, storage.User, error)
	ClearSessionCookie func(w http.ResponseWriter)
	MinPasswordLength  int
	MaxPasswordLength  int
	BCryptCost         int
}

type EmailSignInAttempt struct {
	Request       *http.Request
	User          storage.User
	TwoFactorCode string
}

type EmailSignInValidator func(EmailSignInAttempt) error

type SignInDenyError struct {
	Status  int
	Code    string
	Message string
}

func (e *SignInDenyError) Error() string {
	return e.Message
}

type Plugin interface {
	ID() string
	Register(*Registry) error
}
