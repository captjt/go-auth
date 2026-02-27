package username

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins/internal/plugutil"
	"github.com/captjt/go-auth/storage"
)

type Options struct {
	MinUsernameLength int
	MaxUsernameLength int
}

type Plugin struct {
	opts Options
}

func New(opts Options) *Plugin {
	if opts.MinUsernameLength <= 0 {
		opts.MinUsernameLength = 3
	}
	if opts.MaxUsernameLength <= 0 {
		opts.MaxUsernameLength = 32
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "username" }

func (p *Plugin) Register(r *plugin.Registry) error {
	svc := r.Services()

	hashCost := svc.BCryptCost
	if hashCost == 0 {
		hashCost = 12
	}

	signUp := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Email    string `json:"email"`
			Username string `json:"username"`
			Password string `json:"password"`
			Name     string `json:"name"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		email := plugutil.NormalizeEmail(body.Email)
		username := plugutil.NormalizeUsername(body.Username)
		if email == "" || !strings.Contains(email, "@") {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_EMAIL", "invalid email", nil)
			return
		}
		if len(username) < p.opts.MinUsernameLength || len(username) > p.opts.MaxUsernameLength {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_USERNAME_LENGTH", "username length out of range", map[string]any{
				"min": p.opts.MinUsernameLength,
				"max": p.opts.MaxUsernameLength,
			})
			return
		}
		if len(body.Password) < svc.MinPasswordLength || len(body.Password) > svc.MaxPasswordLength {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_PASSWORD_LENGTH", "password length out of range", map[string]any{
				"min": svc.MinPasswordLength,
				"max": svc.MaxPasswordLength,
			})
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), hashCost)
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "PASSWORD_HASH_FAILED", "failed to hash password", nil)
			return
		}

		user, err := svc.PrimaryStore.CreateUser(req.Context(), storage.CreateUserParams{
			Email:        email,
			Username:     username,
			Name:         strings.TrimSpace(body.Name),
			PasswordHash: string(hash),
		})
		if err == storage.ErrAlreadyExists {
			plugutil.WriteError(w, http.StatusConflict, "USER_EXISTS", "user already exists", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "CREATE_USER_FAILED", "failed to create user", nil)
			return
		}

		if svc.CreateSession != nil {
			if err := svc.CreateSession(w, req, user.ID); err != nil {
				plugutil.WriteError(w, http.StatusInternalServerError, "CREATE_SESSION_FAILED", "failed to create session", nil)
				return
			}
		}

		plugutil.WriteJSON(w, http.StatusCreated, map[string]any{
			"user": map[string]any{
				"id":       user.ID,
				"email":    user.Email,
				"username": user.Username,
				"name":     user.Name,
			},
		})
	}

	signIn := func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		user, err := svc.PrimaryStore.FindUserByUsername(req.Context(), body.Username)
		if err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials", nil)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials", nil)
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

	available := func(w http.ResponseWriter, req *http.Request) {
		username := plugutil.NormalizeUsername(req.URL.Query().Get("username"))
		if len(username) < p.opts.MinUsernameLength || len(username) > p.opts.MaxUsernameLength {
			plugutil.WriteJSON(w, http.StatusOK, map[string]any{"available": false})
			return
		}

		_, err := svc.PrimaryStore.FindUserByUsername(req.Context(), username)
		plugutil.WriteJSON(w, http.StatusOK, map[string]any{"available": err == storage.ErrNotFound})
	}

	update := func(w http.ResponseWriter, req *http.Request) {
		if svc.CurrentSession == nil {
			plugutil.WriteError(w, http.StatusNotImplemented, "SESSION_NOT_AVAILABLE", "session flow is unavailable", nil)
			return
		}
		session, _, err := svc.CurrentSession(req)
		if err != nil {
			plugutil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not signed in", nil)
			return
		}

		var body struct {
			Username string `json:"username"`
		}
		if err := plugutil.DecodeJSON(req, &body); err != nil {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON body", nil)
			return
		}

		username := plugutil.NormalizeUsername(body.Username)
		if len(username) < p.opts.MinUsernameLength || len(username) > p.opts.MaxUsernameLength {
			plugutil.WriteError(w, http.StatusBadRequest, "INVALID_USERNAME_LENGTH", "username length out of range", map[string]any{
				"min": p.opts.MinUsernameLength,
				"max": p.opts.MaxUsernameLength,
			})
			return
		}

		user, err := svc.PrimaryStore.UpdateUserUsername(req.Context(), session.UserID, username)
		if err == storage.ErrAlreadyExists {
			plugutil.WriteError(w, http.StatusConflict, "USERNAME_EXISTS", "username is already taken", nil)
			return
		}
		if err != nil {
			plugutil.WriteError(w, http.StatusInternalServerError, "UPDATE_USERNAME_FAILED", "failed to update username", nil)
			return
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

	endpoints := []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/plugins/username/sign-up", Summary: "Sign up with username", Tags: []string{"Username"}, Handler: signUp},
		{Method: http.MethodPost, Path: "/plugins/username/sign-in", Summary: "Sign in with username", Tags: []string{"Username"}, Handler: signIn},
		{Method: http.MethodGet, Path: "/plugins/username/available", Summary: "Check username availability", Tags: []string{"Username"}, Handler: available},
		{Method: http.MethodPost, Path: "/plugins/username/update", Summary: "Update current user's username", Tags: []string{"Username"}, Handler: update},
	}
	for _, ep := range endpoints {
		if err := r.Handle(ep); err != nil {
			return err
		}
	}
	return nil
}
