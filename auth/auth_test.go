package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/storage/memory"
)

func TestEmailPasswordFlow(t *testing.T) {
	store := memory.New()
	s, err := New(Config{
		Secret:       "01234567890123456789012345678901",
		PrimaryStore: store,
		EmailPassword: EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: RateLimitConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	h := s.Handler()

	signUpBody := `{"email":"alice@example.com","password":"supersecure1","name":"Alice"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-up/email", strings.NewReader(signUpBody))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	cookie := rec.Result().Cookies()
	if len(cookie) == 0 {
		t.Fatalf("expected session cookie to be set")
	}

	recSession := httptest.NewRecorder()
	reqSession := httptest.NewRequest(http.MethodGet, "/auth/v1/get-session", nil)
	reqSession.AddCookie(cookie[0])
	h.ServeHTTP(recSession, reqSession)
	if recSession.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recSession.Code, recSession.Body.String())
	}
	if !strings.Contains(recSession.Body.String(), "alice@example.com") {
		t.Fatalf("expected response to include signed-in user")
	}

	recOut := httptest.NewRecorder()
	reqOut := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-out", nil)
	reqOut.AddCookie(cookie[0])
	h.ServeHTTP(recOut, reqOut)
	if recOut.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recOut.Code, recOut.Body.String())
	}

	recSession2 := httptest.NewRecorder()
	reqSession2 := httptest.NewRequest(http.MethodGet, "/auth/v1/get-session", nil)
	reqSession2.AddCookie(cookie[0])
	h.ServeHTTP(recSession2, reqSession2)
	if recSession2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recSession2.Code, recSession2.Body.String())
	}
	if strings.Contains(recSession2.Body.String(), "alice@example.com") {
		t.Fatalf("expected signed out session")
	}
}

func TestUntrustedOriginBlocked(t *testing.T) {
	s, err := New(Config{
		Secret:         "01234567890123456789012345678901",
		PrimaryStore:   memory.New(),
		EmailPassword:  EmailPasswordConfig{Enabled: true},
		TrustedOrigins: []string{"https://app.example.com"},
		RateLimit:      RateLimitConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	body := `{"email":"alice@example.com","password":"supersecure1","name":"Alice"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-up/email", strings.NewReader(body))
	req.Header.Set("Origin", "https://evil.example.com")
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPluginConflictDetection(t *testing.T) {
	_, err := New(Config{
		Secret:       "01234567890123456789012345678901",
		PrimaryStore: memory.New(),
		RateLimit:    RateLimitConfig{Enabled: false},
		Plugins: []plugin.Plugin{
			testPlugin{id: "p1"},
			testPlugin{id: "p2"},
		},
	})
	if err == nil {
		t.Fatalf("expected plugin route conflict error")
	}
}

func TestOpenAPIEndpoint(t *testing.T) {
	s, err := New(Config{
		Secret:        "01234567890123456789012345678901",
		PrimaryStore:  memory.New(),
		EmailPassword: EmailPasswordConfig{Enabled: true},
		RateLimit:     RateLimitConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/openapi.json", nil)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&payload); err != nil {
		t.Fatalf("openapi should be valid json: %v", err)
	}

	paths, ok := payload["paths"].(map[string]any)
	if !ok {
		t.Fatalf("openapi missing paths")
	}
	if _, ok := paths["/auth/v1/sign-in/email"]; !ok {
		t.Fatalf("openapi missing sign-in route")
	}
}

type testPlugin struct {
	id string
}

func (p testPlugin) ID() string { return p.id }

func (p testPlugin) Register(r *plugin.Registry) error {
	return r.Handle(plugin.Endpoint{
		Method:  http.MethodGet,
		Path:    "/plugin-conflict",
		Handler: func(http.ResponseWriter, *http.Request) {},
	})
}
