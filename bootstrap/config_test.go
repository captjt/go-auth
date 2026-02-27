package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewServerFromFileMemory(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "go-auth.yaml")

	config := strings.TrimSpace(`appName: "Bootstrap Test"
basePath: "/auth/v1"
secret: "01234567890123456789012345678901"
emailPassword:
  enabled: true
plugins:
  username:
    enabled: true
`) + "\n"

	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	srv, cleanup, err := NewServerFromFile(path)
	if err != nil {
		t.Fatalf("new server from file: %v", err)
	}
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/ok", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	recPlugin := httptest.NewRecorder()
	reqPlugin := httptest.NewRequest(http.MethodGet, "/auth/v1/plugins/username/available?username=tester", nil)
	srv.Handler().ServeHTTP(recPlugin, reqPlugin)
	if recPlugin.Code != http.StatusOK {
		t.Fatalf("expected 200 plugin route, got %d body=%s", recPlugin.Code, recPlugin.Body.String())
	}
}

func TestNewServerFromFileSQLiteAutoMigrate(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "go-auth-sqlite.yaml")
	dbPath := filepath.Join(tmp, "go-auth.db")
	config := strings.TrimSpace(`appName: "Bootstrap SQLite Test"
basePath: "/auth/v1"
secret: "01234567890123456789012345678901"
database:
  dialect: "sqlite"
  dsn: "`+dbPath+`"
  autoMigrate: true
emailPassword:
  enabled: true
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	srv, cleanup, err := NewServerFromFile(cfgPath)
	if err != nil {
		t.Fatalf("new sqlite server from file: %v", err)
	}
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/openapi.json", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}
