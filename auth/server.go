package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/captjt/go-auth/plugin"
)

type Server struct {
	cfg                   Config
	routes                map[string]map[string]http.HandlerFunc
	summaries             map[string]map[string]routeDoc
	limiter               *rateLimiter
	openapi               []byte
	emailSignInValidators []plugin.EmailSignInValidator
}

func New(cfg Config) (*Server, error) {
	resolved := cfg.withDefaults()
	if err := resolved.validate(); err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       resolved,
		routes:    map[string]map[string]http.HandlerFunc{},
		summaries: map[string]map[string]routeDoc{},
	}
	if resolved.RateLimit.Enabled {
		s.limiter = newRateLimiter(resolved.RateLimit.Window, resolved.RateLimit.Max)
	}

	if err := s.registerCoreRoutes(); err != nil {
		return nil, err
	}
	if err := s.registerPluginRoutes(); err != nil {
		return nil, err
	}
	if err := s.refreshOpenAPI(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)
		if path == "" {
			path = "/"
		}

		methods, exists := s.routes[path]
		if !exists {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "endpoint not found", nil)
			return
		}

		h, ok := methods[strings.ToUpper(r.Method)]
		if !ok {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", nil)
			return
		}

		if err := s.checkRequestPolicy(r); err != nil {
			writeError(w, http.StatusForbidden, "REQUEST_BLOCKED", err.Error(), nil)
			return
		}

		if s.limiter != nil {
			key := requestIP(r) + ":" + path
			if !s.limiter.Allow(key, time.Now().UTC()) {
				writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", map[string]any{
					"windowSeconds": int(s.cfg.RateLimit.Window.Seconds()),
					"maxRequests":   s.cfg.RateLimit.Max,
				})
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}

func (s *Server) Mount(mux *http.ServeMux, basePath string) {
	mountPath := normalizePath(basePath)
	if mountPath == "" {
		mountPath = s.cfg.BasePath
	}

	if mountPath == s.cfg.BasePath {
		mux.Handle(mountPath, s.Handler())
		mux.Handle(mountPath+"/", s.Handler())
		return
	}

	prefix := strings.TrimSuffix(mountPath, "/")
	mux.Handle(prefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.rewriteAndServe(w, r, prefix)
	}))
	mux.Handle(prefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.rewriteAndServe(w, r, prefix)
	}))
}

func (s *Server) rewriteAndServe(w http.ResponseWriter, r *http.Request, mountPrefix string) {
	cloned := r.Clone(r.Context())
	suffix := strings.TrimPrefix(cloned.URL.Path, mountPrefix)
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	cloned.URL.Path = joinPath(s.cfg.BasePath, suffix)
	s.Handler().ServeHTTP(w, cloned)
}

func (s *Server) OpenAPISpec(_ context.Context) ([]byte, error) {
	out := make([]byte, len(s.openapi))
	copy(out, s.openapi)
	return out, nil
}

func (s *Server) registerCoreRoutes() error {
	if err := s.addRoute("GET", joinPath(s.cfg.BasePath, "/ok"), s.handleOK, routeDoc{
		Method:  "GET",
		Path:    joinPath(s.cfg.BasePath, "/ok"),
		Summary: "Health check",
		Tags:    []string{"Core"},
	}); err != nil {
		return err
	}

	if err := s.addRoute("GET", joinPath(s.cfg.BasePath, "/openapi.json"), s.handleOpenAPI, routeDoc{
		Method:  "GET",
		Path:    joinPath(s.cfg.BasePath, "/openapi.json"),
		Summary: "OpenAPI specification",
		Tags:    []string{"Core"},
	}); err != nil {
		return err
	}

	if !s.cfg.EmailPassword.Enabled {
		return nil
	}

	coreRoutes := []struct {
		method string
		path   string
		h      http.HandlerFunc
		s      string
	}{
		{"POST", joinPath(s.cfg.BasePath, "/sign-up/email"), s.handleSignUpEmail, "Sign up with email and password"},
		{"POST", joinPath(s.cfg.BasePath, "/sign-in/email"), s.handleSignInEmail, "Sign in with email and password"},
		{"POST", joinPath(s.cfg.BasePath, "/sign-out"), s.handleSignOut, "Sign out current session"},
		{"GET", joinPath(s.cfg.BasePath, "/get-session"), s.handleGetSession, "Get current session"},
	}

	for _, rt := range coreRoutes {
		if err := s.addRoute(rt.method, rt.path, rt.h, routeDoc{
			Method:  rt.method,
			Path:    rt.path,
			Summary: rt.s,
			Tags:    []string{"EmailPassword", "Session"},
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) registerPluginRoutes() error {
	registry := plugin.NewRegistry(plugin.Services{
		PrimaryStore:       s.cfg.PrimaryStore,
		CreateSession:      s.createSessionAndSetCookie,
		CurrentSession:     s.currentSession,
		ClearSessionCookie: s.clearSessionCookie,
		MinPasswordLength:  s.cfg.EmailPassword.MinPasswordLength,
		MaxPasswordLength:  s.cfg.EmailPassword.MaxPasswordLength,
		BCryptCost:         s.cfg.EmailPassword.BCryptCost,
	})
	for _, p := range s.cfg.Plugins {
		if p == nil {
			continue
		}
		if strings.TrimSpace(p.ID()) == "" {
			return errors.New("plugin id cannot be empty")
		}
		if err := p.Register(registry); err != nil {
			return fmt.Errorf("register plugin %q: %w", p.ID(), err)
		}
	}

	for _, endpoint := range registry.Endpoints() {
		fullPath := joinPath(s.cfg.BasePath, endpoint.Path)
		if err := s.addRoute(endpoint.Method, fullPath, endpoint.Handler, routeDoc{
			Method:  endpoint.Method,
			Path:    fullPath,
			Summary: endpoint.Summary,
			Tags:    endpoint.Tags,
		}); err != nil {
			return err
		}
	}
	s.emailSignInValidators = registry.EmailSignInValidators()

	return nil
}

func (s *Server) addRoute(method, path string, h http.HandlerFunc, doc routeDoc) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = normalizePath(path)
	if method == "" || path == "" || h == nil {
		return fmt.Errorf("invalid route registration %q %q", method, path)
	}

	if _, ok := s.routes[path]; !ok {
		s.routes[path] = map[string]http.HandlerFunc{}
		s.summaries[path] = map[string]routeDoc{}
	}
	if _, exists := s.routes[path][method]; exists {
		return fmt.Errorf("conflicting route registration for %s %s", method, path)
	}

	s.routes[path][method] = h
	s.summaries[path][method] = doc
	return nil
}

func (s *Server) refreshOpenAPI() error {
	docs := make([]routeDoc, 0, len(s.summaries)*2)
	for path, byMethod := range s.summaries {
		for method, d := range byMethod {
			d.Method = method
			d.Path = path
			docs = append(docs, d)
		}
	}
	spec, err := buildOpenAPISpec(s.cfg.AppName, docs)
	if err != nil {
		return err
	}
	s.openapi = bytes.Clone(spec)
	return nil
}

func (s *Server) checkRequestPolicy(r *http.Request) error {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return nil
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if !isOriginTrusted(origin, s.cfg.TrustedOrigins) {
		return errors.New("origin is not trusted")
	}
	return nil
}
