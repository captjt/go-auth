package plugin

import (
	"fmt"
	"strings"
)

type Registry struct {
	endpoints  []Endpoint
	keys       map[string]struct{}
	services   Services
	validators []EmailSignInValidator
}

func NewRegistry(services Services) *Registry {
	return &Registry{
		endpoints:  []Endpoint{},
		keys:       map[string]struct{}{},
		services:   services,
		validators: []EmailSignInValidator{},
	}
}

func (r *Registry) Handle(endpoint Endpoint) error {
	method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	path := normalizePath(endpoint.Path)
	if method == "" || path == "" || endpoint.Handler == nil {
		return fmt.Errorf("invalid plugin endpoint %q %q", method, path)
	}

	key := routeKey(method, path)
	if _, exists := r.keys[key]; exists {
		return fmt.Errorf("conflicting endpoint registration for %s %s", method, path)
	}

	r.keys[key] = struct{}{}
	endpoint.Method = method
	endpoint.Path = path
	r.endpoints = append(r.endpoints, endpoint)
	return nil
}

func (r *Registry) Endpoints() []Endpoint {
	out := make([]Endpoint, len(r.endpoints))
	copy(out, r.endpoints)
	return out
}

func (r *Registry) Services() Services {
	return r.services
}

func (r *Registry) AddEmailSignInValidator(v EmailSignInValidator) {
	if v == nil {
		return
	}
	r.validators = append(r.validators, v)
}

func (r *Registry) EmailSignInValidators() []EmailSignInValidator {
	out := make([]EmailSignInValidator, len(r.validators))
	copy(out, r.validators)
	return out
}

func routeKey(method, path string) string {
	return method + " " + path
}

func normalizePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if len(trimmed) > 1 {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	return trimmed
}
