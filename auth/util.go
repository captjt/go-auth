package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
)

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

func joinPath(basePath, path string) string {
	base := normalizePath(basePath)
	p := normalizePath(path)
	if p == "" || p == "/" {
		return base
	}
	if base == "/" {
		return p
	}
	return strings.TrimSuffix(base, "/") + p
}

func newSessionToken() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	return raw, hash, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func requestIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func isOriginTrusted(origin string, trusted []string) bool {
	if strings.TrimSpace(origin) == "" {
		return true
	}
	if len(trusted) == 0 {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		return false
	}
	for _, allowed := range trusted {
		a := strings.TrimSpace(allowed)
		if a == "*" {
			return true
		}
		if strings.EqualFold(origin, a) {
			return true
		}
		allowedURL, err := url.Parse(a)
		if err != nil || allowedURL.Host == "" {
			continue
		}
		if !strings.EqualFold(allowedURL.Scheme, originURL.Scheme) {
			continue
		}
		if strings.HasPrefix(allowedURL.Host, "*.") {
			suffix := strings.TrimPrefix(allowedURL.Host, "*")
			if strings.HasSuffix(strings.ToLower(originURL.Host), strings.ToLower(suffix)) {
				return true
			}
		}
	}
	return false
}
