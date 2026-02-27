package auth

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	entries map[string]rateEntry
}

type rateEntry struct {
	windowStart time.Time
	count       int
}

func newRateLimiter(window time.Duration, max int) *rateLimiter {
	return &rateLimiter{
		window:  window,
		max:     max,
		entries: map[string]rateEntry{},
	}
}

func (l *rateLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok || now.Sub(entry.windowStart) >= l.window {
		l.entries[key] = rateEntry{windowStart: now, count: 1}
		return true
	}
	if entry.count >= l.max {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}
