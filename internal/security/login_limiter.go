package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type loginRateEntry struct {
	WindowStart  time.Time
	Attempts     int
	BlockedUntil time.Time
	LastSeenAt   time.Time
}

type LoginRateLimiter struct {
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	block       time.Duration
	entries     map[string]*loginRateEntry
}

func NewLoginRateLimiter(maxAttempts int, window, block time.Duration) *LoginRateLimiter {
	if maxAttempts < 1 {
		maxAttempts = 5
	}
	if window < 10*time.Second {
		window = 15 * time.Minute
	}
	if block < 10*time.Second {
		block = window
	}
	return &LoginRateLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		block:       block,
		entries:     map[string]*loginRateEntry{},
	}
}

func (l *LoginRateLimiter) IsBlocked(key string, now time.Time) (bool, time.Duration) {
	if l == nil || strings.TrimSpace(key) == "" {
		return false, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.gc(now)
	entry := l.entries[key]
	if entry == nil {
		return false, 0
	}

	entry.LastSeenAt = now
	if now.Before(entry.BlockedUntil) {
		return true, entry.BlockedUntil.Sub(now)
	}
	return false, 0
}

func (l *LoginRateLimiter) RegisterFailure(key string, now time.Time) (bool, time.Duration) {
	if l == nil || strings.TrimSpace(key) == "" {
		return false, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.gc(now)

	entry := l.entries[key]
	if entry == nil {
		entry = &loginRateEntry{
			WindowStart: now,
		}
		l.entries[key] = entry
	}

	entry.LastSeenAt = now
	if now.Before(entry.BlockedUntil) {
		return true, entry.BlockedUntil.Sub(now)
	}

	if now.Sub(entry.WindowStart) > l.window {
		entry.WindowStart = now
		entry.Attempts = 0
	}

	entry.Attempts++
	if entry.Attempts >= l.maxAttempts {
		entry.Attempts = 0
		entry.WindowStart = now
		entry.BlockedUntil = now.Add(l.block)
		return true, l.block
	}

	return false, 0
}

func (l *LoginRateLimiter) Reset(key string) {
	if l == nil || strings.TrimSpace(key) == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func LoginRateKeyFromRequest(r *http.Request, email string) string {
	ip := clientIP(r)
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedEmail == "" {
		return ip
	}
	return ip + "|" + normalizedEmail
}

func clientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			value := strings.TrimSpace(parts[0])
			if value != "" {
				return value
			}
		}
	}

	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" {
		return "unknown"
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func (l *LoginRateLimiter) gc(now time.Time) {
	if len(l.entries) < 2000 {
		return
	}
	cutoff := now.Add(-2 * l.window)
	for key, entry := range l.entries {
		if entry == nil {
			delete(l.entries, key)
			continue
		}
		if entry.LastSeenAt.Before(cutoff) && now.After(entry.BlockedUntil) {
			delete(l.entries, key)
		}
	}
}
