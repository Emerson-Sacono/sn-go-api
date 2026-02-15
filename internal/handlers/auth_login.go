package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sn-go-api/internal/auth"
	"sn-go-api/internal/authstore"
	"sn-go-api/internal/config"
	"sn-go-api/internal/security"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func AuthLogin(cfg config.Config, store *authstore.MongoStore, limiter *security.LoginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		var body loginRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "Payload inválido.",
			})
			return
		}

		email := strings.ToLower(strings.TrimSpace(body.Email))
		password := body.Password
		if email == "" || password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "Informe e-mail e senha.",
			})
			return
		}

		rateKey := security.LoginRateKeyFromRequest(r, email)
		now := time.Now().UTC()
		if blocked, retryAfter := limiter.IsBlocked(rateKey, now); blocked {
			writeRetryAfterHeader(w, retryAfter)
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "Muitas tentativas de login. Tente novamente em instantes.",
			})
			return
		}

		if store == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "Autenticação indisponível no momento.",
			})
			return
		}

		adminIdentity, reason, err := store.VerifyCredentials(email, password)
		if reason == "email_not_verified" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                 "Seu e-mail ainda não foi verificado. Use reenviar verificação.",
				"code":                  "email_not_verified",
				"verificationEmailSent": false,
			})
			return
		}
		if reason == "invalid_credentials" {
			handleLoginFailureWithRateLimit(w, limiter, rateKey, now)
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível validar o login no banco agora.",
			})
			return
		}
		if adminIdentity == nil {
			handleLoginFailureWithRateLimit(w, limiter, rateKey, now)
			return
		}

		adminID := strings.TrimSpace(adminIdentity.ID)
		adminEmail := strings.ToLower(strings.TrimSpace(adminIdentity.Email))
		adminRole := strings.TrimSpace(adminIdentity.Role)
		if adminID == "" || adminEmail == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Resposta inválida do provedor de autenticação.",
			})
			return
		}
		if adminRole == "" {
			adminRole = "admin"
		}

		userObjectID, err := primitive.ObjectIDFromHex(adminID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "ID de usuário inválido para sessão.",
			})
			return
		}

		sessionID, err := authstore.RandomToken(32)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Falha ao criar sessão.",
			})
			return
		}

		accessExpiresAt := now.Add(time.Duration(cfg.AdminJWTAccessTTLSec) * time.Second)
		refreshExpiresAt := now.Add(time.Duration(cfg.AdminJWTRefreshTTLSec) * time.Second)

		accessToken, err := auth.SignAccessToken(
			cfg.AdminJWTAccessSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
			adminID,
			adminEmail,
			adminRole,
			sessionID,
			accessExpiresAt,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Falha ao criar token de acesso.",
			})
			return
		}

		refreshToken, err := auth.SignRefreshToken(
			cfg.AdminJWTRefreshSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
			adminID,
			sessionID,
			refreshExpiresAt,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Falha ao criar token de sessão.",
			})
			return
		}

		meta := readRequestMeta(r)
		if err := store.CreateSession(
			userObjectID,
			sessionID,
			authstore.HashToken(refreshToken),
			refreshExpiresAt,
			meta.UserAgent,
			meta.IPAddress,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Falha ao persistir sessão de login.",
			})
			return
		}

		setAuthCookies(w, cfg, accessToken, accessExpiresAt, refreshToken, refreshExpiresAt)
		limiter.Reset(rateKey)

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"authenticated": true,
			"admin": map[string]any{
				"id":    adminID,
				"email": adminEmail,
				"role":  adminRole,
			},
		})
	}
}

func AuthLogout(cfg config.Config, store *authstore.MongoStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		sessionID := ""
		now := time.Now().UTC()

		if accessToken := readCookieToken(r, cfg.AdminAccessCookieName, "__sn_console_at"); accessToken != "" {
			if claims, err := auth.ValidateAccessToken(
				accessToken,
				cfg.AdminJWTAccessSecret,
				cfg.AdminJWTIssuer,
				cfg.AdminJWTAudience,
				now,
			); err == nil {
				sessionID = claims.SessionID
			}
		}

		if sessionID == "" {
			if refreshToken := readCookieToken(r, cfg.AdminRefreshCookieName, "__sn_console_rt"); refreshToken != "" {
				if claims, err := auth.ValidateRefreshToken(
					refreshToken,
					cfg.AdminJWTRefreshSecret,
					cfg.AdminJWTIssuer,
					cfg.AdminJWTAudience,
					now,
				); err == nil {
					sessionID = claims.SessionID
				}
			}
		}

		if store != nil && strings.TrimSpace(sessionID) != "" {
			_ = store.RevokeSessionByID(sessionID, now)
		}

		clearAuthCookies(w, cfg)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
		})
	}
}

func setAuthCookies(
	w http.ResponseWriter,
	cfg config.Config,
	accessToken string,
	accessExpiresAt time.Time,
	refreshToken string,
	refreshExpiresAt time.Time,
) {
	setAuthAccessCookie(w, cfg, accessToken, accessExpiresAt)
	setAuthRefreshCookie(w, cfg, refreshToken, refreshExpiresAt)
}

func setAuthAccessCookie(w http.ResponseWriter, cfg config.Config, token string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     strings.TrimSpace(cfg.AdminAccessCookieName),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.AdminCookieSecure,
		SameSite: parseSameSiteMode(cfg.AdminCookieSameSite),
		MaxAge:   cfg.AdminJWTAccessTTLSec,
		Expires:  expiresAt.UTC(),
	}
	if cookie.Name == "" {
		cookie.Name = "__sn_console_at"
	}
	if cfg.AdminCookieDomain != "" {
		cookie.Domain = cfg.AdminCookieDomain
	}
	http.SetCookie(w, cookie)
}

func setAuthRefreshCookie(w http.ResponseWriter, cfg config.Config, token string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     strings.TrimSpace(cfg.AdminRefreshCookieName),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.AdminCookieSecure,
		SameSite: parseSameSiteMode(cfg.AdminCookieSameSite),
		MaxAge:   cfg.AdminJWTRefreshTTLSec,
		Expires:  expiresAt.UTC(),
	}
	if cookie.Name == "" {
		cookie.Name = "__sn_console_rt"
	}
	if cfg.AdminCookieDomain != "" {
		cookie.Domain = cfg.AdminCookieDomain
	}
	http.SetCookie(w, cookie)
}

func clearAuthCookies(w http.ResponseWriter, cfg config.Config) {
	clearAuthAccessCookie(w, cfg)
	clearAuthRefreshCookie(w, cfg)
}

func clearAuthAccessCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := &http.Cookie{
		Name:     strings.TrimSpace(cfg.AdminAccessCookieName),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.AdminCookieSecure,
		SameSite: parseSameSiteMode(cfg.AdminCookieSameSite),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
	if cookie.Name == "" {
		cookie.Name = "__sn_console_at"
	}
	if cfg.AdminCookieDomain != "" {
		cookie.Domain = cfg.AdminCookieDomain
	}
	http.SetCookie(w, cookie)
}

func clearAuthRefreshCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := &http.Cookie{
		Name:     strings.TrimSpace(cfg.AdminRefreshCookieName),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.AdminCookieSecure,
		SameSite: parseSameSiteMode(cfg.AdminCookieSameSite),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
	if cookie.Name == "" {
		cookie.Name = "__sn_console_rt"
	}
	if cfg.AdminCookieDomain != "" {
		cookie.Domain = cfg.AdminCookieDomain
	}
	http.SetCookie(w, cookie)
}

func parseSameSiteMode(v string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func readCookieToken(r *http.Request, configuredName, fallback string) string {
	cookieName := strings.TrimSpace(configuredName)
	if cookieName == "" {
		cookieName = fallback
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func handleLoginFailureWithRateLimit(w http.ResponseWriter, limiter *security.LoginRateLimiter, key string, now time.Time) {
	if blocked, retryAfter := limiter.RegisterFailure(key, now); blocked {
		writeRetryAfterHeader(w, retryAfter)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "Muitas tentativas de login. Tente novamente em instantes.",
		})
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error": "Credenciais inválidas.",
	})
}

func writeRetryAfterHeader(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
}
