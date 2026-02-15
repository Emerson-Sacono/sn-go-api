package handlers

import (
	"net/http"
	"strings"
	"time"

	"sn-go-api/internal/auth"
	"sn-go-api/internal/authservice"
	"sn-go-api/internal/authstore"
	"sn-go-api/internal/config"
)

func AuthSession(cfg config.Config, authSvc *authservice.Service, store *authstore.MongoStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		security := map[string]any{
			"passwordMinLength":        cfg.AdminPasswordMinLength,
			"verificationTtlMin":       cfg.EmailVerificationTTLMin,
			"verificationCooldownSec":  cfg.EmailVerificationCooldownSec,
			"resetPasswordTtlMin":      cfg.PasswordResetTTLMin,
			"resetPasswordCooldownSec": cfg.PasswordResetCooldownSec,
			"resendConfigured":         cfg.ResendConfigured,
		}
		if authSvc != nil {
			security = authSvc.SecurityConfig()
		}

		hasUsers := cfg.AdminHasUsers
		if authSvc != nil {
			if value, err := authSvc.HasAnyUsers(); err == nil {
				hasUsers = value
			}
		}

		unauthorized := map[string]any{
			"authenticated": false,
			"hasUsers":      hasUsers,
			"security":      security,
		}

		if store == nil {
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		now := time.Now().UTC()
		meta := readRequestMeta(r)

		accessToken := readCookieToken(r, cfg.AdminAccessCookieName, "__sn_console_at")
		if accessToken != "" {
			if claims, err := auth.ValidateAccessToken(
				accessToken,
				cfg.AdminJWTAccessSecret,
				cfg.AdminJWTIssuer,
				cfg.AdminJWTAudience,
				now,
			); err == nil {
				if authPayload := resolveAuthenticatedPayloadFromAccessClaims(claims, store, meta.UserAgent, meta.IPAddress, now); authPayload != nil {
					authPayload["hasUsers"] = hasUsers
					authPayload["security"] = security
					writeJSON(w, http.StatusOK, authPayload)
					return
				}
			}
		}

		refreshToken := readCookieToken(r, cfg.AdminRefreshCookieName, "__sn_console_rt")
		if refreshToken == "" {
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		refreshClaims, err := auth.ValidateRefreshToken(
			refreshToken,
			cfg.AdminJWTRefreshSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
			now,
		)
		if err != nil {
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		session, err := store.FindActiveSessionByID(refreshClaims.SessionID, now)
		if err != nil || session == nil {
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		if session.UserID.Hex() != refreshClaims.Subject || session.RefreshTokenHash != authstore.HashToken(refreshToken) {
			_ = store.RevokeSessionByID(refreshClaims.SessionID, now)
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		user, err := store.FindUserByIDHex(refreshClaims.Subject)
		if err != nil || user == nil || !user.IsActive || !user.IsEmailVerified {
			_ = store.RevokeSessionByID(refreshClaims.SessionID, now)
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		accessExpiresAt := now.Add(time.Duration(cfg.AdminJWTAccessTTLSec) * time.Second)
		refreshExpiresAt := now.Add(time.Duration(cfg.AdminJWTRefreshTTLSec) * time.Second)
		role := strings.TrimSpace(user.Role)
		if role == "" {
			role = "admin"
		}

		newAccessToken, err := auth.SignAccessToken(
			cfg.AdminJWTAccessSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
			user.ID.Hex(),
			user.Email,
			role,
			refreshClaims.SessionID,
			accessExpiresAt,
		)
		if err != nil {
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		newRefreshToken, err := auth.SignRefreshToken(
			cfg.AdminJWTRefreshSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
			user.ID.Hex(),
			refreshClaims.SessionID,
			refreshExpiresAt,
		)
		if err != nil {
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		if err := store.RotateSessionRefreshToken(
			refreshClaims.SessionID,
			authstore.HashToken(newRefreshToken),
			refreshExpiresAt,
			meta.UserAgent,
			meta.IPAddress,
			now,
		); err != nil {
			clearAuthCookies(w, cfg)
			writeJSON(w, http.StatusOK, unauthorized)
			return
		}

		setAuthCookies(w, cfg, newAccessToken, accessExpiresAt, newRefreshToken, refreshExpiresAt)
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"hasUsers":      hasUsers,
			"security":      security,
			"admin": map[string]any{
				"id":        user.ID.Hex(),
				"email":     user.Email,
				"role":      role,
				"expiresAt": accessExpiresAt.UTC().Format(time.RFC3339),
			},
		})
	}
}

func resolveAuthenticatedPayloadFromAccessClaims(
	claims *auth.AccessClaims,
	store *authstore.MongoStore,
	userAgent string,
	ipAddress string,
	now time.Time,
) map[string]any {
	if claims == nil || store == nil {
		return nil
	}

	session, err := store.FindActiveSessionByID(claims.SessionID, now)
	if err != nil || session == nil {
		return nil
	}
	if session.UserID.Hex() != claims.Subject {
		_ = store.RevokeSessionByID(claims.SessionID, now)
		return nil
	}

	user, err := store.FindUserByIDHex(claims.Subject)
	if err != nil || user == nil || !user.IsActive || !user.IsEmailVerified {
		_ = store.RevokeSessionByID(claims.SessionID, now)
		return nil
	}

	_ = store.TouchSession(claims.SessionID, now, userAgent, ipAddress)
	role := strings.TrimSpace(user.Role)
	if role == "" {
		role = "admin"
	}

	return map[string]any{
		"authenticated": true,
		"admin": map[string]any{
			"id":        user.ID.Hex(),
			"email":     user.Email,
			"role":      role,
			"expiresAt": claims.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}
}
