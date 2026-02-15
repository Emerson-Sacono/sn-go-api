package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"sn-go-api/internal/auth"
	"sn-go-api/internal/authstore"
	"sn-go-api/internal/config"
)

func requireAccessClaims(r *http.Request, cfg config.Config, store *authstore.MongoStore) (*auth.AccessClaims, error) {
	cookieName := strings.TrimSpace(cfg.AdminAccessCookieName)
	if cookieName == "" {
		cookieName = "__sn_console_at"
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, errors.New("missing access cookie")
	}

	claims, err := auth.ValidateAccessToken(
		cookie.Value,
		cfg.AdminJWTAccessSecret,
		cfg.AdminJWTIssuer,
		cfg.AdminJWTAudience,
		time.Now().UTC(),
	)
	if err != nil {
		return nil, err
	}

	if store != nil {
		session, err := store.FindActiveSessionByID(claims.SessionID, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if session == nil || session.UserID.Hex() != claims.Subject {
			return nil, errors.New("invalid session")
		}
	}

	return claims, nil
}
