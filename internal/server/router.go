package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"sn-go-api/internal/authservice"
	"sn-go-api/internal/authstore"
	"sn-go-api/internal/billingstore"
	"sn-go-api/internal/config"
	"sn-go-api/internal/handlers"
	"sn-go-api/internal/security"
)

func NewRouter(cfg config.Config) (http.Handler, error) {
	allowedOrigins := make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
	for _, origin := range cfg.CORSAllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		allowedOrigins[origin] = struct{}{}
	}
	if len(allowedOrigins) == 0 {
		return nil, fmt.Errorf("no valid CORS origins configured")
	}

	mux := http.NewServeMux()

	authStore, err := authstore.NewMongoStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("auth store error: %w", err)
	}
	authSvc := authservice.New(cfg, authStore)
	billingOverviewStore, err := billingstore.NewOverviewStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("billing overview store error: %w", err)
	}
	loginLimiter := security.NewLoginRateLimiter(
		cfg.AdminLoginRateLimitMaxAttempts,
		time.Duration(cfg.AdminLoginRateLimitWindowSec)*time.Second,
		time.Duration(cfg.AdminLoginRateLimitBlockSec)*time.Second,
	)

	health := handlers.Health(cfg.AppName)
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /api/health", health)

	mux.HandleFunc("POST /api/checkout/session", handlers.CheckoutSession(cfg))
	mux.HandleFunc("POST /api/stripe/webhook", handlers.StripeWebhook(cfg, billingOverviewStore))
	mux.HandleFunc("GET /api/console/auth/session", handlers.AuthSession(cfg, authSvc, authStore))
	mux.HandleFunc("POST /api/console/auth/login", handlers.AuthLogin(cfg, authStore, loginLimiter))
	mux.HandleFunc("POST /api/console/auth/logout", handlers.AuthLogout(cfg, authStore))
	mux.HandleFunc("POST /api/console/auth/bootstrap", handlers.AuthBootstrap(authSvc))
	mux.HandleFunc("GET /api/console/auth/verify-email", handlers.AuthVerifyEmailQuery(authSvc))
	mux.HandleFunc("POST /api/console/auth/verify-email", handlers.AuthVerifyEmail(authSvc))
	mux.HandleFunc("POST /api/console/auth/resend-verification", handlers.AuthResendVerification(authSvc))
	mux.HandleFunc("POST /api/console/auth/request-password-reset", handlers.AuthRequestPasswordReset(authSvc))
	mux.HandleFunc("POST /api/console/auth/reset-password", handlers.AuthResetPassword(cfg, authSvc))
	mux.HandleFunc("POST /api/console/auth/change-password", handlers.AuthChangePassword(cfg, authSvc, authStore))
	mux.HandleFunc("GET /api/console/billing/overview", handlers.BillingOverview(cfg, billingOverviewStore, authStore))
	mux.HandleFunc("POST /api/console/billing/links", handlers.BillingLinks(cfg, billingOverviewStore, authStore))
	mux.HandleFunc("POST /api/stripe/customer-portal", handlers.CustomerPortal(cfg, billingOverviewStore))

	handler := withRecovery(
		withCORS(allowedOrigins, mux),
	)
	return handler, nil
}
