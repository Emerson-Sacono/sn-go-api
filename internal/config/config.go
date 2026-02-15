package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppName string
	AppEnv  string

	Port int

	AppBaseURL string
	APIBaseURL string

	CORSAllowedOrigins []string

	HTTPReadTimeout     time.Duration
	HTTPWriteTimeout    time.Duration
	HTTPIdleTimeout     time.Duration
	HTTPShutdownTimeout time.Duration

	MongoURI          string
	MongoURIAuth      string
	MongoURIBilling   string
	MongoURICustomers string
	MongoDBAuth       string
	MongoDBBilling    string
	MongoDBCustomers  string

	StripeSecretKey         string
	StripeWebhookSecret     string
	StripeDefaultCurrency   string
	StripePriceFoodtruck    string
	StripePriceVirtualMenu  string
	StripePriceBooking      string
	CheckoutSuccessURL      string
	CheckoutCancelURL       string
	CustomerPortalReturnURL string

	AdminAccessCookieName          string
	AdminRefreshCookieName         string
	AdminJWTAccessSecret           string
	AdminJWTRefreshSecret          string
	AdminJWTIssuer                 string
	AdminJWTAudience               string
	AdminJWTAccessTTLSec           int
	AdminJWTRefreshTTLSec          int
	AdminHasUsers                  bool
	AdminLoginRateLimitMaxAttempts int
	AdminLoginRateLimitWindowSec   int
	AdminLoginRateLimitBlockSec    int

	AdminCookieSecure   bool
	AdminCookieSameSite string
	AdminCookieDomain   string

	AdminPasswordMinLength       int
	EmailVerificationTTLMin      int
	EmailVerificationCooldownSec int
	PasswordResetTTLMin          int
	PasswordResetCooldownSec     int
	ConsoleBootstrapKey          string
	AdminVerifyEmailPath         string
	AdminResetPasswordPath       string
	ResendAPIKey                 string
	ResendFromEmail              string
	ResendConfigured             bool
}

func Load() (Config, error) {
	mongoURI := strings.TrimSpace(os.Getenv("MONGODB_URI"))
	mongoURIAuth := resolveMongoURI(strings.TrimSpace(os.Getenv("MONGODB_URI_AUTH")), mongoURI, envOrDefault("MONGODB_DB_AUTH", "snweb-go-auth"))
	mongoURIBilling := resolveMongoURI(strings.TrimSpace(os.Getenv("MONGODB_URI_BILLING")), mongoURI, envOrDefault("MONGODB_DB_BILLING", "snweb-go-billing"))
	mongoURICustomers := resolveMongoURI(strings.TrimSpace(os.Getenv("MONGODB_URI_CUSTOMERS")), mongoURI, envOrDefault("MONGODB_DB_CUSTOMERS", "snweb-go-customers"))
	defaultHasUsers := mongoURIAuth != ""

	cfg := Config{
		AppName:            envOrDefault("APP_NAME", "sn-go-api"),
		AppEnv:             envOrDefault("APP_ENV", "development"),
		Port:               envInt("PORT", 4010),
		AppBaseURL:         strings.TrimSpace(os.Getenv("APP_BASE_URL")),
		APIBaseURL:         strings.TrimSpace(os.Getenv("API_PUBLIC_BASE_URL")),
		CORSAllowedOrigins: envCSVOrDefault("CORS_ALLOWED_ORIGINS", defaultCORSOrigins()),
		HTTPReadTimeout:    envDurationSeconds("HTTP_READ_TIMEOUT_SEC", 10),
		HTTPWriteTimeout:   envDurationSeconds("HTTP_WRITE_TIMEOUT_SEC", 20),
		HTTPIdleTimeout:    envDurationSeconds("HTTP_IDLE_TIMEOUT_SEC", 60),
		HTTPShutdownTimeout: envDurationSeconds(
			"HTTP_SHUTDOWN_TIMEOUT_SEC",
			10,
		),
		MongoURI:          mongoURI,
		MongoURIAuth:      mongoURIAuth,
		MongoURIBilling:   mongoURIBilling,
		MongoURICustomers: mongoURICustomers,
		MongoDBAuth:       strings.TrimSpace(os.Getenv("MONGODB_DB_AUTH")),
		MongoDBBilling:    strings.TrimSpace(os.Getenv("MONGODB_DB_BILLING")),
		MongoDBCustomers:  strings.TrimSpace(os.Getenv("MONGODB_DB_CUSTOMERS")),

		StripeSecretKey:         strings.TrimSpace(os.Getenv("STRIPE_SECRET_KEY")),
		StripeWebhookSecret:     strings.TrimSpace(os.Getenv("STRIPE_WEBHOOK_SECRET")),
		StripeDefaultCurrency:   strings.ToLower(envOrDefault("STRIPE_DEFAULT_CURRENCY", "jpy")),
		StripePriceFoodtruck:    strings.TrimSpace(os.Getenv("STRIPE_PRICE_FOODTRUCK")),
		StripePriceVirtualMenu:  strings.TrimSpace(os.Getenv("STRIPE_PRICE_VIRTUAL_MENU")),
		StripePriceBooking:      strings.TrimSpace(os.Getenv("STRIPE_PRICE_BOOKING")),
		CheckoutSuccessURL:      envOrDefault("CHECKOUT_SUCCESS_URL", "https://snwebdevsolutions.com/sucesso.html"),
		CheckoutCancelURL:       envOrDefault("CHECKOUT_CANCEL_URL", "https://snwebdevsolutions.com/assinaturas.html"),
		CustomerPortalReturnURL: envOrDefault("CUSTOMER_PORTAL_RETURN_URL", "https://snwebdevsolutions.com/assinaturas.html"),

		AdminAccessCookieName:          envOrDefault("ADMIN_ACCESS_COOKIE_NAME", "__sn_console_at"),
		AdminRefreshCookieName:         envOrDefault("ADMIN_REFRESH_COOKIE_NAME", "__sn_console_rt"),
		AdminJWTAccessSecret:           strings.TrimSpace(os.Getenv("ADMIN_JWT_ACCESS_SECRET")),
		AdminJWTRefreshSecret:          strings.TrimSpace(os.Getenv("ADMIN_JWT_REFRESH_SECRET")),
		AdminJWTIssuer:                 envOrDefault("ADMIN_JWT_ISSUER", "sn-console"),
		AdminJWTAudience:               envOrDefault("ADMIN_JWT_AUDIENCE", "sn-console-admin"),
		AdminJWTAccessTTLSec:           envInt("ADMIN_JWT_ACCESS_TTL_SEC", 900),
		AdminJWTRefreshTTLSec:          envInt("ADMIN_JWT_REFRESH_TTL_SEC", 2592000),
		AdminHasUsers:                  envBool("ADMIN_HAS_USERS", defaultHasUsers),
		AdminLoginRateLimitMaxAttempts: envInt("ADMIN_LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5),
		AdminLoginRateLimitWindowSec:   envInt("ADMIN_LOGIN_RATE_LIMIT_WINDOW_SEC", 900),
		AdminLoginRateLimitBlockSec:    envInt("ADMIN_LOGIN_RATE_LIMIT_BLOCK_SEC", 900),
		AdminCookieSecure:              envBool("ADMIN_COOKIE_SECURE", cfgDefaultCookieSecure(envOrDefault("APP_ENV", "development"))),
		AdminCookieSameSite:            strings.ToLower(envOrDefault("ADMIN_COOKIE_SAMESITE", "lax")),
		AdminCookieDomain:              strings.TrimSpace(os.Getenv("ADMIN_COOKIE_DOMAIN")),
		AdminPasswordMinLength:         envInt("ADMIN_PASSWORD_MIN_LENGTH", 10),
		EmailVerificationTTLMin:        envInt("EMAIL_VERIFICATION_TTL_MIN", 1440),
		EmailVerificationCooldownSec:   envInt("EMAIL_VERIFICATION_COOLDOWN_SEC", 60),
		PasswordResetTTLMin:            envInt("PASSWORD_RESET_TTL_MIN", 60),
		PasswordResetCooldownSec:       envInt("PASSWORD_RESET_COOLDOWN_SEC", 60),
		ConsoleBootstrapKey:            strings.TrimSpace(os.Getenv("CONSOLE_BOOTSTRAP_KEY")),
		AdminVerifyEmailPath:           envOrDefault("ADMIN_VERIFY_EMAIL_PATH", "/acesso-painel.html"),
		AdminResetPasswordPath:         envOrDefault("ADMIN_RESET_PASSWORD_PATH", "/acesso-painel.html"),
		ResendAPIKey:                   strings.TrimSpace(os.Getenv("RESEND_API_KEY")),
		ResendFromEmail:                strings.TrimSpace(os.Getenv("RESEND_FROM_EMAIL")),
		ResendConfigured:               strings.TrimSpace(os.Getenv("RESEND_API_KEY")) != "" && strings.TrimSpace(os.Getenv("RESEND_FROM_EMAIL")) != "",
	}

	if cfg.Port <= 0 || cfg.Port > 65535 {
		return Config{}, fmt.Errorf("PORT inválida: %d", cfg.Port)
	}
	if cfg.AdminJWTAccessTTLSec < 60 {
		cfg.AdminJWTAccessTTLSec = 900
	}
	if cfg.AdminJWTRefreshTTLSec < cfg.AdminJWTAccessTTLSec {
		cfg.AdminJWTRefreshTTLSec = 2592000
	}
	if cfg.AdminLoginRateLimitMaxAttempts < 1 {
		cfg.AdminLoginRateLimitMaxAttempts = 5
	}
	if cfg.AdminLoginRateLimitWindowSec < 10 {
		cfg.AdminLoginRateLimitWindowSec = 900
	}
	if cfg.AdminLoginRateLimitBlockSec < 10 {
		cfg.AdminLoginRateLimitBlockSec = cfg.AdminLoginRateLimitWindowSec
	}
	if cfg.AdminCookieSameSite != "lax" && cfg.AdminCookieSameSite != "strict" && cfg.AdminCookieSameSite != "none" {
		cfg.AdminCookieSameSite = "lax"
	}

	if len(cfg.CORSAllowedOrigins) == 0 {
		return Config{}, errors.New("CORS_ALLOWED_ORIGINS vazio")
	}
	for _, origin := range cfg.CORSAllowedOrigins {
		if origin == "*" {
			return Config{}, errors.New("CORS_ALLOWED_ORIGINS não pode conter '*' com cookies/credentials")
		}
	}

	return cfg, nil
}

func resolveMongoURI(explicitURI, baseURI, dbName string) string {
	if explicitURI != "" {
		return explicitURI
	}
	if baseURI == "" {
		return ""
	}
	parsed, err := url.Parse(baseURI)
	if err != nil {
		return baseURI
	}
	name := strings.TrimSpace(dbName)
	if name == "" {
		name = "snweb-go-auth"
	}
	parsed.Path = "/" + name
	return parsed.String()
}

func cfgDefaultCookieSecure(appEnv string) bool {
	return strings.EqualFold(strings.TrimSpace(appEnv), "production")
}

func defaultCORSOrigins() []string {
	return []string{
		"https://snwebdevsolutions.com",
		"https://www.snwebdevsolutions.com",
		"http://localhost:5500",
		"http://127.0.0.1:5500",
	}
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDurationSeconds(key string, fallbackSeconds int) time.Duration {
	return time.Duration(envInt(key, fallbackSeconds)) * time.Second
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envCSVOrDefault(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return append([]string(nil), fallback...)
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
