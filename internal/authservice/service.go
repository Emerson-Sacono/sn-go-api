package authservice

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"sn-go-api/internal/authstore"
	"sn-go-api/internal/config"
	"sn-go-api/internal/notify"
)

type SessionMeta struct {
	UserAgent string
	IPAddress string
}

type SanitizedAdmin struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	Name            any    `json:"name"`
	Role            string `json:"role"`
	IsEmailVerified bool   `json:"isEmailVerified"`
	EmailVerifiedAt any    `json:"emailVerifiedAt"`
}

type BootstrapResult struct {
	User                      SanitizedAdmin `json:"admin"`
	RequiresEmailVerification bool           `json:"requiresEmailVerification"`
	VerificationEmailSent     bool           `json:"verificationEmailSent"`
	VerificationError         any            `json:"verificationError"`
}

type Service struct {
	cfg    config.Config
	store  *authstore.MongoStore
	sender *notify.ResendSender
}

func New(cfg config.Config, store *authstore.MongoStore) *Service {
	return &Service{
		cfg:   cfg,
		store: store,
		sender: &notify.ResendSender{
			APIKey:    cfg.ResendAPIKey,
			FromEmail: cfg.ResendFromEmail,
		},
	}
}

func (s *Service) HasAnyUsers() (bool, error) {
	if s.store == nil {
		return false, nil
	}
	return s.store.HasAnyUsers()
}

func (s *Service) SecurityConfig() map[string]any {
	return map[string]any{
		"passwordMinLength":        s.cfg.AdminPasswordMinLength,
		"verificationTtlMin":       s.cfg.EmailVerificationTTLMin,
		"verificationCooldownSec":  s.cfg.EmailVerificationCooldownSec,
		"resetPasswordTtlMin":      s.cfg.PasswordResetTTLMin,
		"resetPasswordCooldownSec": s.cfg.PasswordResetCooldownSec,
		"resendConfigured":         s.cfg.ResendConfigured,
	}
}

func (s *Service) BootstrapFirstAdmin(name, email, password, bootstrapKey string, meta SessionMeta) (*BootstrapResult, error) {
	if s.store == nil {
		return nil, fmt.Errorf("auth store indisponível")
	}

	hasUsers, err := s.store.HasAnyUsers()
	if err != nil {
		return nil, err
	}
	if hasUsers {
		return nil, fmt.Errorf("Bootstrap já concluído. Use o painel para criar novos usuários.")
	}

	cfgBootstrap := strings.TrimSpace(s.cfg.ConsoleBootstrapKey)
	if cfgBootstrap != "" && bootstrapKey != cfgBootstrap {
		return nil, fmt.Errorf("Chave de bootstrap inválida.")
	}

	normalizedEmail := authstore.NormalizeEmail(email)
	if !isValidEmail(normalizedEmail) {
		return nil, fmt.Errorf("E-mail inválido.")
	}

	if err := assertStrongPassword(password, s.cfg.AdminPasswordMinLength); err != nil {
		return nil, err
	}

	existing, err := s.store.FindUserByEmail(normalizedEmail)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("Já existe um usuário com esse e-mail.")
	}

	passwordHash, err := authstore.HashPasswordArgon2ID(password)
	if err != nil {
		return nil, err
	}

	user, err := s.store.CreateUser(name, normalizedEmail, passwordHash, "owner", false)
	if err != nil {
		return nil, err
	}

	result := &BootstrapResult{
		User:                      sanitizeUser(user),
		RequiresEmailVerification: true,
		VerificationEmailSent:     false,
		VerificationError:         nil,
	}

	if err := s.issueVerificationEmail(user, meta); err != nil {
		result.VerificationError = err.Error()
	} else {
		result.VerificationEmailSent = true
	}
	return result, nil
}

func (s *Service) VerifyEmailToken(rawToken string) (string, error) {
	if s.store == nil {
		return "", fmt.Errorf("auth store indisponível")
	}

	token := strings.TrimSpace(rawToken)
	if len(token) < 20 {
		return "", fmt.Errorf("Token inválido.")
	}

	tokenHash := authstore.HashToken(token)
	tokenDoc, err := s.store.FindActiveVerificationTokenByHash(tokenHash, time.Now().UTC())
	if err != nil {
		return "", err
	}
	if tokenDoc == nil {
		return "", fmt.Errorf("Token inválido ou expirado.")
	}

	user, err := s.store.FindUserByIDHex(tokenDoc.UserID.Hex())
	if err != nil {
		return "", err
	}
	if user == nil || !user.IsActive {
		_ = s.store.ConsumeVerificationTokenByHash(tokenHash, time.Now().UTC())
		return "", fmt.Errorf("Usuário não encontrado ou inativo.")
	}

	now := time.Now().UTC()
	if err := s.store.MarkUserEmailVerified(user.ID); err != nil {
		return "", err
	}
	_ = s.store.ConsumeAllVerificationTokensByUser(user.ID, now)
	return user.Email, nil
}

func (s *Service) ResendVerification(email string, meta SessionMeta) {
	normalized := authstore.NormalizeEmail(email)
	if !isValidEmail(normalized) || s.store == nil {
		return
	}

	user, err := s.store.FindUserByEmail(normalized)
	if err != nil || user == nil {
		return
	}
	if !user.IsActive || user.IsEmailVerified {
		return
	}

	_ = s.issueVerificationEmail(user, meta)
}

func (s *Service) RequestPasswordReset(email string, meta SessionMeta) {
	normalized := authstore.NormalizeEmail(email)
	if !isValidEmail(normalized) || s.store == nil {
		return
	}

	user, err := s.store.FindUserByEmail(normalized)
	if err != nil || user == nil {
		return
	}
	if !user.IsActive || !user.IsEmailVerified {
		return
	}

	_ = s.issuePasswordResetEmail(user, meta)
}

func (s *Service) ResetPassword(rawToken, newPassword string) (string, error) {
	if s.store == nil {
		return "", fmt.Errorf("auth store indisponível")
	}

	token := strings.TrimSpace(rawToken)
	if len(token) < 20 {
		return "", fmt.Errorf("Token inválido.")
	}
	if err := assertStrongPassword(newPassword, s.cfg.AdminPasswordMinLength); err != nil {
		return "", err
	}

	tokenHash := authstore.HashToken(token)
	tokenDoc, err := s.store.FindActiveResetTokenByHash(tokenHash, time.Now().UTC())
	if err != nil {
		return "", err
	}
	if tokenDoc == nil {
		return "", fmt.Errorf("Token inválido ou expirado.")
	}

	user, err := s.store.FindUserByIDHex(tokenDoc.UserID.Hex())
	if err != nil {
		return "", err
	}
	if user == nil || !user.IsActive {
		_ = s.store.ConsumeResetTokenByHash(tokenHash, time.Now().UTC())
		return "", fmt.Errorf("Usuário não encontrado ou inativo.")
	}

	samePassword, err := authstore.VerifyPasswordHash(user.PasswordHash, newPassword)
	if err == nil && samePassword {
		return "", fmt.Errorf("A nova senha deve ser diferente da senha atual.")
	}

	newHash, err := authstore.HashPasswordArgon2ID(newPassword)
	if err != nil {
		return "", err
	}
	if err := s.store.SetUserPasswordHash(user.ID, newHash); err != nil {
		return "", err
	}
	_ = s.store.ConsumeAllResetTokensByUser(user.ID, time.Now().UTC())
	return user.Email, nil
}

func (s *Service) ChangePassword(userIDHex, currentPassword, newPassword string) error {
	if s.store == nil {
		return fmt.Errorf("auth store indisponível")
	}
	if err := assertStrongPassword(newPassword, s.cfg.AdminPasswordMinLength); err != nil {
		return err
	}

	user, err := s.store.FindUserByIDHex(userIDHex)
	if err != nil {
		return err
	}
	if user == nil || !user.IsActive || !user.IsEmailVerified {
		return fmt.Errorf("Sessão inválida.")
	}

	currentOK, err := authstore.VerifyPasswordHash(user.PasswordHash, currentPassword)
	if err != nil || !currentOK {
		return fmt.Errorf("Senha atual inválida.")
	}

	same, err := authstore.VerifyPasswordHash(user.PasswordHash, newPassword)
	if err == nil && same {
		return fmt.Errorf("A nova senha deve ser diferente da senha atual.")
	}

	newHash, err := authstore.HashPasswordArgon2ID(newPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetUserPasswordHash(user.ID, newHash); err != nil {
		return err
	}
	_ = s.store.ConsumeAllResetTokensByUser(user.ID, time.Now().UTC())
	return nil
}

func (s *Service) issueVerificationEmail(user *authstore.AdminUserRecord, meta SessionMeta) error {
	if user == nil {
		return fmt.Errorf("usuário inválido")
	}
	if user.IsEmailVerified {
		return nil
	}

	now := time.Now().UTC()
	cooldownFloor := now.Add(-time.Duration(s.cfg.EmailVerificationCooldownSec) * time.Second)
	recent, err := s.store.FindRecentUnconsumedVerificationToken(user.ID, cooldownFloor, now)
	if err != nil {
		return err
	}
	if recent != nil {
		return fmt.Errorf("Aguarde %ds para reenviar outro e-mail de verificação.", s.cfg.EmailVerificationCooldownSec)
	}

	if err := s.store.ConsumeAllVerificationTokensByUser(user.ID, now); err != nil {
		return err
	}

	rawToken, err := authstore.RandomToken(32)
	if err != nil {
		return err
	}
	tokenHash := authstore.HashToken(rawToken)
	expiresAt := now.Add(time.Duration(s.cfg.EmailVerificationTTLMin) * time.Minute)

	if err := s.store.InsertVerificationToken(user.ID, tokenHash, expiresAt, user.Email, meta.UserAgent, meta.IPAddress); err != nil {
		return err
	}

	verifyURL, err := s.buildFrontendURL(s.cfg.AdminVerifyEmailPath, "verify_token", rawToken)
	if err != nil {
		_ = s.store.ConsumeVerificationTokenByHash(tokenHash, time.Now().UTC())
		return err
	}

	html := fmt.Sprintf(`
<div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827;">
  <h2 style="margin-bottom:8px;">Confirme seu e-mail</h2>
  <p>Olá%s.</p>
  <p>Use o link abaixo para ativar seu acesso ao painel administrativo:</p>
  <p><a href="%s" target="_blank" rel="noopener noreferrer">Confirmar e-mail</a></p>
  <p>Este link expira em %d minutos.</p>
  <p>Se você não solicitou este acesso, ignore este e-mail.</p>
</div>`, optionalNameSuffix(user.Name), verifyURL, s.cfg.EmailVerificationTTLMin)

	if err := s.sender.SendEmail(user.Email, "Verifique seu acesso ao painel S&N", html); err != nil {
		_ = s.store.ConsumeVerificationTokenByHash(tokenHash, time.Now().UTC())
		return err
	}

	return nil
}

func (s *Service) issuePasswordResetEmail(user *authstore.AdminUserRecord, meta SessionMeta) error {
	if user == nil {
		return fmt.Errorf("usuário inválido")
	}

	now := time.Now().UTC()
	cooldownFloor := now.Add(-time.Duration(s.cfg.PasswordResetCooldownSec) * time.Second)
	recent, err := s.store.FindRecentUnconsumedResetToken(user.ID, cooldownFloor, now)
	if err != nil {
		return err
	}
	if recent != nil {
		return fmt.Errorf("Aguarde %ds para reenviar outra redefinição de senha.", s.cfg.PasswordResetCooldownSec)
	}

	if err := s.store.ConsumeAllResetTokensByUser(user.ID, now); err != nil {
		return err
	}

	rawToken, err := authstore.RandomToken(32)
	if err != nil {
		return err
	}
	tokenHash := authstore.HashToken(rawToken)
	expiresAt := now.Add(time.Duration(s.cfg.PasswordResetTTLMin) * time.Minute)

	if err := s.store.InsertResetToken(user.ID, tokenHash, expiresAt, user.Email, meta.UserAgent, meta.IPAddress); err != nil {
		return err
	}

	resetURL, err := s.buildFrontendURL(s.cfg.AdminResetPasswordPath, "reset_token", rawToken)
	if err != nil {
		_ = s.store.ConsumeResetTokenByHash(tokenHash, time.Now().UTC())
		return err
	}

	html := fmt.Sprintf(`
<div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827;">
  <h2 style="margin-bottom:8px;">Redefinição de senha</h2>
  <p>Olá%s.</p>
  <p>Recebemos um pedido para redefinir sua senha de acesso ao painel.</p>
  <p><a href="%s" target="_blank" rel="noopener noreferrer">Criar nova senha</a></p>
  <p>Este link expira em %d minutos.</p>
  <p>Se você não solicitou, ignore este e-mail.</p>
</div>`, optionalNameSuffix(user.Name), resetURL, s.cfg.PasswordResetTTLMin)

	if err := s.sender.SendEmail(user.Email, "Redefina sua senha do painel S&N", html); err != nil {
		_ = s.store.ConsumeResetTokenByHash(tokenHash, time.Now().UTC())
		return err
	}

	return nil
}

func (s *Service) buildFrontendURL(path, queryKey, token string) (string, error) {
	base := strings.TrimSpace(s.cfg.AppBaseURL)
	if base == "" {
		base = strings.TrimSpace(s.cfg.APIBaseURL)
	}
	if base == "" {
		return "", fmt.Errorf("APP_BASE_URL ou API_PUBLIC_BASE_URL não configurado para gerar links de autenticação")
	}

	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		normalizedPath = "/acesso-painel.html"
	}
	if !strings.HasPrefix(normalizedPath, "/") {
		normalizedPath = "/" + normalizedPath
	}

	u.Path = strings.TrimRight(u.Path, "/") + normalizedPath
	q := u.Query()
	q.Set(queryKey, token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func sanitizeUser(user *authstore.AdminUserRecord) SanitizedAdmin {
	if user == nil {
		return SanitizedAdmin{}
	}
	return SanitizedAdmin{
		ID:              user.ID.Hex(),
		Email:           authstore.NormalizeEmail(user.Email),
		Name:            nullIfEmpty(user.Name),
		Role:            user.Role,
		IsEmailVerified: user.IsEmailVerified,
		EmailVerifiedAt: isoOrNil(user.EmailVerifiedAt),
	}
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	return re.MatchString(strings.TrimSpace(email))
}

func assertStrongPassword(password string, minLen int) error {
	if minLen < 8 {
		minLen = 8
	}
	if len(password) < minLen {
		return fmt.Errorf("Senha fraca. Use pelo menos %d caracteres com maiúsculas, minúsculas, número e símbolo.", minLen)
	}
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`\d`).MatchString(password)
	hasSymbol := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)

	if !hasUpper || !hasLower || !hasNumber || !hasSymbol {
		return fmt.Errorf("Senha fraca. Use pelo menos %d caracteres com maiúsculas, minúsculas, número e símbolo.", minLen)
	}
	return nil
}

func optionalNameSuffix(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	return ", " + trimmed
}

func isoOrNil(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.TrimSpace(v)
}
