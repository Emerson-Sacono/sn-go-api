package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"sn-go-api/internal/authservice"
	"sn-go-api/internal/authstore"
	"sn-go-api/internal/config"
)

type bootstrapRequest struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	BootstrapKey string `json:"bootstrapKey"`
}

type tokenRequest struct {
	Token string `json:"token"`
}

type emailRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func AuthBootstrap(authSvc *authservice.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if authSvc == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Serviço de autenticação indisponível."})
			return
		}

		var body bootstrapRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Payload inválido."})
			return
		}

		email := strings.TrimSpace(body.Email)
		password := body.Password
		if email == "" || password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Informe e-mail e senha para criar o primeiro usuário."})
			return
		}

		result, err := authSvc.BootstrapFirstAdmin(body.Name, email, password, body.BootstrapKey, readRequestMeta(r))
		if err != nil {
			message := err.Error()
			status := http.StatusBadRequest
			if strings.Contains(message, "Bootstrap já concluído") {
				status = http.StatusConflict
			}
			if strings.Contains(message, "Chave de bootstrap") {
				status = http.StatusForbidden
			}
			writeJSON(w, status, map[string]any{"error": message})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":                        true,
			"authenticated":             false,
			"requiresEmailVerification": result.RequiresEmailVerification,
			"verificationEmailSent":     result.VerificationEmailSent,
			"verificationError":         result.VerificationError,
			"admin":                     result.User,
		})
	}
}

func AuthVerifyEmail(authSvc *authservice.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authSvc == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Serviço de autenticação indisponível."})
			return
		}

		var body tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Token de verificação não informado."})
			return
		}

		token := strings.TrimSpace(body.Token)
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Token de verificação não informado."})
			return
		}

		email, err := authSvc.VerifyEmailToken(token)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": email})
	}
}

func AuthVerifyEmailQuery(authSvc *authservice.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authSvc == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Serviço de autenticação indisponível."})
			return
		}

		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("verify_token"))
		}
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Token de verificação não informado."})
			return
		}

		email, err := authSvc.VerifyEmailToken(token)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": email})
	}
}

func AuthResendVerification(authSvc *authservice.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authSvc != nil {
			var body emailRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.TrimSpace(body.Email) != "" {
				authSvc.ResendVerification(body.Email, readRequestMeta(r))
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "Se existir um usuário pendente para este e-mail, enviaremos um novo link de verificação.",
		})
	}
}

func AuthRequestPasswordReset(authSvc *authservice.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authSvc != nil {
			var body emailRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.TrimSpace(body.Email) != "" {
				authSvc.RequestPasswordReset(body.Email, readRequestMeta(r))
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "Se este e-mail estiver cadastrado, enviaremos um link para redefinir a senha.",
		})
	}
}

func AuthResetPassword(cfg config.Config, authSvc *authservice.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authSvc == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Serviço de autenticação indisponível."})
			return
		}

		var body resetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Informe o token e a nova senha."})
			return
		}

		token := strings.TrimSpace(body.Token)
		password := body.Password
		if token == "" || password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Informe o token e a nova senha."})
			return
		}

		email, err := authSvc.ResetPassword(token, password)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		clearAuthCookies(w, cfg)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"email":   email,
			"message": "Senha redefinida com sucesso. Faça login novamente.",
		})
	}
}

func AuthChangePassword(cfg config.Config, authSvc *authservice.Service, authStore *authstore.MongoStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authSvc == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Serviço de autenticação indisponível."})
			return
		}

		claims, err := requireAccessClaims(r, cfg, authStore)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Não autenticado"})
			return
		}

		var body changePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Informe a senha atual e a nova senha."})
			return
		}

		currentPassword := body.CurrentPassword
		newPassword := body.NewPassword
		if currentPassword == "" || newPassword == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Informe a senha atual e a nova senha."})
			return
		}

		if err := authSvc.ChangePassword(claims.Subject, currentPassword, newPassword); err != nil {
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "Senha atual inválida") || strings.Contains(err.Error(), "Sessão inválida") {
				status = http.StatusUnauthorized
			}
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "Senha alterada com sucesso.",
		})
	}
}

func readRequestMeta(r *http.Request) authservice.SessionMeta {
	userAgent := strings.TrimSpace(r.Header.Get("User-Agent"))

	ipAddress := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if ipAddress != "" {
		if parts := strings.Split(ipAddress, ","); len(parts) > 0 {
			ipAddress = strings.TrimSpace(parts[0])
		}
	}
	if ipAddress == "" {
		ipAddress = strings.TrimSpace(r.RemoteAddr)
	}

	return authservice.SessionMeta{
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}
}
