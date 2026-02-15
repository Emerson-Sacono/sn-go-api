package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ResendSender struct {
	APIKey     string
	FromEmail  string
	HTTPClient *http.Client
}

func (s *ResendSender) SendEmail(toEmail, subject, html string) error {
	apiKey := strings.TrimSpace(s.APIKey)
	from := strings.TrimSpace(s.FromEmail)
	to := strings.TrimSpace(toEmail)
	if apiKey == "" || from == "" {
		return fmt.Errorf("resend não configurado")
	}
	if to == "" {
		return fmt.Errorf("destinatário inválido")
	}

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	payload := map[string]any{
		"from":    from,
		"to":      []string{to},
		"subject": subject,
		"html":    html,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("falha ao enviar e-mail via Resend: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
}
