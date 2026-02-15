package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"sn-go-api/internal/billingstore"
	"sn-go-api/internal/config"

	stripe "github.com/stripe/stripe-go/v82"
	billingportalsession "github.com/stripe/stripe-go/v82/billingportal/session"
)

type customerPortalRequest struct {
	CustomerID     string `json:"customerId"`
	SubscriptionID string `json:"subscriptionId"`
	ReturnURL      string `json:"returnUrl"`
	Email          string `json:"email"`
}

func CustomerPortal(cfg config.Config, store *billingstore.OverviewStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível gerar o portal do cliente"})
			return
		}

		var body customerPortalRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Payload inválido."})
			return
		}

		stripeCustomerID, err := store.ResolveStripeCustomerID(body.CustomerID, body.SubscriptionID, body.Email)
		if err != nil {
			log.Printf("[customer-portal] erro ao resolver customerId: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível gerar o portal do cliente"})
			return
		}

		if strings.TrimSpace(stripeCustomerID) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "Informe stripeCustomerId, subscriptionId ou email para abrir o portal.",
			})
			return
		}

		if strings.TrimSpace(cfg.StripeSecretKey) == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível gerar o portal do cliente"})
			return
		}
		stripe.Key = cfg.StripeSecretKey

		returnURL := strings.TrimSpace(body.ReturnURL)
		if returnURL == "" {
			returnURL = strings.TrimSpace(cfg.CustomerPortalReturnURL)
		}

		params := &stripe.BillingPortalSessionParams{
			Customer:  stripe.String(strings.TrimSpace(stripeCustomerID)),
			ReturnURL: stripe.String(returnURL),
		}

		session, err := billingportalsession.New(params)
		if err != nil {
			log.Printf("[customer-portal] erro ao criar sessão do portal: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível gerar o portal do cliente"})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{"url": session.URL})
	}
}
