package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"sn-go-api/internal/billingstore"
	"sn-go-api/internal/config"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

func StripeWebhook(cfg config.Config, store *billingstore.OverviewStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Webhook indisponível"})
			return
		}

		payload, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Body inválido"})
			return
		}

		var event stripe.Event
		webhookSecret := strings.TrimSpace(cfg.StripeWebhookSecret)
		if webhookSecret != "" {
			signature := strings.TrimSpace(r.Header.Get("Stripe-Signature"))
			if signature == "" {
				http.Error(w, "Missing Stripe-Signature header", http.StatusBadRequest)
				return
			}
			event, err = webhook.ConstructEventWithOptions(
				payload,
				signature,
				webhookSecret,
				webhook.ConstructEventOptions{
					// Stripe dashboard no modo "clover" pode ficar à frente da versão
					// esperada pela SDK. Mantemos assinatura validada e ignoramos só mismatch de versão.
					IgnoreAPIVersionMismatch: true,
				},
			)
			if err != nil {
				http.Error(w, "Webhook Error: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := json.Unmarshal(payload, &event); err != nil {
				http.Error(w, "Webhook Error: payload inválido", http.StatusBadRequest)
				return
			}
		}

		switch event.Type {
		case "checkout.session.completed":
			if err := store.UpsertSubscriptionFromCheckoutSession(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em checkout.session.completed subscription: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			if err := store.UpsertBillingFromCheckoutSession(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em checkout.session.completed billing: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}

		case "checkout.session.expired":
			if err := store.MarkBillingCheckoutExpired(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em checkout.session.expired: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}

		case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
			if err := store.UpsertSubscriptionFromSubscription(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em %s subscription: %v", event.Type, err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			if err := store.UpdateBillingFromSubscription(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em %s billing: %v", event.Type, err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}

		case "invoice.payment_succeeded", "invoice.payment_failed":
			if err := store.UpdateSubscriptionFromInvoice(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em %s subscription: %v", event.Type, err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			if err := store.UpdateBillingFromInvoice(event.Data.Raw); err != nil {
				log.Printf("[stripe-webhook] erro em %s billing: %v", event.Type, err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{"received": true})
	}
}
