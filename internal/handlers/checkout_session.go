package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"sn-go-api/internal/config"

	stripe "github.com/stripe/stripe-go/v82"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"
)

type createCheckoutSessionBody struct {
	Plan string `json:"plan"`
}

func CheckoutSession(cfg config.Config) http.HandlerFunc {
	priceMap := map[string]string{
		"foodtruck":    strings.TrimSpace(cfg.StripePriceFoodtruck),
		"virtual_menu": strings.TrimSpace(cfg.StripePriceVirtualMenu),
		"booking":      strings.TrimSpace(cfg.StripePriceBooking),
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var body createCheckoutSessionBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Payload inválido."})
			return
		}

		plan := strings.TrimSpace(body.Plan)
		priceID, ok := priceMap[plan]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Plano inválido"})
			return
		}
		if priceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Price ID não configurado para o plano: " + plan})
			return
		}

		if strings.TrimSpace(cfg.StripeSecretKey) == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "STRIPE_SECRET_KEY não configurado"})
			return
		}
		stripe.Key = cfg.StripeSecretKey

		params := &stripe.CheckoutSessionParams{
			Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
			LineItems: []*stripe.CheckoutSessionLineItemParams{
				{
					Price:    stripe.String(priceID),
					Quantity: stripe.Int64(1),
				},
			},
			ClientReferenceID: stripe.String(plan),
			Metadata: map[string]string{
				"plan": plan,
			},
			SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
				Metadata: map[string]string{
					"plan": plan,
				},
			},
			SuccessURL: stripe.String(withCheckoutSessionPlaceholder(cfg.CheckoutSuccessURL)),
			CancelURL:  stripe.String(cfg.CheckoutCancelURL),
		}

		session, err := checkoutsession.New(params)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Erro ao criar sessão de checkout"})
			return
		}
		if session == nil || strings.TrimSpace(session.URL) == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível gerar a URL de checkout"})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{"url": session.URL})
	}
}
