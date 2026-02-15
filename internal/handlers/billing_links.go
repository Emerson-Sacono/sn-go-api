package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sn-go-api/internal/authstore"
	"sn-go-api/internal/billingstore"
	"sn-go-api/internal/config"

	stripe "github.com/stripe/stripe-go/v82"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"
)

type createBillingLinkBody struct {
	Type          string            `json:"type"`
	Amount        json.RawMessage   `json:"amount"`
	Currency      string            `json:"currency"`
	Description   string            `json:"description"`
	CustomerEmail string            `json:"customerEmail"`
	CustomerName  string            `json:"customerName"`
	Stage         string            `json:"stage"`
	Interval      string            `json:"interval"`
	IntervalCount int64             `json:"intervalCount"`
	SuccessURL    string            `json:"successUrl"`
	CancelURL     string            `json:"cancelUrl"`
	Metadata      map[string]string `json:"metadata"`
}

var zeroDecimalCurrencies = map[string]struct{}{
	"bif": {}, "clp": {}, "djf": {}, "gnf": {}, "jpy": {}, "kmf": {}, "krw": {}, "mga": {},
	"pyg": {}, "rwf": {}, "ugx": {}, "vnd": {}, "vuv": {}, "xaf": {}, "xof": {}, "xpf": {},
}

func BillingLinks(cfg config.Config, store *billingstore.OverviewStore, authStore *authstore.MongoStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := requireAccessClaims(r, cfg, authStore); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Não autenticado"})
			return
		}
		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Serviço de billing indisponível."})
			return
		}

		var body createBillingLinkBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Payload inválido."})
			return
		}

		typ := strings.TrimSpace(body.Type)
		if typ != "one_time" && typ != "recurring" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Tipo inválido. Use one_time ou recurring."})
			return
		}

		description := strings.TrimSpace(body.Description)
		if description == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Descrição é obrigatória."})
			return
		}

		currency := strings.ToLower(strings.TrimSpace(body.Currency))
		if currency == "" {
			currency = strings.ToLower(strings.TrimSpace(cfg.StripeDefaultCurrency))
			if currency == "" {
				currency = "jpy"
			}
		}

		customerEmail := strings.ToLower(strings.TrimSpace(body.CustomerEmail))
		if customerEmail != "" && !isValidSimpleEmail(customerEmail) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "E-mail do cliente inválido."})
			return
		}

		amountMinor, err := toMinorUnits(body.Amount, currency)
		if err != nil || amountMinor <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Valor inválido."})
			return
		}

		interval := strings.TrimSpace(body.Interval)
		intervalCount := body.IntervalCount
		if intervalCount <= 0 {
			intervalCount = 1
		}
		if typ == "recurring" && interval == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Intervalo é obrigatório para cobrança recorrente."})
			return
		}

		successURL := strings.TrimSpace(body.SuccessURL)
		if successURL == "" {
			successURL = strings.TrimSpace(cfg.CheckoutSuccessURL)
		}
		cancelURL := strings.TrimSpace(body.CancelURL)
		if cancelURL == "" {
			cancelURL = strings.TrimSpace(cfg.CheckoutCancelURL)
		}

		metadata := sanitizeMetadata(body.Metadata)

		recordID, err := store.CreateBillingRecord(billingstore.CreateBillingRecordInput{
			Type:          typ,
			Stage:         strings.TrimSpace(body.Stage),
			Description:   description,
			CustomerEmail: customerEmail,
			CustomerName:  strings.TrimSpace(body.CustomerName),
			AmountMinor:   amountMinor,
			Currency:      currency,
			Interval:      interval,
			IntervalCount: intervalCount,
			Metadata:      metadata,
		})
		if err != nil {
			log.Printf("[billing-links] erro ao criar billing record: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível criar o link de pagamento."})
			return
		}

		stripeMeta := map[string]string{
			"billingRecordId": recordID,
			"billingType":     typ,
			"description":     description,
		}
		if stage := strings.TrimSpace(body.Stage); stage != "" {
			stripeMeta["stage"] = stage
		}
		if customerEmail != "" {
			stripeMeta["customerEmail"] = customerEmail
		}
		if customerName := strings.TrimSpace(body.CustomerName); customerName != "" {
			stripeMeta["customerName"] = customerName
		}
		for key, value := range metadata {
			stripeMeta[key] = value
		}

		if strings.TrimSpace(cfg.StripeSecretKey) == "" {
			_ = store.MarkBillingRecordFailed(recordID, "STRIPE_SECRET_KEY não configurado")
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível criar o link de pagamento."})
			return
		}
		stripe.Key = cfg.StripeSecretKey

		lineItem := &stripe.CheckoutSessionLineItemParams{
			Quantity: stripe.Int64(1),
			PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
				Currency:   stripe.String(currency),
				UnitAmount: stripe.Int64(amountMinor),
				ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
					Name: stripe.String(description),
				},
			},
		}

		if typ == "recurring" {
			lineItem.PriceData.Recurring = &stripe.CheckoutSessionLineItemPriceDataRecurringParams{
				Interval:      stripe.String(interval),
				IntervalCount: stripe.Int64(intervalCount),
			}
		}

		params := &stripe.CheckoutSessionParams{
			LineItems:         []*stripe.CheckoutSessionLineItemParams{lineItem},
			ClientReferenceID: stripe.String(recordID),
			Metadata:          stripeMeta,
			SuccessURL:        stripe.String(withCheckoutSessionPlaceholder(successURL)),
			CancelURL:         stripe.String(cancelURL),
		}

		if customerEmail != "" {
			params.CustomerEmail = stripe.String(customerEmail)
		}

		if typ == "recurring" {
			params.Mode = stripe.String(string(stripe.CheckoutSessionModeSubscription))
			params.SubscriptionData = &stripe.CheckoutSessionSubscriptionDataParams{
				Metadata: stripeMeta,
			}
		} else {
			params.Mode = stripe.String(string(stripe.CheckoutSessionModePayment))
			params.PaymentIntentData = &stripe.CheckoutSessionPaymentIntentDataParams{
				Metadata: stripeMeta,
			}
		}

		session, err := checkoutsession.New(params)
		if err != nil {
			_ = store.MarkBillingRecordFailed(recordID, err.Error())
			log.Printf("[billing-links] erro ao criar checkout session: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Não foi possível criar o link de pagamento."})
			return
		}

		if session == nil || strings.TrimSpace(session.URL) == "" {
			_ = store.MarkBillingRecordFailed(recordID, "checkout criado sem URL")
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Checkout criado, mas sem URL retornada pela Stripe."})
			return
		}

		var expiresAt *time.Time
		if session.ExpiresAt > 0 {
			t := time.Unix(session.ExpiresAt, 0).UTC()
			expiresAt = &t
		}

		stripeCustomerID := ""
		if session.Customer != nil {
			stripeCustomerID = strings.TrimSpace(session.Customer.ID)
		}

		_ = store.MarkBillingRecordCheckoutOpen(recordID, session.ID, session.URL, expiresAt, stripeCustomerID)

		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":                true,
			"billingRecordId":   recordID,
			"url":               session.URL,
			"checkoutSessionId": session.ID,
		})
	}
}

func sanitizeMetadata(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string)
	for key, value := range raw {
		k := strings.TrimSpace(key)
		v := strings.TrimSpace(value)
		if k == "" || v == "" {
			continue
		}
		if len(k) > 40 {
			k = k[:40]
		}
		if len(v) > 380 {
			v = v[:380]
		}
		if len(out) >= 25 {
			break
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isValidSimpleEmail(email string) bool {
	email = strings.TrimSpace(email)
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func toMinorUnits(amountRaw json.RawMessage, currency string) (int64, error) {
	raw := strings.TrimSpace(string(amountRaw))
	if raw == "" {
		return 0, fmt.Errorf("missing amount")
	}

	var parsed float64
	if strings.HasPrefix(raw, "\"") {
		var asString string
		if err := json.Unmarshal(amountRaw, &asString); err != nil {
			return 0, err
		}
		asString = strings.ReplaceAll(strings.TrimSpace(asString), ",", ".")
		n, err := strconv.ParseFloat(asString, 64)
		if err != nil {
			return 0, err
		}
		parsed = n
	} else {
		var asNumber float64
		if err := json.Unmarshal(amountRaw, &asNumber); err != nil {
			return 0, err
		}
		parsed = asNumber
	}

	if !isFinitePositive(parsed) {
		return 0, fmt.Errorf("invalid amount")
	}

	factor := 100.0
	if _, ok := zeroDecimalCurrencies[strings.ToLower(strings.TrimSpace(currency))]; ok {
		factor = 1.0
	}
	minor := int64(math.Round(parsed * factor))
	if minor <= 0 {
		return 0, fmt.Errorf("invalid amount")
	}
	return minor, nil
}

func isFinitePositive(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0
}

func withCheckoutSessionPlaceholder(baseURL string) string {
	trimmed := strings.TrimSpace(baseURL)
	if strings.Contains(trimmed, "{CHECKOUT_SESSION_ID}") {
		return trimmed
	}
	separator := "?"
	if strings.Contains(trimmed, "?") {
		separator = "&"
	}
	return trimmed + separator + "session_id={CHECKOUT_SESSION_ID}"
}
