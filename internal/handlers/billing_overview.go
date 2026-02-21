package handlers

import (
	"log"
	"net/http"
	"strconv"

	"sn-go-api/internal/authstore"
	"sn-go-api/internal/billingstore"
	"sn-go-api/internal/config"
)

func BillingOverview(cfg config.Config, store *billingstore.OverviewStore, authStore *authstore.MongoStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if _, err := requireAccessClaims(r, cfg, authStore); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "Não autenticado",
			})
			return
		}

		oneTimePage := parsePositiveInt64(r.URL.Query().Get("oneTimePage"), 1, 1, 1_000_000)
		oneTimePageSize := parsePositiveInt64(r.URL.Query().Get("oneTimePageSize"), 10, 1, 100)
		recurringPage := parsePositiveInt64(r.URL.Query().Get("recurringPage"), 1, 1, 1_000_000)
		recurringPageSize := parsePositiveInt64(r.URL.Query().Get("recurringPageSize"), 10, 1, 100)

		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível carregar o dashboard.",
			})
			return
		}

		overview, err := store.GetOverview(oneTimePage, oneTimePageSize, recurringPage, recurringPageSize)
		if err != nil {
			log.Printf("[billing-overview] erro ao carregar overview: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível carregar o dashboard.",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"stats":     overview.Stats,
			"oneTime":   overview.OneTime,
			"recurring": overview.Recurring,
		})
	}
}

func parsePositiveInt64(raw string, fallback, min, max int64) int64 {
	value := fallback
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		value = n
	}
	if value < min {
		value = min
	}
	if value > max {
		value = max
	}
	return value
}
