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

		limit := int64(120)
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				if n > 300 {
					n = 300
				}
				limit = int64(n)
			}
		}

		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível carregar o dashboard.",
			})
			return
		}

		overview, err := store.GetOverview(limit)
		if err != nil {
			log.Printf("[billing-overview] erro ao carregar overview: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível carregar o dashboard.",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"stats":         overview.Stats,
			"records":       overview.Records,
			"subscriptions": overview.Subscriptions,
		})
	}
}
