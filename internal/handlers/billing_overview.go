package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		filters := billingstore.OverviewFilters{
			OneTime: billingstore.OverviewTableFilter{
				Status: parseFilterString(r.URL.Query().Get("oneTimeStatus"), 40),
				Client: parseFilterString(r.URL.Query().Get("oneTimeClient"), 120),
				From:   parseFilterDateStart(r.URL.Query().Get("oneTimeFrom")),
				To:     parseFilterDateEndExclusive(r.URL.Query().Get("oneTimeTo")),
			},
			Recurring: billingstore.OverviewTableFilter{
				Status: parseFilterString(r.URL.Query().Get("recurringStatus"), 40),
				Client: parseFilterString(r.URL.Query().Get("recurringClient"), 120),
				From:   parseFilterDateStart(r.URL.Query().Get("recurringFrom")),
				To:     parseFilterDateEndExclusive(r.URL.Query().Get("recurringTo")),
			},
		}

		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível carregar o dashboard.",
			})
			return
		}

		overview, err := store.GetOverview(oneTimePage, oneTimePageSize, recurringPage, recurringPageSize, filters)
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

func parseFilterString(raw string, maxLen int) string {
	text := strings.TrimSpace(raw)
	if text == "" || maxLen <= 0 {
		return text
	}
	runes := []rune(text)
	if len(runes) > maxLen {
		return string(runes[:maxLen])
	}
	return text
}

func parseFilterDateStart(raw string) *time.Time {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}

	if day, err := time.Parse("2006-01-02", text); err == nil {
		value := day.UTC()
		return &value
	}
	if stamp, err := time.Parse(time.RFC3339, text); err == nil {
		value := stamp.UTC()
		return &value
	}
	return nil
}

func parseFilterDateEndExclusive(raw string) *time.Time {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}

	if day, err := time.Parse("2006-01-02", text); err == nil {
		value := day.UTC().Add(24 * time.Hour)
		return &value
	}
	if stamp, err := time.Parse(time.RFC3339, text); err == nil {
		value := stamp.UTC()
		return &value
	}
	return nil
}
