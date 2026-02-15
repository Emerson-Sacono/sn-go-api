package handlers

import (
	"net/http"
	"time"
)

func Health(appName string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"service":   appName,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}
}
