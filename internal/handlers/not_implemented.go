package handlers

import "net/http"

func NotImplemented(message string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"error":   "not_implemented",
			"message": message,
		})
	}
}
