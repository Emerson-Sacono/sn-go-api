package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"sn-go-api/internal/authstore"
	"sn-go-api/internal/billingstore"
	"sn-go-api/internal/config"
)

type billingDeleteBody struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

func BillingDelete(cfg config.Config, store *billingstore.OverviewStore, authStore *authstore.MongoStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if _, err := requireAccessClaims(r, cfg, authStore); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "Não autenticado",
			})
			return
		}

		if store == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Serviço de billing indisponível.",
			})
			return
		}

		var body billingDeleteBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "Payload inválido.",
			})
			return
		}

		result, err := store.SoftDeleteByID(strings.TrimSpace(body.ID), strings.TrimSpace(body.Source))
		if err != nil {
			if errors.Is(err, billingstore.ErrDeleteIDRequired) ||
				errors.Is(err, billingstore.ErrDeleteIDInvalid) ||
				errors.Is(err, billingstore.ErrDeleteSourceInvalid) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error": err.Error(),
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "Não foi possível excluir o registro.",
			})
			return
		}

		if !result.Found {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"error": "Registro não encontrado.",
			})
			return
		}

		message := "Registro já estava removido da listagem."
		if result.Deleted {
			message = "Registro removido da listagem com sucesso."
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"deleted": result.Deleted,
			"message": message,
		})
	}
}
