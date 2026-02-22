package billingstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	BillingSourceRecord             = "billing_record"
	BillingSourceLegacySubscription = "legacy_subscription"
)

var (
	ErrDeleteIDRequired    = errors.New("id é obrigatório")
	ErrDeleteIDInvalid     = errors.New("id inválido")
	ErrDeleteSourceInvalid = errors.New("source inválido")
)

type SoftDeleteResult struct {
	Found   bool
	Deleted bool
}

func normalizeDeleteSource(raw string) string {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", BillingSourceRecord:
		return BillingSourceRecord
	case BillingSourceLegacySubscription:
		return BillingSourceLegacySubscription
	default:
		return ""
	}
}

func (s *OverviewStore) SoftDeleteByID(idHex, source string) (SoftDeleteResult, error) {
	trimmedID := strings.TrimSpace(idHex)
	if trimmedID == "" {
		return SoftDeleteResult{}, ErrDeleteIDRequired
	}

	objectID, err := primitive.ObjectIDFromHex(trimmedID)
	if err != nil {
		return SoftDeleteResult{}, ErrDeleteIDInvalid
	}

	normalizedSource := normalizeDeleteSource(source)
	if normalizedSource == "" {
		return SoftDeleteResult{}, ErrDeleteSourceInvalid
	}

	var collection *mongo.Collection
	switch normalizedSource {
	case BillingSourceRecord:
		collection = s.billingRecords
	case BillingSourceLegacySubscription:
		collection = s.subscriptions
	default:
		return SoftDeleteResult{}, ErrDeleteSourceInvalid
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	updateResult, err := collection.UpdateOne(
		ctx,
		bson.M{
			"_id":       objectID,
			"deletedAt": bson.M{"$exists": false},
		},
		bson.M{
			"$set": bson.M{
				"deletedAt": now,
				"updatedAt": now,
			},
		},
	)
	if err != nil {
		return SoftDeleteResult{}, err
	}
	if updateResult != nil && updateResult.MatchedCount > 0 {
		return SoftDeleteResult{Found: true, Deleted: true}, nil
	}

	var existingDoc bson.M
	findErr := collection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&existingDoc)
	if errors.Is(findErr, mongo.ErrNoDocuments) {
		return SoftDeleteResult{Found: false, Deleted: false}, nil
	}
	if findErr != nil {
		return SoftDeleteResult{}, findErr
	}

	return SoftDeleteResult{Found: true, Deleted: false}, nil
}
