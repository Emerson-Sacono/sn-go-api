package billingstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (s *OverviewStore) UpsertSubscriptionFromCheckoutSession(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	subscriptionID := getExpandableID(obj["subscription"])
	customerID := getExpandableID(obj["customer"])
	if subscriptionID == "" || customerID == "" {
		return nil
	}

	customerDetails := getMapAny(obj["customer_details"])
	metadata := getStringMap(obj["metadata"])
	now := time.Now().UTC()

	setDoc := bson.M{
		"stripeCustomerId": customerID,
		"status":           "active",
		"updatedAt":        now,
	}
	if email := getStringAny(customerDetails["email"]); email != "" {
		setDoc["email"] = email
	}
	if name := getStringAny(customerDetails["name"]); name != "" {
		setDoc["name"] = name
	}
	if phone := getStringAny(customerDetails["phone"]); phone != "" {
		setDoc["phone"] = phone
	}
	if plan := firstNonEmpty(metadata["plan"], getStringAny(obj["client_reference_id"])); plan != "" {
		setDoc["plan"] = plan
	}
	if len(metadata) > 0 {
		setDoc["metadata"] = metadata
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	_, err = s.subscriptions.UpdateOne(
		ctx,
		bson.M{"subscriptionId": subscriptionID},
		bson.M{
			"$set": setDoc,
			"$setOnInsert": bson.M{
				"subscriptionId": subscriptionID,
				"createdAt":      now,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (s *OverviewStore) UpsertSubscriptionFromSubscription(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	subscriptionID := getStringAny(obj["id"])
	if subscriptionID == "" {
		return nil
	}

	price := extractFirstPrice(obj)
	recurring := getMapAny(price["recurring"])
	now := time.Now().UTC()

	setDoc := bson.M{
		"updatedAt": now,
	}
	if stripeCustomerID := getExpandableID(obj["customer"]); stripeCustomerID != "" {
		setDoc["stripeCustomerId"] = stripeCustomerID
	}
	if priceID := getStringAny(price["id"]); priceID != "" {
		setDoc["priceId"] = priceID
	}
	if plan := firstNonEmpty(getStringAny(price["nickname"]), getStringAny(price["product"])); plan != "" {
		setDoc["plan"] = plan
	}
	if status := getStringAny(obj["status"]); status != "" {
		setDoc["status"] = status
	}
	if ts := toTimePtr(getInt64Any(obj["current_period_end"])); ts != nil {
		setDoc["currentPeriodEnd"] = ts
	}
	if ts := toTimePtr(getInt64Any(obj["trial_end"])); ts != nil {
		setDoc["trialEnd"] = ts
	}
	if ts := toTimePtr(getInt64Any(obj["cancel_at"])); ts != nil {
		setDoc["cancelAt"] = ts
	}
	if value, ok := getBoolAny(obj["cancel_at_period_end"]); ok {
		setDoc["cancelAtPeriodEnd"] = value
	}
	if interval := getStringAny(recurring["interval"]); interval != "" {
		setDoc["interval"] = interval
	}
	if intervalCount := getInt64Any(recurring["interval_count"]); intervalCount > 0 {
		setDoc["intervalCount"] = intervalCount
	}
	if metadata := getStringMap(obj["metadata"]); len(metadata) > 0 {
		setDoc["metadata"] = metadata
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	_, err = s.subscriptions.UpdateOne(
		ctx,
		bson.M{"subscriptionId": subscriptionID},
		bson.M{
			"$set": setDoc,
			"$setOnInsert": bson.M{
				"subscriptionId": subscriptionID,
				"createdAt":      now,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (s *OverviewStore) UpdateSubscriptionFromInvoice(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	subscriptionID := getExpandableID(obj["subscription"])
	if subscriptionID == "" {
		return nil
	}

	now := time.Now().UTC()
	setDoc := bson.M{
		"updatedAt": now,
	}
	if invoiceStatus := getStringAny(obj["status"]); invoiceStatus != "" {
		setDoc["lastInvoiceStatus"] = invoiceStatus
		if invoiceStatus == "paid" {
			setDoc["status"] = "active"
		}
	}
	if ts := toTimePtr(getInt64Any(obj["created"])); ts != nil {
		setDoc["lastInvoiceAt"] = ts
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	_, err = s.subscriptions.UpdateOne(
		ctx,
		bson.M{"subscriptionId": subscriptionID},
		bson.M{"$set": setDoc},
	)
	return err
}

func (s *OverviewStore) UpsertBillingFromCheckoutSession(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	sessionID := getStringAny(obj["id"])
	if sessionID == "" {
		return nil
	}

	metadata := getStringMap(obj["metadata"])
	billingRecordID := strings.TrimSpace(metadata["billingRecordId"])
	recordType := resolveTypeFromCheckout(getStringAny(obj["mode"]))
	status := resolveCheckoutStatus(getStringAny(obj["status"]), getStringAny(obj["payment_status"]), recordType)

	stripeCustomerID := getExpandableID(obj["customer"])
	stripeSubscriptionID := getExpandableID(obj["subscription"])
	stripePaymentIntentID := getExpandableID(obj["payment_intent"])

	customerDetails := getMapAny(obj["customer_details"])
	customerEmail := firstNonEmpty(getStringAny(customerDetails["email"]), getStringAny(obj["customer_email"]), metadata["customerEmail"])
	customerName := firstNonEmpty(getStringAny(customerDetails["name"]), metadata["customerName"])
	stage := strings.TrimSpace(metadata["stage"])
	description := firstNonEmpty(metadata["description"], "Cobranca personalizada")
	amountMinor := resolveCheckoutAmountMinor(obj)
	currency := resolveCheckoutCurrency(getStringAny(obj["currency"]))
	checkoutURL := getStringAny(obj["url"])

	var checkoutExpiresAt *time.Time
	if ts := toTimePtr(getInt64Any(obj["expires_at"])); ts != nil {
		checkoutExpiresAt = ts
	}

	var paidAt *time.Time
	if status == "paid" {
		if ts := toTimePtr(getInt64Any(obj["created"])); ts != nil {
			paidAt = ts
		}
	}

	now := time.Now().UTC()
	sharedSet := bson.M{
		"status":            status,
		"checkoutSessionId": sessionID,
		"updatedAt":         now,
	}
	if stage != "" {
		sharedSet["stage"] = stage
	}
	if customerEmail != "" {
		sharedSet["customerEmail"] = strings.ToLower(customerEmail)
	}
	if customerName != "" {
		sharedSet["customerName"] = customerName
	}
	if checkoutURL != "" {
		sharedSet["checkoutUrl"] = checkoutURL
	}
	if checkoutExpiresAt != nil {
		sharedSet["checkoutExpiresAt"] = checkoutExpiresAt
	}
	if stripeCustomerID != "" {
		sharedSet["stripeCustomerId"] = stripeCustomerID
	}
	if stripeSubscriptionID != "" {
		sharedSet["stripeSubscriptionId"] = stripeSubscriptionID
	}
	if stripePaymentIntentID != "" {
		sharedSet["stripePaymentIntentId"] = stripePaymentIntentID
	}
	if len(metadata) > 0 {
		sharedSet["metadata"] = metadata
	}
	if paidAt != nil {
		sharedSet["paidAt"] = paidAt
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	if objectID, ok := asObjectID(billingRecordID); ok {
		result, err := s.billingRecords.UpdateOne(ctx, bson.M{"_id": objectID}, bson.M{"$set": sharedSet})
		if err != nil {
			return err
		}
		if result != nil && result.MatchedCount > 0 {
			return nil
		}
	}

	setOnInsert := bson.M{
		"type":        recordType,
		"description": description,
		"amountMinor": amountMinor,
		"currency":    currency,
		"createdAt":   now,
	}
	if stage != "" {
		setOnInsert["stage"] = stage
	}
	if customerEmail != "" {
		setOnInsert["customerEmail"] = strings.ToLower(customerEmail)
	}
	if customerName != "" {
		setOnInsert["customerName"] = customerName
	}

	_, err = s.billingRecords.UpdateOne(
		ctx,
		bson.M{"checkoutSessionId": sessionID},
		bson.M{
			"$set":         sharedSet,
			"$setOnInsert": setOnInsert,
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (s *OverviewStore) MarkBillingCheckoutExpired(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	metadata := getStringMap(obj["metadata"])
	billingRecordID := strings.TrimSpace(metadata["billingRecordId"])
	sessionID := getStringAny(obj["id"])
	checkoutExpiresAt := toTimePtr(getInt64Any(obj["expires_at"]))

	filter := bson.M{}
	if objectID, ok := asObjectID(billingRecordID); ok {
		filter["_id"] = objectID
	} else if sessionID != "" {
		filter["checkoutSessionId"] = sessionID
	} else {
		return nil
	}

	setDoc := bson.M{
		"status":    "expired",
		"updatedAt": time.Now().UTC(),
	}
	if sessionID != "" {
		setDoc["checkoutSessionId"] = sessionID
	}
	if checkoutExpiresAt != nil {
		setDoc["checkoutExpiresAt"] = checkoutExpiresAt
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	_, err = s.billingRecords.UpdateOne(ctx, filter, bson.M{"$set": setDoc})
	return err
}

func (s *OverviewStore) UpdateBillingFromSubscription(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	subscriptionID := getStringAny(obj["id"])
	if subscriptionID == "" {
		return nil
	}

	metadata := getStringMap(obj["metadata"])
	billingRecordID := strings.TrimSpace(metadata["billingRecordId"])
	status := mapSubscriptionStatus(getStringAny(obj["status"]))
	price := extractFirstPrice(obj)
	recurring := getMapAny(price["recurring"])
	amountMinor := maxInt64(1, getInt64Any(price["unit_amount"]))
	stage := strings.TrimSpace(metadata["stage"])
	description := firstNonEmpty(metadata["description"], getStringAny(price["nickname"]), "Assinatura personalizada")
	stripeCustomerID := getExpandableID(obj["customer"])
	canceledAt := toTimePtr(getInt64Any(obj["canceled_at"]))
	currentPeriodEnd := toTimePtr(getInt64Any(obj["current_period_end"]))
	currency := strings.ToLower(firstNonEmpty(getStringAny(price["currency"]), "jpy"))

	now := time.Now().UTC()
	sharedSet := bson.M{
		"type":                 "recurring",
		"description":          description,
		"status":               status,
		"stripeSubscriptionId": subscriptionID,
		"amountMinor":          amountMinor,
		"currency":             currency,
		"updatedAt":            now,
	}
	if stage != "" {
		sharedSet["stage"] = stage
	}
	if stripeCustomerID != "" {
		sharedSet["stripeCustomerId"] = stripeCustomerID
	}
	if interval := getStringAny(recurring["interval"]); interval != "" {
		sharedSet["interval"] = interval
	}
	if intervalCount := getInt64Any(recurring["interval_count"]); intervalCount > 0 {
		sharedSet["intervalCount"] = intervalCount
	}
	if currentPeriodEnd != nil {
		sharedSet["currentPeriodEnd"] = currentPeriodEnd
	}
	if canceledAt != nil {
		sharedSet["canceledAt"] = canceledAt
	}
	if len(metadata) > 0 {
		sharedSet["metadata"] = metadata
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	if objectID, ok := asObjectID(billingRecordID); ok {
		result, err := s.billingRecords.UpdateOne(ctx, bson.M{"_id": objectID}, bson.M{"$set": sharedSet})
		if err != nil {
			return err
		}
		if result != nil && result.MatchedCount > 0 {
			return nil
		}
	}

	_, err = s.billingRecords.UpdateOne(
		ctx,
		bson.M{"stripeSubscriptionId": subscriptionID},
		bson.M{
			"$set": sharedSet,
			"$setOnInsert": bson.M{
				"type":        "recurring",
				"description": description,
				"amountMinor": amountMinor,
				"currency":    currency,
				"createdAt":   now,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (s *OverviewStore) UpdateBillingFromInvoice(raw json.RawMessage) error {
	obj, err := parseRawObject(raw)
	if err != nil {
		return err
	}

	stripeSubscriptionID := getExpandableID(obj["subscription"])
	if stripeSubscriptionID == "" {
		return nil
	}

	invoiceStatus := getStringAny(obj["status"])
	lastInvoiceAt := toTimePtr(getInt64Any(obj["created"]))
	amountDue := maxInt64(1, getInt64Any(obj["amount_due"]))
	currency := strings.ToLower(firstNonEmpty(getStringAny(obj["currency"]), "jpy"))

	now := time.Now().UTC()
	setDoc := bson.M{
		"updatedAt": now,
	}
	if invoiceStatus != "" {
		setDoc["lastInvoiceStatus"] = invoiceStatus
	}
	if lastInvoiceAt != nil {
		setDoc["lastInvoiceAt"] = lastInvoiceAt
	}

	switch invoiceStatus {
	case "paid":
		setDoc["status"] = "active"
		if lastInvoiceAt != nil {
			setDoc["paidAt"] = lastInvoiceAt
		}
	case "open":
		setDoc["status"] = "past_due"
	case "uncollectible":
		setDoc["status"] = "failed"
	case "void":
		setDoc["status"] = "canceled"
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	_, err = s.billingRecords.UpdateOne(
		ctx,
		bson.M{"stripeSubscriptionId": stripeSubscriptionID},
		bson.M{
			"$set": setDoc,
			"$setOnInsert": bson.M{
				"type":        "recurring",
				"description": "Assinatura recorrente",
				"amountMinor": amountDue,
				"currency":    currency,
				"createdAt":   now,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func parseRawObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("payload stripe vazio")
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func resolveTypeFromCheckout(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "subscription") {
		return "recurring"
	}
	return "one_time"
}

func resolveCheckoutStatus(status, paymentStatus, recordType string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	paymentStatus = strings.TrimSpace(strings.ToLower(paymentStatus))

	if status == "expired" {
		return "expired"
	}
	if recordType == "one_time" {
		if paymentStatus == "paid" {
			return "paid"
		}
		if status == "complete" {
			return "checkout_completed"
		}
		return "checkout_open"
	}
	if status == "complete" {
		return "checkout_completed"
	}
	return "checkout_open"
}

func resolveCheckoutAmountMinor(obj map[string]any) int64 {
	total := getInt64Any(obj["amount_total"])
	if total <= 0 {
		total = getInt64Any(obj["amount_subtotal"])
	}
	return maxInt64(1, total)
}

func resolveCheckoutCurrency(currency string) string {
	value := strings.ToLower(strings.TrimSpace(currency))
	if value == "" {
		return "jpy"
	}
	return value
}

func mapSubscriptionStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "active":
		return "active"
	case "trialing":
		return "trialing"
	case "past_due":
		return "past_due"
	case "canceled":
		return "canceled"
	case "unpaid":
		return "unpaid"
	case "incomplete":
		return "incomplete"
	case "incomplete_expired":
		return "failed"
	case "paused":
		return "past_due"
	default:
		return "failed"
	}
}

func extractFirstPrice(obj map[string]any) map[string]any {
	items := getMapAny(obj["items"])
	rawData, ok := items["data"].([]any)
	if !ok || len(rawData) == 0 {
		return nil
	}
	firstItem := getMapAny(rawData[0])
	return getMapAny(firstItem["price"])
}

func getStringAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func getInt64Any(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case float32:
		return int64(typed)
	case int:
		return int64(typed)
	case int64:
		return typed
	case int32:
		return int64(typed)
	case json.Number:
		number, err := typed.Int64()
		if err == nil {
			return number
		}
		floatNumber, err := typed.Float64()
		if err != nil {
			return 0
		}
		return int64(floatNumber)
	default:
		return 0
	}
}

func getBoolAny(value any) (bool, bool) {
	parsed, ok := value.(bool)
	return parsed, ok
}

func getMapAny(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	default:
		return nil
	}
}

func getStringMap(value any) map[string]string {
	input := getMapAny(value)
	if len(input) == 0 {
		return nil
	}

	out := make(map[string]string)
	for key, rawValue := range input {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := getStringAny(rawValue)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func getExpandableID(value any) string {
	if id := getStringAny(value); id != "" {
		return id
	}
	if obj := getMapAny(value); len(obj) > 0 {
		return getStringAny(obj["id"])
	}
	return ""
}

func toTimePtr(unixSeconds int64) *time.Time {
	if unixSeconds <= 0 {
		return nil
	}
	value := time.Unix(unixSeconds, 0).UTC()
	return &value
}

func asObjectID(hex string) (primitive.ObjectID, bool) {
	objectID, err := primitive.ObjectIDFromHex(strings.TrimSpace(hex))
	if err != nil {
		return primitive.NilObjectID, false
	}
	return objectID, true
}

func maxInt64(a, b int64) int64 {
	if a >= b {
		return a
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
