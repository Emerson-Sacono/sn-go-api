package billingstore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"sn-go-api/internal/config"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type OverviewStore struct {
	billingClient   *mongo.Client
	customersClient *mongo.Client
	billingRecords  *mongo.Collection
	subscriptions   *mongo.Collection
	requestTimeout  time.Duration
}

type OverviewResult struct {
	Stats         OverviewStats
	Records       []BillingRecordPayload
	Subscriptions []SubscriptionPayload
}

type OverviewStats struct {
	OneTimePaid        int64 `json:"oneTimePaid"`
	OneTimeOpen        int64 `json:"oneTimeOpen"`
	RecurringActive    int64 `json:"recurringActive"`
	RecurringCanceled  int64 `json:"recurringCanceled"`
	RecurringAttention int64 `json:"recurringAttention"`
}

type BillingRecordPayload struct {
	ID                    string `json:"id"`
	Type                  string `json:"type"`
	Stage                 any    `json:"stage"`
	Description           string `json:"description"`
	ProductName           any    `json:"productName"`
	ProductDescription    any    `json:"productDescription"`
	ProductImageURL       any    `json:"productImageUrl"`
	CancellationReason    any    `json:"cancellationReason"`
	CancellationFeedback  any    `json:"cancellationFeedback"`
	CancellationComment   any    `json:"cancellationComment"`
	CustomerEmail         any    `json:"customerEmail"`
	CustomerName          any    `json:"customerName"`
	AmountMinor           int64  `json:"amountMinor"`
	Currency              string `json:"currency"`
	Interval              any    `json:"interval"`
	IntervalCount         any    `json:"intervalCount"`
	TrialDays             any    `json:"trialDays"`
	Status                string `json:"status"`
	CheckoutSessionID     any    `json:"checkoutSessionId"`
	CheckoutURL           any    `json:"checkoutUrl"`
	CheckoutExpiresAt     any    `json:"checkoutExpiresAt"`
	StripeCustomerID      any    `json:"stripeCustomerId"`
	StripeSubscriptionID  any    `json:"stripeSubscriptionId"`
	StripePaymentIntentID any    `json:"stripePaymentIntentId"`
	CurrentPeriodEnd      any    `json:"currentPeriodEnd"`
	LastInvoiceStatus     any    `json:"lastInvoiceStatus"`
	LastInvoiceAt         any    `json:"lastInvoiceAt"`
	PaidAt                any    `json:"paidAt"`
	CanceledAt            any    `json:"canceledAt"`
	Metadata              any    `json:"metadata"`
	CreatedAt             any    `json:"createdAt"`
	UpdatedAt             any    `json:"updatedAt"`
}

type SubscriptionPayload struct {
	ID                   string `json:"id"`
	StripeCustomerID     string `json:"stripeCustomerId"`
	SubscriptionID       string `json:"subscriptionId"`
	Email                any    `json:"email"`
	Name                 any    `json:"name"`
	Phone                any    `json:"phone"`
	Plan                 any    `json:"plan"`
	CancellationReason   any    `json:"cancellationReason"`
	CancellationFeedback any    `json:"cancellationFeedback"`
	CancellationComment  any    `json:"cancellationComment"`
	PriceID              any    `json:"priceId"`
	Status               any    `json:"status"`
	CurrentPeriodEnd     any    `json:"currentPeriodEnd"`
	TrialEnd             any    `json:"trialEnd"`
	CancelAt             any    `json:"cancelAt"`
	CancelAtPeriodEnd    bool   `json:"cancelAtPeriodEnd"`
	LastInvoiceStatus    any    `json:"lastInvoiceStatus"`
	LastInvoiceAt        any    `json:"lastInvoiceAt"`
	UpdatedAt            any    `json:"updatedAt"`
}

type billingRecordDoc struct {
	ID                    primitive.ObjectID `bson:"_id"`
	Type                  string             `bson:"type"`
	Stage                 any                `bson:"stage,omitempty"`
	Description           string             `bson:"description"`
	ProductName           any                `bson:"productName,omitempty"`
	ProductDescription    any                `bson:"productDescription,omitempty"`
	ProductImageURL       any                `bson:"productImageUrl,omitempty"`
	CancellationReason    any                `bson:"cancellationReason,omitempty"`
	CancellationFeedback  any                `bson:"cancellationFeedback,omitempty"`
	CancellationComment   any                `bson:"cancellationComment,omitempty"`
	CustomerEmail         any                `bson:"customerEmail,omitempty"`
	CustomerName          any                `bson:"customerName,omitempty"`
	AmountMinor           int64              `bson:"amountMinor"`
	Currency              string             `bson:"currency"`
	Interval              any                `bson:"interval,omitempty"`
	IntervalCount         any                `bson:"intervalCount,omitempty"`
	TrialDays             any                `bson:"trialDays,omitempty"`
	Status                string             `bson:"status"`
	CheckoutSessionID     any                `bson:"checkoutSessionId,omitempty"`
	CheckoutURL           any                `bson:"checkoutUrl,omitempty"`
	CheckoutExpiresAt     *time.Time         `bson:"checkoutExpiresAt,omitempty"`
	StripeCustomerID      any                `bson:"stripeCustomerId,omitempty"`
	StripeSubscriptionID  any                `bson:"stripeSubscriptionId,omitempty"`
	StripePaymentIntentID any                `bson:"stripePaymentIntentId,omitempty"`
	CurrentPeriodEnd      *time.Time         `bson:"currentPeriodEnd,omitempty"`
	LastInvoiceStatus     any                `bson:"lastInvoiceStatus,omitempty"`
	LastInvoiceAt         *time.Time         `bson:"lastInvoiceAt,omitempty"`
	PaidAt                *time.Time         `bson:"paidAt,omitempty"`
	CanceledAt            *time.Time         `bson:"canceledAt,omitempty"`
	Metadata              any                `bson:"metadata,omitempty"`
	CreatedAt             *time.Time         `bson:"createdAt,omitempty"`
	UpdatedAt             *time.Time         `bson:"updatedAt,omitempty"`
}

type subscriptionDoc struct {
	ID                   primitive.ObjectID `bson:"_id"`
	StripeCustomerID     string             `bson:"stripeCustomerId"`
	SubscriptionID       string             `bson:"subscriptionId"`
	Email                any                `bson:"email,omitempty"`
	Name                 any                `bson:"name,omitempty"`
	Phone                any                `bson:"phone,omitempty"`
	Plan                 any                `bson:"plan,omitempty"`
	CancellationReason   any                `bson:"cancellationReason,omitempty"`
	CancellationFeedback any                `bson:"cancellationFeedback,omitempty"`
	CancellationComment  any                `bson:"cancellationComment,omitempty"`
	PriceID              any                `bson:"priceId,omitempty"`
	Status               any                `bson:"status,omitempty"`
	CurrentPeriodEnd     *time.Time         `bson:"currentPeriodEnd,omitempty"`
	TrialEnd             *time.Time         `bson:"trialEnd,omitempty"`
	CancelAt             *time.Time         `bson:"cancelAt,omitempty"`
	CancelAtPeriodEnd    bool               `bson:"cancelAtPeriodEnd,omitempty"`
	LastInvoiceStatus    any                `bson:"lastInvoiceStatus,omitempty"`
	LastInvoiceAt        *time.Time         `bson:"lastInvoiceAt,omitempty"`
	UpdatedAt            *time.Time         `bson:"updatedAt,omitempty"`
}

type CreateBillingRecordInput struct {
	Type               string
	Stage              string
	Description        string
	ProductName        string
	ProductDescription string
	ProductImageURL    string
	TrialDays          int64
	CustomerEmail      string
	CustomerName       string
	AmountMinor        int64
	Currency           string
	Interval           string
	IntervalCount      int64
	Metadata           map[string]string
}

func NewOverviewStore(cfg config.Config) (*OverviewStore, error) {
	billingURI := strings.TrimSpace(cfg.MongoURIBilling)
	if billingURI == "" {
		return nil, errors.New("MONGODB_URI_BILLING não configurada")
	}
	customersURI := strings.TrimSpace(cfg.MongoURICustomers)
	if customersURI == "" {
		return nil, errors.New("MONGODB_URI_CUSTOMERS não configurada")
	}

	billingDB := strings.TrimSpace(cfg.MongoDBBilling)
	if billingDB == "" {
		billingDB = databaseNameFromURI(billingURI)
	}
	if billingDB == "" {
		return nil, errors.New("MONGODB_DB_BILLING não configurada")
	}

	customersDB := strings.TrimSpace(cfg.MongoDBCustomers)
	if customersDB == "" {
		customersDB = databaseNameFromURI(customersURI)
	}
	if customersDB == "" {
		return nil, errors.New("MONGODB_DB_CUSTOMERS não configurada")
	}

	billingClient, err := connectMongoClient(cfg.AppName, billingURI)
	if err != nil {
		return nil, fmt.Errorf("billing db: %w", err)
	}

	customersClient, err := connectMongoClient(cfg.AppName, customersURI)
	if err != nil {
		_ = billingClient.Disconnect(context.Background())
		return nil, fmt.Errorf("customers db: %w", err)
	}

	log.Printf("[billingstore] mongo billing conectado host=%s db=%s collection=billingrecords", mongoTarget(billingURI), billingDB)
	log.Printf("[billingstore] mongo customers conectado host=%s db=%s collection=customersubscriptions", mongoTarget(customersURI), customersDB)

	return &OverviewStore{
		billingClient:   billingClient,
		customersClient: customersClient,
		billingRecords:  billingClient.Database(billingDB).Collection("billingrecords"),
		subscriptions:   customersClient.Database(customersDB).Collection("customersubscriptions"),
		requestTimeout:  8 * time.Second,
	}, nil
}

func connectMongoClient(appName, uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := options.Client().
		ApplyURI(uri).
		SetAppName(appName).
		SetServerSelectionTimeout(8 * time.Second)

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}
	return client, nil
}

func (s *OverviewStore) GetOverview(limit int64) (OverviewResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	records := make([]billingRecordDoc, 0, limit)
	cursor, err := s.billingRecords.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}).SetLimit(limit))
	if err != nil {
		return OverviewResult{}, err
	}
	if err := cursor.All(ctx, &records); err != nil {
		return OverviewResult{}, err
	}

	subscriptions := make([]subscriptionDoc, 0, limit)
	subCursor, err := s.subscriptions.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "updatedAt", Value: -1}}).SetLimit(limit))
	if err != nil {
		return OverviewResult{}, err
	}
	if err := subCursor.All(ctx, &subscriptions); err != nil {
		return OverviewResult{}, err
	}

	oneTimePaid, err := s.billingRecords.CountDocuments(ctx, bson.M{"type": "one_time", "status": "paid"})
	if err != nil {
		return OverviewResult{}, err
	}
	oneTimeOpen, err := s.billingRecords.CountDocuments(ctx, bson.M{
		"type":   "one_time",
		"status": bson.M{"$in": bson.A{"link_created", "checkout_open", "checkout_completed"}},
	})
	if err != nil {
		return OverviewResult{}, err
	}
	recurringActive, err := s.billingRecords.CountDocuments(ctx, bson.M{
		"type":   "recurring",
		"status": bson.M{"$in": bson.A{"active", "trialing"}},
	})
	if err != nil {
		return OverviewResult{}, err
	}
	recurringCanceled, err := s.billingRecords.CountDocuments(ctx, bson.M{"type": "recurring", "status": "canceled"})
	if err != nil {
		return OverviewResult{}, err
	}
	recurringAttention, err := s.billingRecords.CountDocuments(ctx, bson.M{
		"type":   "recurring",
		"status": bson.M{"$in": bson.A{"past_due", "failed", "unpaid", "incomplete"}},
	})
	if err != nil {
		return OverviewResult{}, err
	}

	out := OverviewResult{
		Stats: OverviewStats{
			OneTimePaid:        oneTimePaid,
			OneTimeOpen:        oneTimeOpen,
			RecurringActive:    recurringActive,
			RecurringCanceled:  recurringCanceled,
			RecurringAttention: recurringAttention,
		},
		Records:       make([]BillingRecordPayload, 0, len(records)),
		Subscriptions: make([]SubscriptionPayload, 0, len(subscriptions)),
	}

	for _, item := range records {
		out.Records = append(out.Records, BillingRecordPayload{
			ID:                    item.ID.Hex(),
			Type:                  item.Type,
			Stage:                 item.Stage,
			Description:           item.Description,
			ProductName:           item.ProductName,
			ProductDescription:    item.ProductDescription,
			ProductImageURL:       item.ProductImageURL,
			CancellationReason:    item.CancellationReason,
			CancellationFeedback:  item.CancellationFeedback,
			CancellationComment:   item.CancellationComment,
			CustomerEmail:         item.CustomerEmail,
			CustomerName:          item.CustomerName,
			AmountMinor:           item.AmountMinor,
			Currency:              item.Currency,
			Interval:              item.Interval,
			IntervalCount:         item.IntervalCount,
			TrialDays:             item.TrialDays,
			Status:                item.Status,
			CheckoutSessionID:     item.CheckoutSessionID,
			CheckoutURL:           item.CheckoutURL,
			CheckoutExpiresAt:     isoOrNil(item.CheckoutExpiresAt),
			StripeCustomerID:      item.StripeCustomerID,
			StripeSubscriptionID:  item.StripeSubscriptionID,
			StripePaymentIntentID: item.StripePaymentIntentID,
			CurrentPeriodEnd:      isoOrNil(item.CurrentPeriodEnd),
			LastInvoiceStatus:     item.LastInvoiceStatus,
			LastInvoiceAt:         isoOrNil(item.LastInvoiceAt),
			PaidAt:                isoOrNil(item.PaidAt),
			CanceledAt:            isoOrNil(item.CanceledAt),
			Metadata:              item.Metadata,
			CreatedAt:             isoOrNil(item.CreatedAt),
			UpdatedAt:             isoOrNil(item.UpdatedAt),
		})
	}

	for _, item := range subscriptions {
		out.Subscriptions = append(out.Subscriptions, SubscriptionPayload{
			ID:                   item.ID.Hex(),
			StripeCustomerID:     item.StripeCustomerID,
			SubscriptionID:       item.SubscriptionID,
			Email:                item.Email,
			Name:                 item.Name,
			Phone:                item.Phone,
			Plan:                 item.Plan,
			CancellationReason:   item.CancellationReason,
			CancellationFeedback: item.CancellationFeedback,
			CancellationComment:  item.CancellationComment,
			PriceID:              item.PriceID,
			Status:               item.Status,
			CurrentPeriodEnd:     isoOrNil(item.CurrentPeriodEnd),
			TrialEnd:             isoOrNil(item.TrialEnd),
			CancelAt:             isoOrNil(item.CancelAt),
			CancelAtPeriodEnd:    item.CancelAtPeriodEnd,
			LastInvoiceStatus:    item.LastInvoiceStatus,
			LastInvoiceAt:        isoOrNil(item.LastInvoiceAt),
			UpdatedAt:            isoOrNil(item.UpdatedAt),
		})
	}

	return out, nil
}

func (s *OverviewStore) CreateBillingRecord(input CreateBillingRecordInput) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	doc := bson.M{
		"type":        input.Type,
		"description": input.Description,
		"amountMinor": input.AmountMinor,
		"currency":    strings.ToLower(strings.TrimSpace(input.Currency)),
		"status":      "link_created",
		"createdAt":   now,
		"updatedAt":   now,
	}
	if strings.TrimSpace(input.Stage) != "" {
		doc["stage"] = strings.TrimSpace(input.Stage)
	}
	if strings.TrimSpace(input.CustomerEmail) != "" {
		doc["customerEmail"] = strings.TrimSpace(strings.ToLower(input.CustomerEmail))
	}
	if strings.TrimSpace(input.CustomerName) != "" {
		doc["customerName"] = strings.TrimSpace(input.CustomerName)
	}
	if strings.TrimSpace(input.ProductName) != "" {
		doc["productName"] = strings.TrimSpace(input.ProductName)
	}
	if strings.TrimSpace(input.ProductDescription) != "" {
		doc["productDescription"] = strings.TrimSpace(input.ProductDescription)
	}
	if strings.TrimSpace(input.ProductImageURL) != "" {
		doc["productImageUrl"] = strings.TrimSpace(input.ProductImageURL)
	}
	if input.Type == "recurring" {
		if strings.TrimSpace(input.Interval) != "" {
			doc["interval"] = strings.TrimSpace(input.Interval)
		}
		if input.IntervalCount > 0 {
			doc["intervalCount"] = input.IntervalCount
		}
		if input.TrialDays > 0 {
			doc["trialDays"] = input.TrialDays
		}
	}
	if len(input.Metadata) > 0 {
		doc["metadata"] = input.Metadata
	}

	result, err := s.billingRecords.InsertOne(ctx, doc)
	if err != nil {
		return "", err
	}

	objectID, _ := result.InsertedID.(primitive.ObjectID)
	return objectID.Hex(), nil
}

func (s *OverviewStore) MarkBillingRecordCheckoutOpen(recordID, checkoutSessionID, checkoutURL string, checkoutExpiresAt *time.Time, stripeCustomerID string) error {
	objectID, err := primitive.ObjectIDFromHex(strings.TrimSpace(recordID))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	update := bson.M{
		"status":            "checkout_open",
		"checkoutSessionId": checkoutSessionID,
		"checkoutUrl":       checkoutURL,
		"updatedAt":         now,
	}
	if checkoutExpiresAt != nil && !checkoutExpiresAt.IsZero() {
		update["checkoutExpiresAt"] = checkoutExpiresAt.UTC()
	}
	if strings.TrimSpace(stripeCustomerID) != "" {
		update["stripeCustomerId"] = strings.TrimSpace(stripeCustomerID)
	}

	_, err = s.billingRecords.UpdateOne(
		ctx,
		bson.M{"_id": objectID},
		bson.M{"$set": update},
	)
	return err
}

func (s *OverviewStore) MarkBillingRecordFailed(recordID, message string) error {
	objectID, err := primitive.ObjectIDFromHex(strings.TrimSpace(recordID))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	_, err = s.billingRecords.UpdateOne(
		ctx,
		bson.M{"_id": objectID},
		bson.M{"$set": bson.M{
			"status":         "failed",
			"updatedAt":      now,
			"metadata.error": strings.TrimSpace(message),
		}},
	)
	return err
}

func (s *OverviewStore) ResolveStripeCustomerID(customerID, subscriptionID, email string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	if strings.TrimSpace(customerID) != "" {
		return strings.TrimSpace(customerID), nil
	}

	if strings.TrimSpace(subscriptionID) != "" {
		var doc subscriptionDoc
		err := s.subscriptions.FindOne(ctx, bson.M{"subscriptionId": strings.TrimSpace(subscriptionID)}).Decode(&doc)
		if err == nil {
			return strings.TrimSpace(doc.StripeCustomerID), nil
		}
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			return "", err
		}
	}

	if strings.TrimSpace(email) != "" {
		pattern := fmt.Sprintf("^%s$", regexp.QuoteMeta(strings.TrimSpace(email)))
		filter := bson.M{"email": primitive.Regex{Pattern: pattern, Options: "i"}}

		var doc subscriptionDoc
		err := s.subscriptions.FindOne(ctx, filter, options.FindOne().SetSort(bson.D{{Key: "updatedAt", Value: -1}})).Decode(&doc)
		if err == nil {
			return strings.TrimSpace(doc.StripeCustomerID), nil
		}
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			return "", err
		}
	}

	return "", nil
}

func isoOrNil(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func databaseNameFromURI(rawURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil {
		return ""
	}
	return strings.Trim(strings.TrimSpace(parsed.Path), "/")
}

func mongoTarget(rawURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}
