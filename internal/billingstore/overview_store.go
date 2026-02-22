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
	Stats     OverviewStats
	OneTime   TablePage[OneTimeTableRow]
	Recurring TablePage[RecurringTableRow]
}

type OverviewFilters struct {
	OneTime   OverviewTableFilter
	Recurring OverviewTableFilter
}

type OverviewTableFilter struct {
	Status string
	Client string
	From   *time.Time
	To     *time.Time
}

type TablePage[T any] struct {
	Items      []T   `json:"items"`
	Page       int64 `json:"page"`
	PageSize   int64 `json:"pageSize"`
	TotalItems int64 `json:"totalItems"`
	TotalPages int64 `json:"totalPages"`
	HasPrev    bool  `json:"hasPrev"`
	HasNext    bool  `json:"hasNext"`
}

type OverviewStats struct {
	OneTimePaid        int64 `json:"oneTimePaid"`
	OneTimeOpen        int64 `json:"oneTimeOpen"`
	RecurringActive    int64 `json:"recurringActive"`
	RecurringCanceled  int64 `json:"recurringCanceled"`
	RecurringAttention int64 `json:"recurringAttention"`
}

type OneTimeTableRow struct {
	ID          string `json:"id"`
	Client      string `json:"client"`
	Description string `json:"description"`
	AmountMinor int64  `json:"amountMinor"`
	Currency    string `json:"currency"`
	Status      string `json:"status"`
	CreatedAt   any    `json:"createdAt"`
	PaidAt      any    `json:"paidAt"`
}

type RecurringTableRow struct {
	ID                   string `json:"id"`
	Source               string `json:"source"`
	Client               string `json:"client"`
	Description          string `json:"description"`
	AmountMinor          *int64 `json:"amountMinor,omitempty"`
	Currency             string `json:"currency,omitempty"`
	Status               string `json:"status"`
	NextCycle            any    `json:"nextCycle"`
	UpdatedAt            any    `json:"updatedAt"`
	CancellationReason   any    `json:"cancellationReason,omitempty"`
	CancellationFeedback any    `json:"cancellationFeedback,omitempty"`
	CancellationComment  any    `json:"cancellationComment,omitempty"`
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

	store := &OverviewStore{
		billingClient:   billingClient,
		customersClient: customersClient,
		billingRecords:  billingClient.Database(billingDB).Collection("billingrecords"),
		subscriptions:   customersClient.Database(customersDB).Collection("customersubscriptions"),
		requestTimeout:  8 * time.Second,
	}

	if err := store.ensureIndexes(); err != nil {
		_ = billingClient.Disconnect(context.Background())
		_ = customersClient.Disconnect(context.Background())
		return nil, err
	}

	return store, nil
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

func (s *OverviewStore) ensureIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	billingIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "type", Value: 1}, {Key: "status", Value: 1}, {Key: "createdAt", Value: -1}},
			Options: options.Index().SetName("idx_type_status_createdAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "type", Value: 1}, {Key: "status", Value: 1}, {Key: "updatedAt", Value: -1}},
			Options: options.Index().SetName("idx_type_status_updatedAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "type", Value: 1}, {Key: "createdAt", Value: -1}},
			Options: options.Index().SetName("idx_type_createdAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "type", Value: 1}, {Key: "updatedAt", Value: -1}},
			Options: options.Index().SetName("idx_type_updatedAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "checkoutSessionId", Value: 1}},
			Options: options.Index().SetName("idx_checkoutSessionId"),
		},
		{
			Keys:    bson.D{{Key: "stripeSubscriptionId", Value: 1}},
			Options: options.Index().SetName("idx_stripeSubscriptionId"),
		},
		{
			Keys:    bson.D{{Key: "customerEmail", Value: 1}},
			Options: options.Index().SetName("idx_customerEmail"),
		},
		{
			Keys:    bson.D{{Key: "deletedAt", Value: 1}},
			Options: options.Index().SetName("idx_deletedAt"),
		},
	}
	if err := createIndexesIgnoreConflicts(ctx, s.billingRecords, billingIndexes); err != nil {
		return fmt.Errorf("falha ao criar índices de billingrecords: %w", err)
	}

	subscriptionIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "subscriptionId", Value: 1}},
			Options: options.Index().SetName("idx_subscriptionId"),
		},
		{
			Keys:    bson.D{{Key: "stripeCustomerId", Value: 1}},
			Options: options.Index().SetName("idx_stripeCustomerId"),
		},
		{
			Keys:    bson.D{{Key: "status", Value: 1}, {Key: "updatedAt", Value: -1}},
			Options: options.Index().SetName("idx_status_updatedAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "updatedAt", Value: -1}},
			Options: options.Index().SetName("idx_updatedAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "email", Value: 1}, {Key: "updatedAt", Value: -1}},
			Options: options.Index().SetName("idx_email_updatedAt_desc"),
		},
		{
			Keys:    bson.D{{Key: "deletedAt", Value: 1}},
			Options: options.Index().SetName("idx_deletedAt"),
		},
	}
	if err := createIndexesIgnoreConflicts(ctx, s.subscriptions, subscriptionIndexes); err != nil {
		return fmt.Errorf("falha ao criar índices de customersubscriptions: %w", err)
	}
	return nil
}

func createIndexesIgnoreConflicts(ctx context.Context, collection *mongo.Collection, models []mongo.IndexModel) error {
	for _, model := range models {
		if _, err := collection.Indexes().CreateOne(ctx, model); err != nil {
			if isIgnorableIndexConflict(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func isIgnorableIndexConflict(err error) bool {
	if err == nil {
		return false
	}

	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) {
		if cmdErr.Code == 85 || cmdErr.Code == 86 {
			return true
		}
	}

	lowerMessage := strings.ToLower(err.Error())
	return strings.Contains(lowerMessage, "index already exists with a different name") ||
		strings.Contains(lowerMessage, "indexoptionsconflict") ||
		strings.Contains(lowerMessage, "indexkeyspecsconflict")
}

func (s *OverviewStore) GetOverview(
	oneTimePage,
	oneTimePageSize,
	recurringPage,
	recurringPageSize int64,
	filters OverviewFilters,
) (OverviewResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	oneTimeFilter := buildOneTimeFilter(filters.OneTime)
	recurringRecordFilter := buildRecurringBillingFilter(filters.Recurring)

	oneTimePaidFilter := bson.M{"type": "one_time", "status": "paid"}
	appendNotDeletedFilter(oneTimePaidFilter)
	oneTimePaid, err := s.billingRecords.CountDocuments(ctx, oneTimePaidFilter)
	if err != nil {
		return OverviewResult{}, err
	}
	oneTimeOpenFilter := bson.M{
		"type":   "one_time",
		"status": bson.M{"$in": bson.A{"link_created", "checkout_open", "checkout_completed"}},
	}
	appendNotDeletedFilter(oneTimeOpenFilter)
	oneTimeOpen, err := s.billingRecords.CountDocuments(ctx, oneTimeOpenFilter)
	if err != nil {
		return OverviewResult{}, err
	}
	recurringActiveFilter := bson.M{
		"type":   "recurring",
		"status": bson.M{"$in": bson.A{"active", "trialing"}},
	}
	appendNotDeletedFilter(recurringActiveFilter)
	recurringActive, err := s.billingRecords.CountDocuments(ctx, recurringActiveFilter)
	if err != nil {
		return OverviewResult{}, err
	}
	recurringCanceledFilter := bson.M{"type": "recurring", "status": "canceled"}
	appendNotDeletedFilter(recurringCanceledFilter)
	recurringCanceled, err := s.billingRecords.CountDocuments(ctx, recurringCanceledFilter)
	if err != nil {
		return OverviewResult{}, err
	}
	recurringAttentionFilter := bson.M{
		"type":   "recurring",
		"status": bson.M{"$in": bson.A{"past_due", "failed", "unpaid", "incomplete"}},
	}
	appendNotDeletedFilter(recurringAttentionFilter)
	recurringAttention, err := s.billingRecords.CountDocuments(ctx, recurringAttentionFilter)
	if err != nil {
		return OverviewResult{}, err
	}

	oneTimeTotal, err := s.billingRecords.CountDocuments(ctx, oneTimeFilter)
	if err != nil {
		return OverviewResult{}, err
	}
	oneTimePager := normalizePagination(oneTimeTotal, oneTimePage, oneTimePageSize)
	oneTimeDocs := make([]billingRecordDoc, 0, oneTimePager.PageSize)
	oneTimeCursor, err := s.billingRecords.Find(
		ctx,
		oneTimeFilter,
		options.Find().
			SetSort(bson.D{{Key: "createdAt", Value: -1}}).
			SetSkip((oneTimePager.Page-1)*oneTimePager.PageSize).
			SetLimit(oneTimePager.PageSize),
	)
	if err != nil {
		return OverviewResult{}, err
	}
	if err := oneTimeCursor.All(ctx, &oneTimeDocs); err != nil {
		return OverviewResult{}, err
	}

	recurringTotalRecords, err := s.billingRecords.CountDocuments(ctx, recurringRecordFilter)
	if err != nil {
		return OverviewResult{}, err
	}
	subscriptionDistinctFilter := cloneBsonMap(recurringRecordFilter)
	subscriptionDistinctFilter["stripeSubscriptionId"] = bson.M{"$exists": true, "$ne": ""}
	subscriptionIDsAny, err := s.billingRecords.Distinct(
		ctx,
		"stripeSubscriptionId",
		subscriptionDistinctFilter,
	)
	if err != nil {
		return OverviewResult{}, err
	}
	subscriptionIDs := make([]string, 0, len(subscriptionIDsAny))
	for _, raw := range subscriptionIDsAny {
		id := cleanString(raw)
		if id == "" {
			continue
		}
		subscriptionIDs = append(subscriptionIDs, id)
	}

	legacyFilter := buildLegacySubscriptionFilter(subscriptionIDs, filters.Recurring)

	legacyTotal, err := s.subscriptions.CountDocuments(ctx, legacyFilter)
	if err != nil {
		return OverviewResult{}, err
	}

	recurringTotal := recurringTotalRecords + legacyTotal
	recurringPager := normalizePagination(recurringTotal, recurringPage, recurringPageSize)
	recurringRows := make([]RecurringTableRow, 0, recurringPager.PageSize)
	recurringOffset := (recurringPager.Page - 1) * recurringPager.PageSize

	if recurringOffset < recurringTotalRecords {
		recurringDocs := make([]billingRecordDoc, 0, recurringPager.PageSize)
		recurringCursor, findErr := s.billingRecords.Find(
			ctx,
			recurringRecordFilter,
			options.Find().
				SetSort(bson.D{{Key: "createdAt", Value: -1}}).
				SetSkip(recurringOffset).
				SetLimit(recurringPager.PageSize),
		)
		if findErr != nil {
			return OverviewResult{}, findErr
		}
		if allErr := recurringCursor.All(ctx, &recurringDocs); allErr != nil {
			return OverviewResult{}, allErr
		}

		for _, item := range recurringDocs {
			recurringRows = append(recurringRows, RecurringTableRow{
				ID:                   item.ID.Hex(),
				Source:               "billing_record",
				Client:               firstNonEmptyString(cleanString(item.CustomerName), cleanString(item.CustomerEmail), "-"),
				Description:          composeDisplayDescription(item.Description, item.ProductName, item.TrialDays),
				AmountMinor:          ptrInt64(item.AmountMinor),
				Currency:             item.Currency,
				Status:               item.Status,
				NextCycle:            firstNonNil(isoOrNil(item.CurrentPeriodEnd), isoOrNil(item.LastInvoiceAt), isoOrNil(item.CheckoutExpiresAt)),
				UpdatedAt:            isoOrNil(item.UpdatedAt),
				CancellationReason:   item.CancellationReason,
				CancellationFeedback: item.CancellationFeedback,
				CancellationComment:  item.CancellationComment,
			})
		}
	}

	remaining := recurringPager.PageSize - int64(len(recurringRows))
	if remaining > 0 {
		legacySkip := int64(0)
		if recurringOffset > recurringTotalRecords {
			legacySkip = recurringOffset - recurringTotalRecords
		}

		legacyDocs := make([]subscriptionDoc, 0, remaining)
		legacyCursor, findErr := s.subscriptions.Find(
			ctx,
			legacyFilter,
			options.Find().
				SetSort(bson.D{{Key: "updatedAt", Value: -1}}).
				SetSkip(legacySkip).
				SetLimit(remaining),
		)
		if findErr != nil {
			return OverviewResult{}, findErr
		}
		if allErr := legacyCursor.All(ctx, &legacyDocs); allErr != nil {
			return OverviewResult{}, allErr
		}

		for _, item := range legacyDocs {
			recurringRows = append(recurringRows, RecurringTableRow{
				ID:                   item.ID.Hex(),
				Source:               "legacy_subscription",
				Client:               firstNonEmptyString(cleanString(item.Name), cleanString(item.Email), "-"),
				Description:          firstNonEmptyString(cleanString(item.Plan), "Assinatura legada"),
				Status:               firstNonEmptyString(cleanString(item.Status), "active"),
				NextCycle:            firstNonNil(isoOrNil(item.CurrentPeriodEnd), isoOrNil(item.CancelAt)),
				UpdatedAt:            firstNonNil(isoOrNil(item.UpdatedAt), isoOrNil(item.LastInvoiceAt)),
				CancellationReason:   item.CancellationReason,
				CancellationFeedback: item.CancellationFeedback,
				CancellationComment:  item.CancellationComment,
			})
		}
	}

	out := OverviewResult{
		Stats: OverviewStats{
			OneTimePaid:        oneTimePaid,
			OneTimeOpen:        oneTimeOpen,
			RecurringActive:    recurringActive,
			RecurringCanceled:  recurringCanceled,
			RecurringAttention: recurringAttention,
		},
		OneTime: TablePage[OneTimeTableRow]{
			Items:      make([]OneTimeTableRow, 0, len(oneTimeDocs)),
			Page:       oneTimePager.Page,
			PageSize:   oneTimePager.PageSize,
			TotalItems: oneTimePager.TotalItems,
			TotalPages: oneTimePager.TotalPages,
			HasPrev:    oneTimePager.HasPrev,
			HasNext:    oneTimePager.HasNext,
		},
		Recurring: TablePage[RecurringTableRow]{
			Items:      recurringRows,
			Page:       recurringPager.Page,
			PageSize:   recurringPager.PageSize,
			TotalItems: recurringPager.TotalItems,
			TotalPages: recurringPager.TotalPages,
			HasPrev:    recurringPager.HasPrev,
			HasNext:    recurringPager.HasNext,
		},
	}

	for _, item := range oneTimeDocs {
		out.OneTime.Items = append(out.OneTime.Items, OneTimeTableRow{
			ID:          item.ID.Hex(),
			Client:      firstNonEmptyString(cleanString(item.CustomerName), cleanString(item.CustomerEmail), "-"),
			Description: composeDisplayDescription(item.Description, item.ProductName, item.TrialDays),
			AmountMinor: item.AmountMinor,
			Currency:    item.Currency,
			Status:      item.Status,
			CreatedAt:   isoOrNil(item.CreatedAt),
			PaidAt:      isoOrNil(item.PaidAt),
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
		filter := bson.M{"subscriptionId": strings.TrimSpace(subscriptionID)}
		appendNotDeletedFilter(filter)
		err := s.subscriptions.FindOne(ctx, filter).Decode(&doc)
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
		appendNotDeletedFilter(filter)

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

func buildOneTimeFilter(filter OverviewTableFilter) bson.M {
	out := bson.M{
		"type": "one_time",
	}
	appendNotDeletedFilter(out)
	appendStatusFilter(out, filter.Status)
	appendClientFilter(
		out,
		filter.Client,
		"customerName",
		"customerEmail",
		"metadata.customerName",
		"metadata.customerEmail",
	)
	appendDateRangeFilter(out, "createdAt", filter.From, filter.To)
	return out
}

func buildRecurringBillingFilter(filter OverviewTableFilter) bson.M {
	out := bson.M{
		"type": "recurring",
	}
	appendNotDeletedFilter(out)
	appendStatusFilter(out, filter.Status)
	appendClientFilter(
		out,
		filter.Client,
		"customerName",
		"customerEmail",
		"metadata.customerName",
		"metadata.customerEmail",
	)
	appendDateRangeFilter(out, "updatedAt", filter.From, filter.To)
	return out
}

func buildLegacySubscriptionFilter(subscriptionIDs []string, filter OverviewTableFilter) bson.M {
	out := bson.M{
		"subscriptionId": bson.M{"$exists": true, "$ne": ""},
	}
	appendNotDeletedFilter(out)
	if len(subscriptionIDs) > 0 {
		out["subscriptionId"] = bson.M{"$exists": true, "$ne": "", "$nin": subscriptionIDs}
	}
	appendStatusFilter(out, filter.Status)
	appendClientFilter(
		out,
		filter.Client,
		"name",
		"email",
		"metadata.customerName",
		"metadata.customerEmail",
	)
	appendLegacyDateRangeFilter(out, filter.From, filter.To)
	return out
}

func appendStatusFilter(filter bson.M, rawStatus string) {
	status := strings.TrimSpace(strings.ToLower(rawStatus))
	if status == "" {
		return
	}
	appendAndCondition(filter, bson.M{
		"status": primitive.Regex{
			Pattern: fmt.Sprintf("^%s$", regexp.QuoteMeta(status)),
			Options: "i",
		},
	})
}

func appendClientFilter(filter bson.M, rawTerm string, fields ...string) {
	term := strings.TrimSpace(rawTerm)
	if term == "" || len(fields) == 0 {
		return
	}

	pattern := regexp.QuoteMeta(term)
	orFilters := make(bson.A, 0, len(fields))
	for _, field := range fields {
		name := strings.TrimSpace(field)
		if name == "" {
			continue
		}
		orFilters = append(orFilters, bson.M{
			name: primitive.Regex{
				Pattern: pattern,
				Options: "i",
			},
		})
	}
	if len(orFilters) == 0 {
		return
	}
	appendAndCondition(filter, bson.M{"$or": orFilters})
}

func appendDateRangeFilter(filter bson.M, field string, from, to *time.Time) {
	rangeFilter := buildRangeFilter(from, to)
	if len(rangeFilter) == 0 {
		return
	}
	appendAndCondition(filter, bson.M{
		field: rangeFilter,
	})
}

func appendLegacyDateRangeFilter(filter bson.M, from, to *time.Time) {
	rangeFilter := buildRangeFilter(from, to)
	if len(rangeFilter) == 0 {
		return
	}

	appendAndCondition(filter, bson.M{
		"$or": bson.A{
			bson.M{"updatedAt": cloneBsonMap(rangeFilter)},
			bson.M{"lastInvoiceAt": cloneBsonMap(rangeFilter)},
		},
	})
}

func buildRangeFilter(from, to *time.Time) bson.M {
	out := bson.M{}
	if from != nil && !from.IsZero() {
		out["$gte"] = from.UTC()
	}
	if to != nil && !to.IsZero() {
		out["$lt"] = to.UTC()
	}
	return out
}

func appendAndCondition(filter bson.M, condition bson.M) {
	if len(condition) == 0 {
		return
	}
	if current, ok := filter["$and"]; ok {
		if clauses, castOK := current.(bson.A); castOK {
			filter["$and"] = append(clauses, condition)
			return
		}
	}
	filter["$and"] = bson.A{condition}
}

func appendNotDeletedFilter(filter bson.M) {
	appendAndCondition(filter, bson.M{
		"deletedAt": bson.M{"$exists": false},
	})
}

func cloneBsonMap(input bson.M) bson.M {
	out := bson.M{}
	for key, value := range input {
		out[key] = value
	}
	return out
}

func isoOrNil(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func normalizePagination(totalItems, page, pageSize int64) TablePage[struct{}] {
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	if page <= 0 {
		page = 1
	}

	totalPages := int64(1)
	if totalItems > 0 {
		totalPages = (totalItems + pageSize - 1) / pageSize
		if totalPages < 1 {
			totalPages = 1
		}
	}
	if page > totalPages {
		page = totalPages
	}

	return TablePage[struct{}]{
		Page:       page,
		PageSize:   pageSize,
		TotalItems: totalItems,
		TotalPages: totalPages,
		HasPrev:    page > 1,
		HasNext:    page < totalPages,
	}
}

func cleanString(value any) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func ptrInt64(value int64) *int64 {
	v := value
	return &v
}

func composeDisplayDescription(base string, productName any, trialDays any) string {
	description := firstNonEmptyString(cleanString(productName), strings.TrimSpace(base))
	if description == "" {
		description = "-"
	}
	days := toInt64(trialDays)
	if days > 0 {
		return fmt.Sprintf("%s | Trial: %d dia(s)", description, days)
	}
	return description
}

func toInt64(value any) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		if v > uint64(^uint64(0)>>1) {
			return 0
		}
		return int64(v)
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	case primitive.Decimal128:
		bigInt, _, err := v.BigInt()
		if err != nil || bigInt == nil {
			return 0
		}
		return bigInt.Int64()
	default:
		return 0
	}
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
