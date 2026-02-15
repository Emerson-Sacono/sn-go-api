package authstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/argon2"
)

const (
	argon2MemoryCost uint32 = 19456
	argon2TimeCost   uint32 = 3
	argon2Parallel   uint8  = 1
	argon2SaltLen           = 16
	argon2KeyLen            = 32
)

type AdminUserRecord struct {
	ID              primitive.ObjectID
	Name            string
	Email           string
	PasswordHash    string
	Role            string
	IsActive        bool
	IsEmailVerified bool
	EmailVerifiedAt *time.Time
	LastLoginAt     *time.Time
	CreatedAt       *time.Time
	UpdatedAt       *time.Time
}

type EmailVerificationTokenRecord struct {
	ID         primitive.ObjectID
	UserID     primitive.ObjectID
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	Email      string
	UserAgent  string
	IPAddress  string
	CreatedAt  *time.Time
	UpdatedAt  *time.Time
}

type PasswordResetTokenRecord struct {
	ID         primitive.ObjectID
	UserID     primitive.ObjectID
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	Email      string
	UserAgent  string
	IPAddress  string
	CreatedAt  *time.Time
	UpdatedAt  *time.Time
}

type emailVerificationTokenDoc struct {
	ID         primitive.ObjectID `bson:"_id"`
	UserID     primitive.ObjectID `bson:"userId"`
	TokenHash  string             `bson:"tokenHash"`
	ExpiresAt  time.Time          `bson:"expiresAt"`
	ConsumedAt *time.Time         `bson:"consumedAt,omitempty"`
	Email      string             `bson:"email"`
	UserAgent  string             `bson:"userAgent,omitempty"`
	IPAddress  string             `bson:"ipAddress,omitempty"`
	CreatedAt  *time.Time         `bson:"createdAt,omitempty"`
	UpdatedAt  *time.Time         `bson:"updatedAt,omitempty"`
}

type passwordResetTokenDoc struct {
	ID         primitive.ObjectID `bson:"_id"`
	UserID     primitive.ObjectID `bson:"userId"`
	TokenHash  string             `bson:"tokenHash"`
	ExpiresAt  time.Time          `bson:"expiresAt"`
	ConsumedAt *time.Time         `bson:"consumedAt,omitempty"`
	Email      string             `bson:"email"`
	UserAgent  string             `bson:"userAgent,omitempty"`
	IPAddress  string             `bson:"ipAddress,omitempty"`
	CreatedAt  *time.Time         `bson:"createdAt,omitempty"`
	UpdatedAt  *time.Time         `bson:"updatedAt,omitempty"`
}

func NormalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func RandomToken(bytesLen int) (string, error) {
	if bytesLen < 24 {
		bytesLen = 24
	}
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashPasswordArgon2ID(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("senha vazia")
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argon2TimeCost, argon2MemoryCost, argon2Parallel, argon2KeyLen)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argon2MemoryCost, argon2TimeCost, argon2Parallel, saltB64, hashB64)
	return encoded, nil
}

func (s *MongoStore) HasAnyUsers() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	count, err := s.users.CountDocuments(ctx, bson.M{})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *MongoStore) CountUsers() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	return s.users.CountDocuments(ctx, bson.M{})
}

func (s *MongoStore) FindUserByEmail(email string) (*AdminUserRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	normalized := NormalizeEmail(email)
	if normalized == "" {
		return nil, nil
	}

	var user adminUserDocument
	err := s.users.FindOne(ctx, bson.M{"email": normalized}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return mapUserDoc(&user), nil
}

func (s *MongoStore) FindUserByIDHex(idHex string) (*AdminUserRecord, error) {
	objectID, err := primitive.ObjectIDFromHex(strings.TrimSpace(idHex))
	if err != nil {
		return nil, errors.New("id inválido")
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	var user adminUserDocument
	err = s.users.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapUserDoc(&user), nil
}

func (s *MongoStore) CreateUser(name, email, passwordHash, role string, isEmailVerified bool) (*AdminUserRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	normalizedEmail := NormalizeEmail(email)
	now := time.Now().UTC()

	doc := bson.M{
		"name":            strings.TrimSpace(name),
		"email":           normalizedEmail,
		"passwordHash":    passwordHash,
		"role":            role,
		"isActive":        true,
		"isEmailVerified": isEmailVerified,
		"createdAt":       now,
		"updatedAt":       now,
	}
	if isEmailVerified {
		doc["emailVerifiedAt"] = now
	}
	if doc["name"] == "" {
		delete(doc, "name")
	}

	insertResult, err := s.users.InsertOne(ctx, doc)
	if err != nil {
		return nil, err
	}

	objectID, _ := insertResult.InsertedID.(primitive.ObjectID)
	return s.FindUserByIDHex(objectID.Hex())
}

func (s *MongoStore) MarkUserEmailVerified(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	now := time.Now().UTC()
	_, err := s.users.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"isEmailVerified": true, "emailVerifiedAt": now, "updatedAt": now}},
	)
	return err
}

func (s *MongoStore) SetUserPasswordHash(userID primitive.ObjectID, passwordHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	now := time.Now().UTC()
	_, err := s.users.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"passwordHash": passwordHash, "updatedAt": now}},
	)
	return err
}

func (s *MongoStore) FindRecentUnconsumedVerificationToken(userID primitive.ObjectID, createdAfter time.Time, now time.Time) (*EmailVerificationTokenRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	filter := bson.M{
		"userId":     userID,
		"consumedAt": bson.M{"$exists": false},
		"expiresAt":  bson.M{"$gt": now},
		"createdAt":  bson.M{"$gte": createdAfter},
	}
	var doc emailVerificationTokenDoc
	err := s.emailVerificationTokens.FindOne(ctx, filter, options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: -1}})).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapEmailTokenDoc(&doc), nil
}

func (s *MongoStore) ConsumeAllVerificationTokensByUser(userID primitive.ObjectID, consumedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	_, err := s.emailVerificationTokens.UpdateMany(
		ctx,
		bson.M{"userId": userID, "consumedAt": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"consumedAt": consumedAt, "updatedAt": consumedAt}},
	)
	return err
}

func (s *MongoStore) InsertVerificationToken(userID primitive.ObjectID, tokenHash string, expiresAt time.Time, email, userAgent, ipAddress string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	doc := bson.M{
		"userId":    userID,
		"tokenHash": tokenHash,
		"expiresAt": expiresAt,
		"email":     NormalizeEmail(email),
		"createdAt": now,
		"updatedAt": now,
	}
	if strings.TrimSpace(userAgent) != "" {
		doc["userAgent"] = strings.TrimSpace(userAgent)
	}
	if strings.TrimSpace(ipAddress) != "" {
		doc["ipAddress"] = strings.TrimSpace(ipAddress)
	}

	_, err := s.emailVerificationTokens.InsertOne(ctx, doc)
	return err
}

func (s *MongoStore) FindActiveVerificationTokenByHash(tokenHash string, now time.Time) (*EmailVerificationTokenRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	var doc emailVerificationTokenDoc
	err := s.emailVerificationTokens.FindOne(
		ctx,
		bson.M{
			"tokenHash":  tokenHash,
			"consumedAt": bson.M{"$exists": false},
			"expiresAt":  bson.M{"$gt": now},
		},
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapEmailTokenDoc(&doc), nil
}

func (s *MongoStore) ConsumeVerificationTokenByHash(tokenHash string, consumedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	_, err := s.emailVerificationTokens.UpdateOne(
		ctx,
		bson.M{"tokenHash": tokenHash, "consumedAt": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"consumedAt": consumedAt, "updatedAt": consumedAt}},
	)
	return err
}

func (s *MongoStore) FindRecentUnconsumedResetToken(userID primitive.ObjectID, createdAfter time.Time, now time.Time) (*PasswordResetTokenRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	filter := bson.M{
		"userId":     userID,
		"consumedAt": bson.M{"$exists": false},
		"expiresAt":  bson.M{"$gt": now},
		"createdAt":  bson.M{"$gte": createdAfter},
	}

	var doc passwordResetTokenDoc
	err := s.passwordResetTokens.FindOne(ctx, filter, options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: -1}})).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapResetTokenDoc(&doc), nil
}

func (s *MongoStore) ConsumeAllResetTokensByUser(userID primitive.ObjectID, consumedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	_, err := s.passwordResetTokens.UpdateMany(
		ctx,
		bson.M{"userId": userID, "consumedAt": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"consumedAt": consumedAt, "updatedAt": consumedAt}},
	)
	return err
}

func (s *MongoStore) InsertResetToken(userID primitive.ObjectID, tokenHash string, expiresAt time.Time, email, userAgent, ipAddress string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	doc := bson.M{
		"userId":    userID,
		"tokenHash": tokenHash,
		"expiresAt": expiresAt,
		"email":     NormalizeEmail(email),
		"createdAt": now,
		"updatedAt": now,
	}
	if strings.TrimSpace(userAgent) != "" {
		doc["userAgent"] = strings.TrimSpace(userAgent)
	}
	if strings.TrimSpace(ipAddress) != "" {
		doc["ipAddress"] = strings.TrimSpace(ipAddress)
	}

	_, err := s.passwordResetTokens.InsertOne(ctx, doc)
	return err
}

func (s *MongoStore) FindActiveResetTokenByHash(tokenHash string, now time.Time) (*PasswordResetTokenRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	var doc passwordResetTokenDoc
	err := s.passwordResetTokens.FindOne(
		ctx,
		bson.M{
			"tokenHash":  tokenHash,
			"consumedAt": bson.M{"$exists": false},
			"expiresAt":  bson.M{"$gt": now},
		},
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapResetTokenDoc(&doc), nil
}

func (s *MongoStore) ConsumeResetTokenByHash(tokenHash string, consumedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	_, err := s.passwordResetTokens.UpdateOne(
		ctx,
		bson.M{"tokenHash": tokenHash, "consumedAt": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"consumedAt": consumedAt, "updatedAt": consumedAt}},
	)
	return err
}

func mapUserDoc(doc *adminUserDocument) *AdminUserRecord {
	if doc == nil {
		return nil
	}
	return &AdminUserRecord{
		ID:              doc.ID,
		Name:            doc.Name,
		Email:           NormalizeEmail(doc.Email),
		PasswordHash:    doc.PasswordHash,
		Role:            doc.Role,
		IsActive:        doc.IsActive,
		IsEmailVerified: doc.IsEmailVerified,
		EmailVerifiedAt: doc.EmailVerifiedAt,
		LastLoginAt:     doc.LastLoginAt,
		CreatedAt:       doc.CreatedAt,
		UpdatedAt:       doc.UpdatedAt,
	}
}

func mapEmailTokenDoc(doc *emailVerificationTokenDoc) *EmailVerificationTokenRecord {
	if doc == nil {
		return nil
	}
	return &EmailVerificationTokenRecord{
		ID:         doc.ID,
		UserID:     doc.UserID,
		TokenHash:  doc.TokenHash,
		ExpiresAt:  doc.ExpiresAt,
		ConsumedAt: doc.ConsumedAt,
		Email:      doc.Email,
		UserAgent:  doc.UserAgent,
		IPAddress:  doc.IPAddress,
		CreatedAt:  doc.CreatedAt,
		UpdatedAt:  doc.UpdatedAt,
	}
}

func mapResetTokenDoc(doc *passwordResetTokenDoc) *PasswordResetTokenRecord {
	if doc == nil {
		return nil
	}
	return &PasswordResetTokenRecord{
		ID:         doc.ID,
		UserID:     doc.UserID,
		TokenHash:  doc.TokenHash,
		ExpiresAt:  doc.ExpiresAt,
		ConsumedAt: doc.ConsumedAt,
		Email:      doc.Email,
		UserAgent:  doc.UserAgent,
		IPAddress:  doc.IPAddress,
		CreatedAt:  doc.CreatedAt,
		UpdatedAt:  doc.UpdatedAt,
	}
}
