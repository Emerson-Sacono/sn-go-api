package authstore

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"sn-go-api/internal/config"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/argon2"
)

type AdminIdentity struct {
	ID    string
	Email string
	Role  string
}

type Verifier interface {
	VerifyCredentials(email, password string) (*AdminIdentity, string, error)
}

type MongoStore struct {
	client                  *mongo.Client
	users                   *mongo.Collection
	sessions                *mongo.Collection
	emailVerificationTokens *mongo.Collection
	passwordResetTokens     *mongo.Collection
	requestTimeout          time.Duration
}

type adminUserDocument struct {
	ID              primitive.ObjectID `bson:"_id"`
	Name            string             `bson:"name,omitempty"`
	Email           string             `bson:"email"`
	PasswordHash    string             `bson:"passwordHash"`
	Role            string             `bson:"role"`
	IsActive        bool               `bson:"isActive"`
	IsEmailVerified bool               `bson:"isEmailVerified"`
	EmailVerifiedAt *time.Time         `bson:"emailVerifiedAt,omitempty"`
	LastLoginAt     *time.Time         `bson:"lastLoginAt,omitempty"`
	CreatedAt       *time.Time         `bson:"createdAt,omitempty"`
	UpdatedAt       *time.Time         `bson:"updatedAt,omitempty"`
}

func NewMongoStore(cfg config.Config) (*MongoStore, error) {
	uri := strings.TrimSpace(cfg.MongoURIAuth)
	if uri == "" {
		return nil, errors.New("MONGODB_URI_AUTH não configurada")
	}

	dbName := strings.TrimSpace(cfg.MongoDBAuth)
	if dbName == "" {
		dbName = databaseNameFromURI(uri)
	}
	if dbName == "" {
		return nil, errors.New("MONGODB_DB_AUTH não configurada e não foi possível inferir do URI")
	}

	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	clientOpts := options.Client().
		ApplyURI(uri).
		SetAppName(cfg.AppName).
		SetServerSelectionTimeout(8 * time.Second)

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("falha ao conectar Mongo auth: %w", err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("falha ao pingar Mongo auth: %w", err)
	}

	target := mongoTarget(uri)
	log.Printf("[authstore] mongo auth conectado host=%s db=%s collection=adminusers", target, dbName)

	db := client.Database(dbName)
	emailVerificationTokens := db.Collection("adminemailverificationtokens")
	passwordResetTokens := db.Collection("adminpasswordresettokens")
	sessions := db.Collection("adminsessions")

	store := &MongoStore{
		client:                  client,
		users:                   db.Collection("adminusers"),
		sessions:                sessions,
		emailVerificationTokens: emailVerificationTokens,
		passwordResetTokens:     passwordResetTokens,
		requestTimeout:          8 * time.Second,
	}

	if err := store.ensureTokenIndexes(); err != nil {
		return nil, err
	}
	if err := store.ensureSessionIndexes(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *MongoStore) VerifyCredentials(email, password string) (*AdminIdentity, string, error) {
	normalizedEmail := strings.TrimSpace(strings.ToLower(email))
	if normalizedEmail == "" || password == "" {
		return nil, "invalid_credentials", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	var user adminUserDocument
	err := s.users.FindOne(ctx, bson.M{
		"email":    normalizedEmail,
		"isActive": true,
	}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, "invalid_credentials", nil
	}
	if err != nil {
		log.Printf("[authstore] erro ao consultar usuário admin: %v", err)
		return nil, "db_error", err
	}

	ok, err := verifyArgon2IDHash(user.PasswordHash, password)
	if err != nil {
		return nil, "invalid_credentials", nil
	}
	if !ok {
		return nil, "invalid_credentials", nil
	}

	if !user.IsEmailVerified {
		return nil, "email_not_verified", nil
	}

	role := strings.TrimSpace(user.Role)
	if role == "" {
		role = "admin"
	}

	userID := user.ID.Hex()
	if userID == "" {
		userID = normalizedEmail
	}

	_, _ = s.users.UpdateOne(
		ctx,
		bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{"lastLoginAt": time.Now().UTC(), "updatedAt": time.Now().UTC()}},
	)

	return &AdminIdentity{
		ID:    userID,
		Email: strings.TrimSpace(strings.ToLower(user.Email)),
		Role:  role,
	}, "", nil
}

func verifyArgon2IDHash(encodedHash, password string) (bool, error) {
	encodedHash = strings.TrimSpace(encodedHash)
	if encodedHash == "" {
		return false, errors.New("hash vazio")
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) < 5 || parts[0] != "" {
		return false, errors.New("hash argon2 inválido")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("algoritmo não suportado")
	}

	index := 2
	if strings.HasPrefix(parts[index], "v=") {
		version, err := strconv.Atoi(strings.TrimPrefix(parts[index], "v="))
		if err != nil || version != 19 {
			return false, errors.New("versão argon2 inválida")
		}
		index++
	}

	if len(parts) <= index+2 {
		return false, errors.New("hash argon2 incompleto")
	}

	timeCost, memoryCost, parallelism, err := parseArgon2Params(parts[index])
	if err != nil {
		return false, err
	}
	index++

	salt, err := decodeUnpaddedBase64(parts[index])
	if err != nil {
		return false, errors.New("salt inválido")
	}
	index++

	expectedHash, err := decodeUnpaddedBase64(parts[index])
	if err != nil {
		return false, errors.New("hash inválido")
	}
	if len(expectedHash) == 0 {
		return false, errors.New("hash vazio")
	}

	computedHash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1, nil
}

func VerifyPasswordHash(encodedHash, password string) (bool, error) {
	return verifyArgon2IDHash(encodedHash, password)
}

func parseArgon2Params(params string) (uint32, uint32, uint8, error) {
	pairs := strings.Split(params, ",")
	values := map[string]string{}
	for _, pair := range pairs {
		keyValue := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		values[keyValue[0]] = keyValue[1]
	}

	memoryInt, err := strconv.Atoi(values["m"])
	if err != nil || memoryInt <= 0 {
		return 0, 0, 0, errors.New("parâmetro m inválido")
	}
	timeInt, err := strconv.Atoi(values["t"])
	if err != nil || timeInt <= 0 {
		return 0, 0, 0, errors.New("parâmetro t inválido")
	}
	parallelInt, err := strconv.Atoi(values["p"])
	if err != nil || parallelInt <= 0 || parallelInt > 255 {
		return 0, 0, 0, errors.New("parâmetro p inválido")
	}

	return uint32(timeInt), uint32(memoryInt), uint8(parallelInt), nil
}

func decodeUnpaddedBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func databaseNameFromURI(rawURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil {
		return ""
	}
	name := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	return name
}

func mongoTarget(rawURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil {
		return "unknown"
	}
	if parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}

func (s *MongoStore) ensureTokenIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := ensureTokenIndexesForCollection(ctx, s.emailVerificationTokens); err != nil {
		return fmt.Errorf("falha ao criar índices de verification tokens: %w", err)
	}
	if err := ensureTokenIndexesForCollection(ctx, s.passwordResetTokens); err != nil {
		return fmt.Errorf("falha ao criar índices de password reset tokens: %w", err)
	}
	return nil
}

func ensureTokenIndexesForCollection(ctx context.Context, collection *mongo.Collection) error {
	models := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "tokenHash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
		{
			Keys: bson.D{{Key: "userId", Value: 1}},
		},
	}

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

func (s *MongoStore) ensureSessionIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	models := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "sessionId", Value: 1}},
			Options: options.Index().
				SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "userId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0),
		},
		{
			Keys: bson.D{{Key: "revokedAt", Value: 1}},
		},
	}

	for _, model := range models {
		if _, err := s.sessions.Indexes().CreateOne(ctx, model); err != nil {
			if isIgnorableIndexConflict(err) {
				continue
			}
			return fmt.Errorf("falha ao criar índices de sessões: %w", err)
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
