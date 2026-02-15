package authstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AdminSessionRecord struct {
	ID               primitive.ObjectID
	UserID           primitive.ObjectID
	SessionID        string
	RefreshTokenHash string
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	UserAgent        string
	IPAddress        string
	LastSeenAt       *time.Time
	CreatedAt        *time.Time
	UpdatedAt        *time.Time
}

type adminSessionDoc struct {
	ID               primitive.ObjectID `bson:"_id"`
	UserID           primitive.ObjectID `bson:"userId"`
	SessionID        string             `bson:"sessionId"`
	RefreshTokenHash string             `bson:"refreshTokenHash"`
	ExpiresAt        time.Time          `bson:"expiresAt"`
	RevokedAt        *time.Time         `bson:"revokedAt,omitempty"`
	UserAgent        string             `bson:"userAgent,omitempty"`
	IPAddress        string             `bson:"ipAddress,omitempty"`
	LastSeenAt       *time.Time         `bson:"lastSeenAt,omitempty"`
	CreatedAt        *time.Time         `bson:"createdAt,omitempty"`
	UpdatedAt        *time.Time         `bson:"updatedAt,omitempty"`
}

func (s *MongoStore) CreateSession(
	userID primitive.ObjectID,
	sessionID,
	refreshTokenHash string,
	expiresAt time.Time,
	userAgent,
	ipAddress string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	now := time.Now().UTC()
	doc := bson.M{
		"userId":           userID,
		"sessionId":        strings.TrimSpace(sessionID),
		"refreshTokenHash": strings.TrimSpace(refreshTokenHash),
		"expiresAt":        expiresAt.UTC(),
		"lastSeenAt":       now,
		"createdAt":        now,
		"updatedAt":        now,
	}
	if strings.TrimSpace(userAgent) != "" {
		doc["userAgent"] = strings.TrimSpace(userAgent)
	}
	if strings.TrimSpace(ipAddress) != "" {
		doc["ipAddress"] = strings.TrimSpace(ipAddress)
	}

	_, err := s.sessions.InsertOne(ctx, doc)
	return err
}

func (s *MongoStore) FindActiveSessionByID(sessionID string, now time.Time) (*AdminSessionRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	var doc adminSessionDoc
	err := s.sessions.FindOne(
		ctx,
		bson.M{
			"sessionId": strings.TrimSpace(sessionID),
			"revokedAt": bson.M{"$exists": false},
			"expiresAt": bson.M{"$gt": now.UTC()},
		},
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapSessionDoc(&doc), nil
}

func (s *MongoStore) RotateSessionRefreshToken(
	sessionID,
	refreshTokenHash string,
	expiresAt time.Time,
	userAgent,
	ipAddress string,
	now time.Time,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	update := bson.M{
		"refreshTokenHash": strings.TrimSpace(refreshTokenHash),
		"expiresAt":        expiresAt.UTC(),
		"lastSeenAt":       now.UTC(),
		"updatedAt":        now.UTC(),
	}
	if strings.TrimSpace(userAgent) != "" {
		update["userAgent"] = strings.TrimSpace(userAgent)
	}
	if strings.TrimSpace(ipAddress) != "" {
		update["ipAddress"] = strings.TrimSpace(ipAddress)
	}

	_, err := s.sessions.UpdateOne(
		ctx,
		bson.M{
			"sessionId": strings.TrimSpace(sessionID),
			"revokedAt": bson.M{"$exists": false},
		},
		bson.M{"$set": update},
		options.Update().SetUpsert(false),
	)
	return err
}

func (s *MongoStore) TouchSession(sessionID string, now time.Time, userAgent, ipAddress string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	update := bson.M{
		"lastSeenAt": now.UTC(),
		"updatedAt":  now.UTC(),
	}
	if strings.TrimSpace(userAgent) != "" {
		update["userAgent"] = strings.TrimSpace(userAgent)
	}
	if strings.TrimSpace(ipAddress) != "" {
		update["ipAddress"] = strings.TrimSpace(ipAddress)
	}

	_, err := s.sessions.UpdateOne(
		ctx,
		bson.M{
			"sessionId": strings.TrimSpace(sessionID),
			"revokedAt": bson.M{"$exists": false},
		},
		bson.M{"$set": update},
		options.Update().SetUpsert(false),
	)
	return err
}

func (s *MongoStore) RevokeSessionByID(sessionID string, revokedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()

	_, err := s.sessions.UpdateOne(
		ctx,
		bson.M{
			"sessionId": strings.TrimSpace(sessionID),
			"revokedAt": bson.M{"$exists": false},
		},
		bson.M{
			"$set": bson.M{
				"revokedAt": revokedAt.UTC(),
				"updatedAt": revokedAt.UTC(),
			},
		},
		options.Update().SetUpsert(false),
	)
	return err
}

func mapSessionDoc(doc *adminSessionDoc) *AdminSessionRecord {
	if doc == nil {
		return nil
	}
	return &AdminSessionRecord{
		ID:               doc.ID,
		UserID:           doc.UserID,
		SessionID:        doc.SessionID,
		RefreshTokenHash: doc.RefreshTokenHash,
		ExpiresAt:        doc.ExpiresAt,
		RevokedAt:        doc.RevokedAt,
		UserAgent:        doc.UserAgent,
		IPAddress:        doc.IPAddress,
		LastSeenAt:       doc.LastSeenAt,
		CreatedAt:        doc.CreatedAt,
		UpdatedAt:        doc.UpdatedAt,
	}
}
