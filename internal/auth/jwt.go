package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AccessClaims struct {
	Subject   string
	Email     string
	Role      string
	SessionID string
	ExpiresAt time.Time
}

type RefreshClaims struct {
	Subject   string
	SessionID string
	ExpiresAt time.Time
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtPayload struct {
	Type  string      `json:"type"`
	SID   string      `json:"sid"`
	Sub   string      `json:"sub"`
	Email string      `json:"email"`
	Role  string      `json:"role"`
	Exp   json.Number `json:"exp"`
	Iss   string      `json:"iss"`
	Aud   any         `json:"aud"`
}

type signAccessPayload struct {
	Type  string `json:"type"`
	SID   string `json:"sid"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Exp   int64  `json:"exp"`
	Iss   string `json:"iss,omitempty"`
	Aud   string `json:"aud,omitempty"`
}

type signRefreshPayload struct {
	Type string `json:"type"`
	SID  string `json:"sid"`
	Sub  string `json:"sub"`
	Exp  int64  `json:"exp"`
	Iss  string `json:"iss,omitempty"`
	Aud  string `json:"aud,omitempty"`
}

func SignAccessToken(
	secret,
	issuer,
	audience,
	subject,
	email,
	role,
	sessionID string,
	expiresAt time.Time,
) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("jwt secret is empty")
	}
	if strings.TrimSpace(subject) == "" {
		return "", errors.New("jwt subject missing")
	}
	if strings.TrimSpace(sessionID) == "" {
		return "", errors.New("jwt sid missing")
	}
	if strings.TrimSpace(email) == "" {
		return "", errors.New("jwt email missing")
	}
	if strings.TrimSpace(role) == "" {
		return "", errors.New("jwt role missing")
	}

	headerRaw, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}

	payloadRaw, err := json.Marshal(signAccessPayload{
		Type:  "access",
		SID:   sessionID,
		Sub:   subject,
		Email: email,
		Role:  role,
		Exp:   expiresAt.Unix(),
		Iss:   issuer,
		Aud:   audience,
	})
	if err != nil {
		return "", err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerRaw)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadRaw)
	signingInput := headerEnc + "." + payloadEnc

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	signatureEnc := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureEnc, nil
}

func SignRefreshToken(
	secret,
	issuer,
	audience,
	subject,
	sessionID string,
	expiresAt time.Time,
) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("jwt secret is empty")
	}
	if strings.TrimSpace(subject) == "" {
		return "", errors.New("jwt subject missing")
	}
	if strings.TrimSpace(sessionID) == "" {
		return "", errors.New("jwt sid missing")
	}

	headerRaw, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}

	payloadRaw, err := json.Marshal(signRefreshPayload{
		Type: "refresh",
		SID:  sessionID,
		Sub:  subject,
		Exp:  expiresAt.Unix(),
		Iss:  issuer,
		Aud:  audience,
	})
	if err != nil {
		return "", err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerRaw)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadRaw)
	signingInput := headerEnc + "." + payloadEnc

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	signatureEnc := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureEnc, nil
}

func ValidateAccessToken(token, secret, expectedIssuer, expectedAudience string, now time.Time) (*AccessClaims, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("jwt secret is empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt malformed")
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("jwt signature decode failed")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return nil, errors.New("jwt signature mismatch")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt header decode failed")
	}

	var header jwtHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, errors.New("jwt header invalid")
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		return nil, fmt.Errorf("jwt alg %q not supported", header.Alg)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt payload decode failed")
	}

	decoder := json.NewDecoder(strings.NewReader(string(payloadRaw)))
	decoder.UseNumber()
	var payload jwtPayload
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("jwt payload invalid")
	}

	if payload.Type != "access" {
		return nil, errors.New("jwt claim type must be access")
	}
	if strings.TrimSpace(payload.Sub) == "" {
		return nil, errors.New("jwt sub missing")
	}
	if strings.TrimSpace(payload.SID) == "" {
		return nil, errors.New("jwt sid missing")
	}
	if strings.TrimSpace(payload.Email) == "" {
		return nil, errors.New("jwt email missing")
	}
	if strings.TrimSpace(payload.Role) == "" {
		return nil, errors.New("jwt role missing")
	}

	expUnix, err := payload.Exp.Int64()
	if err != nil || expUnix <= 0 {
		return nil, errors.New("jwt exp invalid")
	}

	exp := time.Unix(expUnix, 0)
	if !exp.After(now) {
		return nil, errors.New("jwt expired")
	}

	if expectedIssuer != "" && payload.Iss != expectedIssuer {
		return nil, errors.New("jwt issuer mismatch")
	}

	if expectedAudience != "" && !hasAudience(payload.Aud, expectedAudience) {
		return nil, errors.New("jwt audience mismatch")
	}

	return &AccessClaims{
		Subject:   payload.Sub,
		Email:     payload.Email,
		Role:      payload.Role,
		SessionID: payload.SID,
		ExpiresAt: exp.UTC(),
	}, nil
}

func ValidateRefreshToken(token, secret, expectedIssuer, expectedAudience string, now time.Time) (*RefreshClaims, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("jwt secret is empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt malformed")
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("jwt signature decode failed")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return nil, errors.New("jwt signature mismatch")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt header decode failed")
	}

	var header jwtHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, errors.New("jwt header invalid")
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		return nil, fmt.Errorf("jwt alg %q not supported", header.Alg)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt payload decode failed")
	}

	decoder := json.NewDecoder(strings.NewReader(string(payloadRaw)))
	decoder.UseNumber()
	var payload jwtPayload
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("jwt payload invalid")
	}

	if payload.Type != "refresh" {
		return nil, errors.New("jwt claim type must be refresh")
	}
	if strings.TrimSpace(payload.Sub) == "" {
		return nil, errors.New("jwt sub missing")
	}
	if strings.TrimSpace(payload.SID) == "" {
		return nil, errors.New("jwt sid missing")
	}

	expUnix, err := payload.Exp.Int64()
	if err != nil || expUnix <= 0 {
		return nil, errors.New("jwt exp invalid")
	}

	exp := time.Unix(expUnix, 0)
	if !exp.After(now) {
		return nil, errors.New("jwt expired")
	}

	if expectedIssuer != "" && payload.Iss != expectedIssuer {
		return nil, errors.New("jwt issuer mismatch")
	}

	if expectedAudience != "" && !hasAudience(payload.Aud, expectedAudience) {
		return nil, errors.New("jwt audience mismatch")
	}

	return &RefreshClaims{
		Subject:   payload.Sub,
		SessionID: payload.SID,
		ExpiresAt: exp.UTC(),
	}, nil
}

func hasAudience(rawAud any, expected string) bool {
	switch aud := rawAud.(type) {
	case string:
		return aud == expected
	case []any:
		for _, item := range aud {
			s, ok := item.(string)
			if ok && s == expected {
				return true
			}
		}
		return false
	default:
		return false
	}
}
