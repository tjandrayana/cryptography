package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// JWTModule implements JWT (JSON Web Token) token creation and verification.
// Note: JWT is a token format/standard (RFC 7519), not an encryption algorithm.
// This module creates JWS (JSON Web Signature) tokens - the payload is base64-encoded
// and signed with HMAC-SHA256, but NOT encrypted. Anyone can decode the payload;
// the signature only verifies authenticity and integrity.
type JWTModule struct {
	key string
}

// JWTClaims represents the JWT payload structure
type JWTClaims struct {
	Data      map[string]interface{} `json:"data,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	ExpiresAt int64                  `json:"exp,omitempty"`
}

// NewJWTModule creates a new JWT token module.
// The key is used for HMAC-SHA256 signing to verify token authenticity.
func NewJWTModule(key string) (*JWTModule, error) {
	if key == "" {
		return nil, fmt.Errorf("JWT secret key cannot be empty")
	}

	return &JWTModule{
		key: key,
	}, nil
}

// dataToMap converts data of any type to map[string]interface{}
func (j *JWTModule) dataToMap(data interface{}) (map[string]interface{}, error) {
	switch v := data.(type) {
	case map[string]interface{}:
		return v, nil
	case string:
		return map[string]interface{}{
			"message": v,
		}, nil
	default:
		// For structs and other types, convert to map via JSON
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data: %w", err)
		}
		var dataMap map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &dataMap); err != nil {
			return nil, fmt.Errorf("failed to convert data to map: %w", err)
		}
		return dataMap, nil
	}
}

// Encrypt creates a JWT (JWS) signed token from data of any type with context support.
// Note: This method is named "Encrypt" for interface compatibility, but it actually
// creates a SIGNED token (JWS), not an encrypted token (JWE). The payload is
// base64-encoded and signed with HMAC-SHA256 for authenticity/integrity verification.
// Supports TTL through TokenOptions (from cryptography package).
// If TTL is 0, the token will not expire.
// If TTL > 0, the token will expire after the specified duration.
func (j *JWTModule) Encrypt(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if data == nil {
		return "", fmt.Errorf("data cannot be nil")
	}

	// Convert data to map[string]interface{}
	dataMap, err := j.dataToMap(data)
	if err != nil {
		return "", err
	}

	// Extract TTL from options using reflection
	// Options should be *cryptography.TokenOptions
	var ttl time.Duration
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		// Try interface method first
		if optStruct, ok := opt.(interface{ GetTTL() time.Duration }); ok {
			ttl = optStruct.GetTTL()
			break
		}
		// Use reflection to extract TTL field from struct
		optVal := reflect.ValueOf(opt)
		if optVal.Kind() == reflect.Ptr {
			optVal = optVal.Elem()
		}
		if optVal.Kind() == reflect.Struct {
			ttlField := optVal.FieldByName("TTL")
			if ttlField.IsValid() && ttlField.Type() == reflect.TypeOf(time.Duration(0)) {
				// Safe type assertion with panic recovery
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Type assertion failed, continue to next option
						}
					}()
					if ttlVal, ok := ttlField.Interface().(time.Duration); ok {
						ttl = ttlVal
					}
				}()
				if ttl > 0 {
					break
				}
			}
		}
	}

	// Create JWT claims
	now := time.Now().Unix()
	claims := JWTClaims{
		Data:     dataMap,
		IssuedAt: now,
	}

	// Set expiration if TTL is provided
	if ttl > 0 {
		claims.ExpiresAt = now + int64(ttl.Seconds())
	}

	// Create header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature using HMAC-SHA256
	signature := j.createSignature(headerEncoded + "." + payloadEncoded)

	// Combine into JWT format
	token := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature)
	return token, nil
}

// Decrypt extracts and verifies data from a JWT token with context support.
// Note: This method is named "Decrypt" for interface compatibility, but it actually
// VERIFIES the token signature and extracts the payload. The payload is not encrypted,
// just base64-encoded. Anyone can decode it, but only those with the correct key can
// verify the signature.
// Returns the original data structure (map, string, etc.).
// Key is optional - if provided, uses that key instead of the module's default key.
func (j *JWTModule) Decrypt(ctx context.Context, ciphertext string, key ...string) (interface{}, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ciphertext == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// Use provided key or default to module's key
	decryptKey := j.key
	if len(key) > 0 && key[0] != "" {
		decryptKey = key[0]
	}

	// Validate that we have a key (either from parameter or module default)
	if decryptKey == "" {
		return nil, fmt.Errorf("verification key cannot be empty")
	}

	parts := strings.Split(ciphertext, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Safe array access with bounds checking
	headerEncoded := parts[0]
	payloadEncoded := parts[1]
	signature := parts[2]

	if headerEncoded == "" || payloadEncoded == "" || signature == "" {
		return nil, fmt.Errorf("invalid JWT format: empty parts")
	}

	// Verify signature with the provided key
	expectedSignature := j.createSignatureWithKey(headerEncoded+"."+payloadEncoded, decryptKey)
	if signature != expectedSignature {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Parse payload JSON
	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Check expiration
	if claims.ExpiresAt > 0 {
		now := time.Now().Unix()
		if now > claims.ExpiresAt {
			return nil, fmt.Errorf("token has expired")
		}
	}

	// Return the data
	if claims.Data == nil {
		return make(map[string]interface{}), nil
	}
	return claims.Data, nil
}

// createSignature creates HMAC-SHA256 signature using module's default key
func (j *JWTModule) createSignature(data string) string {
	return j.createSignatureWithKey(data, j.key)
}

// createSignatureWithKey creates HMAC-SHA256 signature with a specific key
func (j *JWTModule) createSignatureWithKey(data string, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signature
}

// Sign creates a signed JWT token with context support (implements Token interface).
// This is the proper method name for token standards.
func (j *JWTModule) Sign(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// Perform signing with context check
	done := make(chan struct{})
	var result string
	var err error

	go func() {
		result, err = j.Encrypt(ctx, data, opts...)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-done:
		return result, err
	}
}

// VerifyToken verifies the token signature with context support (implements Token interface).
// This is the proper method name for token standards.
func (j *JWTModule) VerifyToken(ctx context.Context, token string, key ...string) (interface{}, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Perform verification with context check
	done := make(chan struct{})
	var result interface{}
	var err error

	go func() {
		result, err = j.Decrypt(ctx, token, key...)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return result, err
	}
}

// Validate checks if the data matches the signed JWT token with context support (implements Token interface).
func (j *JWTModule) Validate(ctx context.Context, data interface{}, token string) (bool, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if data == nil {
		return false, fmt.Errorf("data cannot be nil")
	}
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Perform validation with context check
	done := make(chan struct{})
	var result bool
	var err error

	go func() {
		// Verify the token
		decrypted, verifyErr := j.VerifyToken(ctx, token)
		if verifyErr != nil {
			err = verifyErr
			close(done)
			return
		}

		// Convert data to map for comparison
		dataMap, mapErr := j.dataToMap(data)
		if mapErr != nil {
			err = mapErr
			close(done)
			return
		}

		// Compare with decrypted data
		decryptedMap, ok := decrypted.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("decrypted data is not a map")
			close(done)
			return
		}

		// Simple comparison - in production, you might want deeper comparison
		dataJSON, _ := json.Marshal(dataMap)
		decryptedJSON, _ := json.Marshal(decryptedMap)
		result = string(dataJSON) == string(decryptedJSON)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-done:
		return result, err
	}
}

// Verify checks if the data matches the signed JWT token with context support.
// This method implements the Encryption interface for compatibility.
// For new code using Token interface, use Validate() instead.
func (j *JWTModule) Verify(ctx context.Context, data interface{}, token string) (bool, error) {
	return j.Validate(ctx, data, token)
}
