package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// JWTModule implements JWT token encryption/decryption
type JWTModule struct {
	key string
}

// JWTClaims represents the JWT payload structure
type JWTClaims struct {
	Data      map[string]interface{} `json:"data,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	ExpiresAt int64                  `json:"exp,omitempty"`
}

// NewJWTModule creates a new JWT encryption module
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

// Encrypt creates a JWT token from data of any type
// Supports TTL through EncryptOptions (from cryptograhy package)
// If TTL is 0, the token will not expire
// If TTL > 0, the token will expire after the specified duration
func (j *JWTModule) Encrypt(data interface{}, opts ...interface{}) (string, error) {
	if data == nil {
		return "", fmt.Errorf("data cannot be nil")
	}

	// Convert data to map[string]interface{}
	dataMap, err := j.dataToMap(data)
	if err != nil {
		return "", err
	}

	// Extract TTL from options using reflection
	// Options should be *cryptograhy.EncryptOptions
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

// Decrypt extracts data from JWT token
// Returns the original data structure (map, string, etc.)
// Key is optional - if provided, uses that key instead of the module's default key
func (j *JWTModule) Decrypt(ciphertext string, key ...string) (interface{}, error) {
	if ciphertext == "" {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	// Use provided key or default to module's key
	decryptKey := j.key
	if len(key) > 0 && key[0] != "" {
		decryptKey = key[0]
	}

	// Validate that we have a key (either from parameter or module default)
	if decryptKey == "" {
		return nil, fmt.Errorf("decryption key cannot be empty")
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

// Verify checks if the data matches the encrypted JWT token
// For JWT modules, this decrypts the token and compares the data
func (j *JWTModule) Verify(data interface{}, token string) (bool, error) {
	if data == nil {
		return false, fmt.Errorf("data cannot be nil")
	}
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Decrypt the token
	decrypted, err := j.Decrypt(token)
	if err != nil {
		return false, err
	}

	// Convert data to map for comparison
	dataMap, err := j.dataToMap(data)
	if err != nil {
		return false, err
	}

	// Compare with decrypted data
	decryptedMap, ok := decrypted.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("decrypted data is not a map")
	}

	// Simple comparison - in production, you might want deeper comparison
	dataJSON, _ := json.Marshal(dataMap)
	decryptedJSON, _ := json.Marshal(decryptedMap)
	return string(dataJSON) == string(decryptedJSON), nil
}
