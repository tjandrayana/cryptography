package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// AESModule implements AES encryption
type AESModule struct {
	key   string
	block cipher.Block
}

// prepareAESKey derives a 32-byte key from the input key using SHA-256
// This ensures consistent key length and better security than zero-padding
func prepareAESKey(key string) []byte {
	// Use SHA-256 to derive a 32-byte key
	// This provides better security than zero-padding
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

// NewAESModule creates a new AES encryption module
func NewAESModule(key string) (*AESModule, error) {
	if key == "" {
		return nil, fmt.Errorf("AES key cannot be empty")
	}

	// Derive 32-byte key using SHA-256
	keyBytes := prepareAESKey(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESModule{
		key:   key,
		block: block,
	}, nil
}

// Encrypt encrypts data of any type using AES-GCM
// Options are ignored for AES (TTL not applicable to symmetric encryption)
func (a *AESModule) Encrypt(data interface{}, opts ...interface{}) (string, error) {
	if data == nil {
		return "", fmt.Errorf("data cannot be nil")
	}

	var plaintextBytes []byte

	// Convert data to bytes based on type
	switch v := data.(type) {
	case string:
		plaintextBytes = []byte(v)
	case []byte:
		plaintextBytes = v
	default:
		// For other types (maps, structs, etc.), marshal to JSON
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("failed to marshal data to JSON: %w", err)
		}
		plaintextBytes = jsonBytes
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintextBytes, nil)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
// Returns the decrypted data (string, map, etc. depending on what was encrypted)
// Key is optional - if provided, uses that key instead of the module's default key
func (a *AESModule) Decrypt(ciphertext string, key ...string) (interface{}, error) {
	if ciphertext == "" {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	// Use provided key or default to module's key
	decryptKey := a.key
	if len(key) > 0 && key[0] != "" {
		decryptKey = key[0]
	}

	// Validate that we have a key (either from parameter or module default)
	if decryptKey == "" {
		return nil, fmt.Errorf("decryption key cannot be empty")
	}

	// Derive 32-byte key using SHA-256 (same as encryption)
	keyBytes := prepareAESKey(decryptKey)

	// Create cipher block with the key
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Decode from base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Safe slice operations with bounds checking
	if len(ciphertextBytes) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", nonceSize, len(ciphertextBytes))
	}

	nonce := make([]byte, nonceSize)
	copy(nonce, ciphertextBytes[:nonceSize])
	ciphertextBytes = ciphertextBytes[nonceSize:]

	// Decrypt
	plaintextBytes, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Try to unmarshal as JSON first (for structured data)
	var jsonData interface{}
	if err := json.Unmarshal(plaintextBytes, &jsonData); err == nil {
		return jsonData, nil
	}

	// If not JSON, return as string
	return string(plaintextBytes), nil
}

// Verify checks if the data matches the encrypted value
// For encryption modules, this decrypts and compares with the original data
func (a *AESModule) Verify(data interface{}, encrypted string) (bool, error) {
	if data == nil {
		return false, fmt.Errorf("data cannot be nil")
	}
	if encrypted == "" {
		return false, fmt.Errorf("encrypted value cannot be empty")
	}

	// Decrypt the encrypted value
	decrypted, err := a.Decrypt(encrypted)
	if err != nil {
		return false, err
	}

	// Compare decrypted value with original data
	// Convert both to comparable format
	var dataStr string
	switch v := data.(type) {
	case string:
		dataStr = v
	default:
		// For other types, marshal to JSON for comparison
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return false, fmt.Errorf("failed to marshal data: %w", err)
		}
		dataStr = string(jsonBytes)
	}

	// Compare with decrypted value
	var decryptedStr string
	switch v := decrypted.(type) {
	case string:
		decryptedStr = v
	default:
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return false, fmt.Errorf("failed to marshal decrypted data: %w", err)
		}
		decryptedStr = string(jsonBytes)
	}

	return dataStr == decryptedStr, nil
}
