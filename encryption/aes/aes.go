package aes

import (
	"context"
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

// Encrypt encrypts data of any type using AES-GCM with context support.
// Options are ignored for AES (TTL not applicable to symmetric encryption)
func (a *AESModule) Encrypt(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return "", err
	}

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

	// Perform encryption with context check
	done := make(chan struct{})
	var result string
	var err error

	go func() {
		// Create GCM mode
		gcm, gcmErr := cipher.NewGCM(a.block)
		if gcmErr != nil {
			err = fmt.Errorf("failed to create GCM: %w", gcmErr)
			close(done)
			return
		}

		// Create nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, nonceErr := io.ReadFull(rand.Reader, nonce); nonceErr != nil {
			err = fmt.Errorf("failed to generate nonce: %w", nonceErr)
			close(done)
			return
		}

		// Encrypt
		ciphertext := gcm.Seal(nonce, nonce, plaintextBytes, nil)

		// Encode to base64
		result = base64.StdEncoding.EncodeToString(ciphertext)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-done:
		return result, err
	}
}

// Decrypt decrypts ciphertext using AES-GCM with context support.
// Returns the decrypted data (string, map, etc. depending on what was encrypted)
// Key is optional - if provided, uses that key instead of the module's default key
func (a *AESModule) Decrypt(ctx context.Context, ciphertext string, key ...string) (interface{}, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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

	// Perform decryption with context check
	done := make(chan struct{})
	var result interface{}
	var err error

	go func() {
		// Derive 32-byte key using SHA-256 (same as encryption)
		keyBytes := prepareAESKey(decryptKey)

		// Create cipher block with the key
		block, blockErr := aes.NewCipher(keyBytes)
		if blockErr != nil {
			err = fmt.Errorf("failed to create AES cipher: %w", blockErr)
			close(done)
			return
		}

		// Decode from base64
		ciphertextBytes, decodeErr := base64.StdEncoding.DecodeString(ciphertext)
		if decodeErr != nil {
			err = fmt.Errorf("failed to decode base64: %w", decodeErr)
			close(done)
			return
		}

		// Create GCM mode
		gcm, gcmErr := cipher.NewGCM(block)
		if gcmErr != nil {
			err = fmt.Errorf("failed to create GCM: %w", gcmErr)
			close(done)
			return
		}

		// Extract nonce
		nonceSize := gcm.NonceSize()
		if len(ciphertextBytes) < nonceSize {
			err = fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", nonceSize, len(ciphertextBytes))
			close(done)
			return
		}

		nonce := make([]byte, nonceSize)
		copy(nonce, ciphertextBytes[:nonceSize])
		ciphertextBytes = ciphertextBytes[nonceSize:]

		// Decrypt
		plaintextBytes, decryptErr := gcm.Open(nil, nonce, ciphertextBytes, nil)
		if decryptErr != nil {
			err = fmt.Errorf("failed to decrypt: %w", decryptErr)
			close(done)
			return
		}

		// Try to unmarshal as JSON first (for structured data)
		var jsonData interface{}
		if unmarshalErr := json.Unmarshal(plaintextBytes, &jsonData); unmarshalErr == nil {
			result = jsonData
		} else {
			// If not JSON, return as string
			result = string(plaintextBytes)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return result, err
	}
}

// Verify checks if the data matches the encrypted value with context support.
// For encryption modules, this decrypts and compares with the original data
func (a *AESModule) Verify(ctx context.Context, data interface{}, encrypted string) (bool, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if data == nil {
		return false, fmt.Errorf("data cannot be nil")
	}
	if encrypted == "" {
		return false, fmt.Errorf("encrypted value cannot be empty")
	}

	// Perform verification with context check
	done := make(chan struct{})
	var result bool
	var err error

	go func() {
		// Decrypt the encrypted value
		decrypted, decryptErr := a.Decrypt(ctx, encrypted)
		if decryptErr != nil {
			err = decryptErr
			close(done)
			return
		}

		// Compare decrypted value with original data
		// Convert both to comparable format
		var dataStr string
		switch v := data.(type) {
		case string:
			dataStr = v
		default:
			// For other types, marshal to JSON for comparison
			jsonBytes, marshalErr := json.Marshal(v)
			if marshalErr != nil {
				err = fmt.Errorf("failed to marshal data: %w", marshalErr)
				close(done)
				return
			}
			dataStr = string(jsonBytes)
		}

		// Compare with decrypted value
		var decryptedStr string
		switch v := decrypted.(type) {
		case string:
			decryptedStr = v
		default:
			jsonBytes, marshalErr := json.Marshal(v)
			if marshalErr != nil {
				err = fmt.Errorf("failed to marshal decrypted data: %w", marshalErr)
				close(done)
				return
			}
			decryptedStr = string(jsonBytes)
		}

		result = dataStr == decryptedStr
		close(done)
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-done:
		return result, err
	}
}
