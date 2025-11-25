package bcrypt

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptModule implements bcrypt password hashing
type BcryptModule struct {
	cost int
}

// NewBcryptModule creates a bcrypt hash module with custom cost
// cost: bcrypt cost factor (4-31, default is 10)
func NewBcryptModule(cost int) (*BcryptModule, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	return &BcryptModule{
		cost: cost,
	}, nil
}

// Hash performs one-way hashing of data with context support (implements Hash interface)
func (b *BcryptModule) Hash(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if data == nil {
		return "", fmt.Errorf("data cannot be nil")
	}

	// Perform hashing with context check
	done := make(chan struct{})
	var result string
	var err error

	go func() {
		// Convert data to bytes
		dataBytes, bytesErr := b.dataToBytes(data)
		if bytesErr != nil {
			err = fmt.Errorf("failed to convert data to bytes: %w", bytesErr)
			close(done)
			return
		}

		// Bcrypt only works with byte slices (typically passwords)
		hash, hashErr := bcrypt.GenerateFromPassword(dataBytes, b.cost)
		if hashErr != nil {
			err = fmt.Errorf("failed to generate bcrypt hash: %w", hashErr)
			close(done)
			return
		}
		result = string(hash)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-done:
		return result, err
	}
}

// Encrypt creates a one-way hash of the data using bcrypt with context support
// This method implements the Encryption interface for compatibility.
// For new code, use Hash() instead.
func (b *BcryptModule) Encrypt(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
	return b.Hash(ctx, data, opts...)
}

// Decrypt returns an error for hash modules (hashing is one-way)
func (b *BcryptModule) Decrypt(ctx context.Context, ciphertext string, key ...string) (interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("cannot decrypt hash: hashing is a one-way operation")
}

// Verify checks if the data matches the hash with context support
func (b *BcryptModule) Verify(ctx context.Context, data interface{}, hash string) (bool, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if data == nil {
		return false, fmt.Errorf("data cannot be nil")
	}
	if hash == "" {
		return false, fmt.Errorf("hash cannot be empty")
	}

	// Perform verification with context check
	done := make(chan struct{})
	var result bool
	var err error

	go func() {
		// Convert data to bytes
		dataBytes, bytesErr := b.dataToBytes(data)
		if bytesErr != nil {
			err = fmt.Errorf("failed to convert data to bytes: %w", bytesErr)
			close(done)
			return
		}

		compareErr := bcrypt.CompareHashAndPassword([]byte(hash), dataBytes)
		result = compareErr == nil
		close(done)
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-done:
		return result, err
	}
}

// dataToBytes converts data of any type to bytes
// Uses JSON marshaling for consistency with other modules
func (b *BcryptModule) dataToBytes(data interface{}) ([]byte, error) {
	switch v := data.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		// For other types, marshal to JSON for consistency
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data to JSON: %w", err)
		}
		return jsonBytes, nil
	}
}
