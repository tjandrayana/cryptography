package sha

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HashAlgorithm represents the type of SHA hash algorithm
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
)

// SHAModule implements SHA-256 and SHA-512 hashing
type SHAModule struct {
	algorithm HashAlgorithm
}

// NewSHAModule creates a new SHA hash module
// algorithm: "sha256" or "sha512"
func NewSHAModule(algorithm HashAlgorithm) (*SHAModule, error) {
	if algorithm == "" {
		algorithm = HashSHA256 // Default to SHA-256
	}

	if algorithm != HashSHA256 && algorithm != HashSHA512 {
		return nil, fmt.Errorf("unsupported SHA algorithm: %s (supported: sha256, sha512)", algorithm)
	}

	return &SHAModule{
		algorithm: algorithm,
	}, nil
}

// Hash performs one-way hashing of data with context support (implements Hash interface)
func (s *SHAModule) Hash(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
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
		dataBytes, bytesErr := s.dataToBytes(data)
		if bytesErr != nil {
			err = fmt.Errorf("failed to convert data to bytes: %w", bytesErr)
			close(done)
			return
		}

		switch s.algorithm {
		case HashSHA256:
			hash := sha256.Sum256(dataBytes)
			result = hex.EncodeToString(hash[:])
		case HashSHA512:
			hash := sha512.Sum512(dataBytes)
			result = hex.EncodeToString(hash[:])
		default:
			err = fmt.Errorf("unsupported hash algorithm: %s", s.algorithm)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-done:
		return result, err
	}
}

// Encrypt creates a one-way hash of the data with context support (for hash modules, Encrypt = Hash)
// This method implements the Encryption interface for compatibility.
// For new code, use Hash() instead.
func (s *SHAModule) Encrypt(ctx context.Context, data interface{}, opts ...interface{}) (string, error) {
	return s.Hash(ctx, data, opts...)
}

// Decrypt returns an error for hash modules (hashing is one-way)
func (s *SHAModule) Decrypt(ctx context.Context, ciphertext string, key ...string) (interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("cannot decrypt hash: hashing is a one-way operation")
}

// Verify checks if the data matches the hash with context support
func (s *SHAModule) Verify(ctx context.Context, data interface{}, hash string) (bool, error) {
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
		dataBytes, bytesErr := s.dataToBytes(data)
		if bytesErr != nil {
			err = fmt.Errorf("failed to convert data to bytes: %w", bytesErr)
			close(done)
			return
		}

		switch s.algorithm {
		case HashSHA256:
			computedHash := sha256.Sum256(dataBytes)
			computedHashStr := hex.EncodeToString(computedHash[:])
			result = computedHashStr == hash
		case HashSHA512:
			computedHash := sha512.Sum512(dataBytes)
			computedHashStr := hex.EncodeToString(computedHash[:])
			result = computedHashStr == hash
		default:
			err = fmt.Errorf("unsupported hash algorithm: %s", s.algorithm)
		}
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
func (s *SHAModule) dataToBytes(data interface{}) ([]byte, error) {
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
