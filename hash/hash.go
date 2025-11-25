package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashAlgorithm represents the type of hash algorithm
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
	HashBcrypt HashAlgorithm = "bcrypt"
)

// HashModule implements one-way hashing
type HashModule struct {
	algorithm HashAlgorithm
	cost      int // For bcrypt
}

// NewHashModule creates a new hash module
// algorithm: "sha256", "sha512", or "bcrypt"
// key: not used for hashing, but kept for interface compatibility
// For bcrypt, you can use NewBcryptModule for cost configuration
func NewHashModule(algorithm HashAlgorithm, key string) (*HashModule, error) {
	cost := bcrypt.DefaultCost
	if algorithm == "" {
		algorithm = HashSHA256 // Default to SHA-256
	}

	return &HashModule{
		algorithm: algorithm,
		cost:      cost,
	}, nil
}

// NewBcryptModule creates a bcrypt hash module with custom cost
// cost: bcrypt cost factor (4-31, default is 10)
func NewBcryptModule(cost int) (*HashModule, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	return &HashModule{
		algorithm: HashBcrypt,
		cost:      cost,
	}, nil
}

// Encrypt creates a one-way hash of the data (for hash modules, Encrypt = Hash)
func (h *HashModule) Encrypt(data interface{}, opts ...interface{}) (string, error) {
	if data == nil {
		return "", fmt.Errorf("data cannot be nil")
	}

	// Convert data to bytes
	dataBytes, err := h.dataToBytes(data)
	if err != nil {
		return "", fmt.Errorf("failed to convert data to bytes: %w", err)
	}

	switch h.algorithm {
	case HashSHA256:
		hash := sha256.Sum256(dataBytes)
		return hex.EncodeToString(hash[:]), nil

	case HashSHA512:
		hash := sha512.Sum512(dataBytes)
		return hex.EncodeToString(hash[:]), nil

	case HashBcrypt:
		// Bcrypt only works with byte slices (typically passwords)
		hash, err := bcrypt.GenerateFromPassword(dataBytes, h.cost)
		if err != nil {
			return "", fmt.Errorf("failed to generate bcrypt hash: %w", err)
		}
		return string(hash), nil

	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", h.algorithm)
	}
}

// Decrypt returns an error for hash modules (hashing is one-way)
func (h *HashModule) Decrypt(ciphertext string, key ...string) (interface{}, error) {
	return nil, fmt.Errorf("cannot decrypt hash: hashing is a one-way operation")
}

// Verify checks if the data matches the hash
func (h *HashModule) Verify(data interface{}, hash string) (bool, error) {
	if data == nil {
		return false, fmt.Errorf("data cannot be nil")
	}
	if hash == "" {
		return false, fmt.Errorf("hash cannot be empty")
	}

	// Convert data to bytes
	dataBytes, err := h.dataToBytes(data)
	if err != nil {
		return false, fmt.Errorf("failed to convert data to bytes: %w", err)
	}

	switch h.algorithm {
	case HashSHA256:
		computedHash := sha256.Sum256(dataBytes)
		computedHashStr := hex.EncodeToString(computedHash[:])
		return computedHashStr == hash, nil

	case HashSHA512:
		computedHash := sha512.Sum512(dataBytes)
		computedHashStr := hex.EncodeToString(computedHash[:])
		return computedHashStr == hash, nil

	case HashBcrypt:
		err := bcrypt.CompareHashAndPassword([]byte(hash), dataBytes)
		return err == nil, nil

	default:
		return false, fmt.Errorf("unsupported hash algorithm: %s", h.algorithm)
	}
}

// dataToBytes converts data of any type to bytes
// Uses JSON marshaling for consistency with other modules
func (h *HashModule) dataToBytes(data interface{}) ([]byte, error) {
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
