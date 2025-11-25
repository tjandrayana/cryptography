package cryptography

import (
	"fmt"

	"github.com/tjandrayana/cryptography/aes"
	"github.com/tjandrayana/cryptography/hash"
	"github.com/tjandrayana/cryptography/jwt"
)

// Cryptography defines the interface for encryption modules
type Cryptography interface {
	// Encrypt encrypts data of any type (string, map, struct, etc.)
	// Returns the encrypted/hashed string representation
	// Options can be *EncryptOptions or nil
	// For hash modules, this performs one-way hashing
	Encrypt(data interface{}, opts ...interface{}) (string, error)

	// Decrypt decrypts the ciphertext and returns the original data
	// The return type depends on what was encrypted (string, map, etc.)
	// Key is optional - if not provided, uses the module's default key
	// For hash modules, this returns an error (hashing is one-way)
	Decrypt(ciphertext string, key ...string) (interface{}, error)

	// Verify checks if the data matches the hash/encrypted value
	// Returns true if the data matches, false otherwise
	// For encryption modules, this verifies by decrypting and comparing
	// For hash modules, this verifies the hash directly
	Verify(data interface{}, hash string) (bool, error)
}

// ModuleType represents the type of encryption module
type ModuleType string

const (
	ModuleTypeAES  ModuleType = "aes"
	ModuleTypeJWT  ModuleType = "jwt"
	ModuleTypeHash ModuleType = "hash"
)

// NewModule creates a new encryption module based on the module type
// For hash modules, the key parameter is used as the algorithm name (sha256, sha512, bcrypt)
// If key is empty for hash modules, defaults to sha256
func NewModule(moduleType ModuleType, key string) (Cryptography, error) {
	switch moduleType {
	case ModuleTypeAES:
		return aes.NewAESModule(key)
	case ModuleTypeJWT:
		return jwt.NewJWTModule(key)
	case ModuleTypeHash:
		// Use key as algorithm name, or default to sha256 if empty
		return NewHashModule(key)
	default:
		return nil, fmt.Errorf("unsupported module type: %s", moduleType)
	}
}

// NewHashModule creates a hash module with a specific algorithm
// algorithm: "sha256" (default), "sha512", or "bcrypt"
func NewHashModule(algorithm string) (Cryptography, error) {
	var hashAlgo hash.HashAlgorithm
	switch algorithm {
	case "sha256", "":
		hashAlgo = hash.HashSHA256
	case "sha512":
		hashAlgo = hash.HashSHA512
	case "bcrypt":
		// Use default cost for bcrypt
		return hash.NewBcryptModule(10) // bcrypt.DefaultCost is 10
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s (supported: sha256, sha512, bcrypt)", algorithm)
	}
	return hash.NewHashModule(hashAlgo, "")
}

// NewBcryptModule creates a bcrypt hash module with custom cost
func NewBcryptModule(cost int) (Cryptography, error) {
	return hash.NewBcryptModule(cost)
}
