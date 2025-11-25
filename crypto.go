package cryptography

import (
	"fmt"

	"github.com/tjandrayana/cryptography/encryption/aes"
	"github.com/tjandrayana/cryptography/hash/bcrypt"
	"github.com/tjandrayana/cryptography/hash/sha"
	"github.com/tjandrayana/cryptography/token/jwt"
)

// EncryptionAlgorithm represents encryption algorithm types
type EncryptionAlgorithm string

const (
	// EncryptionAES256GCM is the AES-256-GCM encryption algorithm
	EncryptionAES256GCM EncryptionAlgorithm = "aes-256-gcm"
)

// TokenStandard represents token standard/formats
type TokenStandard string

const (
	// TokenJWT is the JWT (JSON Web Token) standard (RFC 7519)
	TokenJWT TokenStandard = "jwt"
)

// HashAlgorithm represents hashing algorithm types
type HashAlgorithm string

const (
	// HashSHA256 is the SHA-256 hashing algorithm
	HashSHA256 HashAlgorithm = "sha256"
	// HashSHA512 is the SHA-512 hashing algorithm
	HashSHA512 HashAlgorithm = "sha512"
	// HashBcrypt is the bcrypt hashing algorithm
	HashBcrypt HashAlgorithm = "bcrypt"
)

// NewEncryption creates a new encryption algorithm module.
// Encryption algorithms provide confidentiality - data is encrypted and cannot be read without the key.
//
// Supported algorithms:
//   - EncryptionAES256GCM: AES-256-GCM encryption algorithm
//
// The key is used for encryption. For AES-256-GCM, the key is derived using SHA-256 to ensure 32-byte length.
func NewEncryption(algorithm EncryptionAlgorithm, key string) (Encryption, error) {
	switch algorithm {
	case EncryptionAES256GCM:
		return aes.NewAESModule(key)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// NewToken creates a new token standard module.
// Token standards provide authenticity and integrity - verify data hasn't been tampered with.
//
// Supported standards:
//   - TokenJWT: JWT (JSON Web Token) standard (RFC 7519) - creates JWS tokens
//
// The key is used for signing. For JWT, the key is used for HMAC-SHA256 signing.
func NewToken(standard TokenStandard, key string) (Token, error) {
	switch standard {
	case TokenJWT:
		return jwt.NewJWTModule(key)
	default:
		return nil, fmt.Errorf("unsupported token standard: %s", standard)
	}
}

// NewHash creates a new hashing algorithm module.
// Hashing algorithms provide one-way transformation - cannot be reversed.
//
// Supported algorithms:
//   - HashSHA256: SHA-256 hashing algorithm (default)
//   - HashSHA512: SHA-512 hashing algorithm
//   - HashBcrypt: bcrypt hashing algorithm (for passwords)
//
// If algorithm is empty, defaults to SHA-256.
func NewHash(algorithm HashAlgorithm) (Hash, error) {
	switch algorithm {
	case HashSHA256, "":
		return sha.NewSHAModule(sha.HashSHA256)
	case HashSHA512:
		return sha.NewSHAModule(sha.HashSHA512)
	case HashBcrypt:
		// Use default cost for bcrypt
		return bcrypt.NewBcryptModule(10) // bcrypt.DefaultCost is 10
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s (supported: sha256, sha512, bcrypt)", algorithm)
	}
}

// NewBcrypt creates a bcrypt hash module with custom cost.
// Bcrypt is specifically designed for password hashing.
//
// cost: bcrypt cost factor (4-31, default is 10)
func NewBcrypt(cost int) (Hash, error) {
	return bcrypt.NewBcryptModule(cost)
}
