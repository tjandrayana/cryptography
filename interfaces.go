package cryptography

import "context"

// Encryption defines the interface for encryption algorithms.
// Encryption algorithms provide confidentiality - data is encrypted and cannot be read without the key.
// Examples: AES-256-GCM
type Encryption interface {
	Encrypt(ctx context.Context, data interface{}, opts ...interface{}) (string, error)
	Decrypt(ctx context.Context, ciphertext string, key ...string) (interface{}, error)
	Verify(ctx context.Context, data interface{}, encrypted string) (bool, error)
}

// Token defines the interface for token standards/formats.
// Token standards provide authenticity and integrity - verify data hasn't been tampered with.
// Examples: JWT (JSON Web Token - RFC 7519)
type Token interface {
	Sign(ctx context.Context, data interface{}, opts ...interface{}) (string, error)
	VerifyToken(ctx context.Context, token string, key ...string) (interface{}, error)
	Validate(ctx context.Context, data interface{}, token string) (bool, error)
}

// Hash defines the interface for hashing algorithms.
// Hashing algorithms provide one-way transformation - cannot be reversed.
// Examples: SHA-256, SHA-512, bcrypt
type Hash interface {
	Hash(ctx context.Context, data interface{}, opts ...interface{}) (string, error)
	Verify(ctx context.Context, data interface{}, hash string) (bool, error)
}
