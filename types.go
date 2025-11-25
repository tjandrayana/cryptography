package cryptography

import "time"

// EncryptOptions holds optional configuration for encryption
type EncryptOptions struct {
	TTL time.Duration // Time to live for the encrypted data (0 means no expiration)
}

// GetTTL returns the TTL value (for interface compatibility)
func (e *EncryptOptions) GetTTL() time.Duration {
	if e == nil {
		return 0
	}
	return e.TTL
}

// WithTTL creates an EncryptOptions with the specified TTL
func WithTTL(ttl time.Duration) *EncryptOptions {
	return &EncryptOptions{TTL: ttl}
}
