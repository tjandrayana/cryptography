package cryptography

import "time"

// TokenOptions holds optional configuration for token standards
type TokenOptions struct {
	TTL time.Duration // Time to live for the token (0 means no expiration)
}

// GetTTL returns the TTL value
func (t *TokenOptions) GetTTL() time.Duration {
	if t == nil {
		return 0
	}
	return t.TTL
}

// WithTokenTTL creates a TokenOptions with the specified TTL
func WithTokenTTL(ttl time.Duration) *TokenOptions {
	return &TokenOptions{TTL: ttl}
}
