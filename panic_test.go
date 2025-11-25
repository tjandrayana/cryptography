package cryptography_test

import (
	"context"
	"testing"

	"github.com/tjandrayana/cryptography"
)

// TestPanicRecovery tests that the library handles panic scenarios gracefully
func TestPanicRecovery(t *testing.T) {
	t.Run("AES with nil data", func(t *testing.T) {
		module, err := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "test-key-12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// This should not panic, but return an error
		_, err = module.Encrypt(context.Background(), nil)
		if err == nil {
			t.Error("Expected error for nil data")
		}
	})

	t.Run("JWT with invalid token format", func(t *testing.T) {
		module, err := cryptography.NewToken(cryptography.TokenJWT, "test-key")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// Test various invalid formats that could cause panic
		invalidTokens := []string{
			"",
			".",
			"..",
			"header.",
			".payload.",
			"header.payload",
			"header.payload.signature.extra",
		}

		for _, token := range invalidTokens {
			_, err := module.VerifyToken(context.Background(), token)
			if err == nil {
				t.Errorf("Expected error for invalid token: %q", token)
			}
		}
	})

	t.Run("AES with empty ciphertext", func(t *testing.T) {
		module, err := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "test-key-12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		_, err = module.Decrypt(context.Background(), "")
		if err == nil {
			t.Error("Expected error for empty ciphertext")
		}
	})

	t.Run("Hash with nil data", func(t *testing.T) {
		module, err := cryptography.NewHash(cryptography.HashSHA256)
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// This should not panic
		_, err = module.Hash(context.Background(), nil)
		if err == nil {
			t.Error("Expected error for nil data")
		}
	})

	t.Run("JWT with empty key in decrypt uses default", func(t *testing.T) {
		module, err := cryptography.NewToken(cryptography.TokenJWT, "test-key")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// Create a valid token
		token, err := module.Sign(context.Background(), "test")
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Empty string in variadic should use module's default key (should work)
		decrypted, err := module.VerifyToken(context.Background(), token, "")
		if err != nil {
			t.Errorf("Unexpected error when using default key: %v", err)
		}
		if decrypted == nil {
			t.Error("Expected decrypted data")
		}
	})

	t.Run("AES with empty key in decrypt uses default", func(t *testing.T) {
		module, err := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "test-key-12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// Create a valid encrypted value
		encrypted, err := module.Encrypt(context.Background(), "test")
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Empty string in variadic should use module's default key (should work)
		decrypted, err := module.Decrypt(context.Background(), encrypted, "")
		if err != nil {
			t.Errorf("Unexpected error when using default key: %v", err)
		}
		if decrypted == nil {
			t.Error("Expected decrypted data")
		}
	})
}

// TestTypeAssertionSafety tests safe type assertions
func TestTypeAssertionSafety(t *testing.T) {
	t.Run("JWT verify returns map safely", func(t *testing.T) {
		module, _ := cryptography.NewToken(cryptography.TokenJWT, "test-key")
		token, _ := module.Sign(context.Background(), "test")

		decrypted, err := module.VerifyToken(context.Background(), token)
		if err != nil {
			t.Fatalf("VerifyToken failed: %v", err)
		}

		// Safe type assertion
		dataMap, ok := decrypted.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected map, got %T", decrypted)
		}

		// Safe field access
		message, ok := dataMap["message"].(string)
		if !ok {
			t.Error("Expected message field to be string")
		}
		if message != "test" {
			t.Errorf("Expected 'test', got %q", message)
		}
	})
}

// TestReflectionSafety tests that reflection operations don't panic
func TestReflectionSafety(t *testing.T) {
	t.Run("JWT with invalid option types", func(t *testing.T) {
		module, _ := cryptography.NewToken(cryptography.TokenJWT, "test-key")

		// Test with various invalid option types that could cause reflection panics
		invalidOptions := []interface{}{
			nil,
			"not a struct",
			123,
			[]string{"invalid"},
			map[string]int{"invalid": 1},
		}

		for _, opt := range invalidOptions {
			// Should not panic, should just ignore invalid options
			_, err := module.Sign(context.Background(), "test", opt)
			if err != nil {
				// Error is acceptable, but panic is not
				continue
			}
			// No error is also fine - invalid options are ignored
		}
	})
}

// TestBoundsChecking tests array/slice bounds safety
func TestBoundsChecking(t *testing.T) {
	t.Run("JWT with malformed token parts", func(t *testing.T) {
		module, _ := cryptography.NewToken(cryptography.TokenJWT, "test-key")

		malformedTokens := []string{
			"",               // Empty
			".",              // One dot
			"..",             // Two dots, no content
			"header.",        // Missing parts
			".payload.",      // Missing parts
			"header.payload", // Missing signature
		}

		for _, token := range malformedTokens {
			_, err := module.VerifyToken(context.Background(), token)
			if err == nil {
				t.Errorf("Expected error for malformed token: %q", token)
			}
			// Should not panic
		}
	})

	t.Run("AES with very short ciphertext", func(t *testing.T) {
		module, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "test-key-12345678901234567890")

		// Very short base64 strings that could cause bounds issues
		shortCiphertexts := []string{
			"",
			"a",
			"ab",
			"abc",
			"abcd",
		}

		for _, ct := range shortCiphertexts {
			_, err := module.Decrypt(context.Background(), ct)
			if err == nil {
				t.Errorf("Expected error for short ciphertext: %q", ct)
			}
			// Should not panic
		}
	})
}

// TestNilPointerSafety tests nil pointer dereference prevention
func TestNilPointerSafety(t *testing.T) {
	t.Run("Verify with nil data", func(t *testing.T) {
		aesModule, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "test-key-12345678901234567890")
		jwtModule, _ := cryptography.NewToken(cryptography.TokenJWT, "test-key")
		hashModule, _ := cryptography.NewHash(cryptography.HashSHA256)

		// All should return errors, not panic
		_, err := aesModule.Verify(context.Background(), nil, "encrypted")
		if err == nil {
			t.Error("Expected error for nil data in AES Verify")
		}

		_, err = jwtModule.Validate(context.Background(), nil, "token")
		if err == nil {
			t.Error("Expected error for nil data in JWT Validate")
		}

		_, err = hashModule.Verify(context.Background(), nil, "hash")
		if err == nil {
			t.Error("Expected error for nil data in Hash Verify")
		}
	})

	t.Run("Verify with empty hash/token", func(t *testing.T) {
		aesModule, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "test-key-12345678901234567890")
		jwtModule, _ := cryptography.NewToken(cryptography.TokenJWT, "test-key")
		hashModule, _ := cryptography.NewHash(cryptography.HashSHA256)

		// All should return errors, not panic
		_, err := aesModule.Verify(context.Background(), "data", "")
		if err == nil {
			t.Error("Expected error for empty encrypted value")
		}

		_, err = jwtModule.Validate(context.Background(), "data", "")
		if err == nil {
			t.Error("Expected error for empty token")
		}

		_, err = hashModule.Verify(context.Background(), "data", "")
		if err == nil {
			t.Error("Expected error for empty hash")
		}
	})
}
