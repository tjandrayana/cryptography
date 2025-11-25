package cryptography_test

import (
	"testing"

	"github.com/tjandrayana/cryptography"
)

// TestPanicRecovery tests that the library handles panic scenarios gracefully
func TestPanicRecovery(t *testing.T) {
	t.Run("AES with nil data", func(t *testing.T) {
		module, err := cryptography.NewModule(cryptography.ModuleTypeAES, "test-key-12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// This should not panic, but return an error
		_, err = module.Encrypt(nil)
		if err == nil {
			t.Error("Expected error for nil data")
		}
	})

	t.Run("JWT with invalid token format", func(t *testing.T) {
		module, err := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")
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
			_, err := module.Decrypt(token)
			if err == nil {
				t.Errorf("Expected error for invalid token: %q", token)
			}
		}
	})

	t.Run("AES with empty ciphertext", func(t *testing.T) {
		module, err := cryptography.NewModule(cryptography.ModuleTypeAES, "test-key-12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		_, err = module.Decrypt("")
		if err == nil {
			t.Error("Expected error for empty ciphertext")
		}
	})

	t.Run("Hash with nil data", func(t *testing.T) {
		module, err := cryptography.NewModule(cryptography.ModuleTypeHash, "sha256")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// This should not panic
		_, err = module.Encrypt(nil)
		if err == nil {
			t.Error("Expected error for nil data")
		}
	})

	t.Run("JWT with empty key in decrypt uses default", func(t *testing.T) {
		module, err := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// Create a valid token
		token, err := module.Encrypt("test")
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Empty string in variadic should use module's default key (should work)
		decrypted, err := module.Decrypt(token, "")
		if err != nil {
			t.Errorf("Unexpected error when using default key: %v", err)
		}
		if decrypted == nil {
			t.Error("Expected decrypted data")
		}
	})

	t.Run("AES with empty key in decrypt uses default", func(t *testing.T) {
		module, err := cryptography.NewModule(cryptography.ModuleTypeAES, "test-key-12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create module: %v", err)
		}

		// Create a valid encrypted value
		encrypted, err := module.Encrypt("test")
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Empty string in variadic should use module's default key (should work)
		decrypted, err := module.Decrypt(encrypted, "")
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
	t.Run("JWT decrypt returns map safely", func(t *testing.T) {
		module, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")
		token, _ := module.Encrypt("test")

		decrypted, err := module.Decrypt(token)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
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
		module, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")

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
			_, err := module.Encrypt("test", opt)
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
		module, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")

		malformedTokens := []string{
			"",               // Empty
			".",              // One dot
			"..",             // Two dots, no content
			"header.",        // Missing parts
			".payload.",      // Missing parts
			"header.payload", // Missing signature
		}

		for _, token := range malformedTokens {
			_, err := module.Decrypt(token)
			if err == nil {
				t.Errorf("Expected error for malformed token: %q", token)
			}
			// Should not panic
		}
	})

	t.Run("AES with very short ciphertext", func(t *testing.T) {
		module, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "test-key-12345678901234567890")

		// Very short base64 strings that could cause bounds issues
		shortCiphertexts := []string{
			"",
			"a",
			"ab",
			"abc",
			"abcd",
		}

		for _, ct := range shortCiphertexts {
			_, err := module.Decrypt(ct)
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
		aesModule, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "test-key-12345678901234567890")
		jwtModule, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")
		hashModule, _ := cryptography.NewModule(cryptography.ModuleTypeHash, "sha256")

		// All should return errors, not panic
		_, err := aesModule.Verify(nil, "encrypted")
		if err == nil {
			t.Error("Expected error for nil data in AES Verify")
		}

		_, err = jwtModule.Verify(nil, "token")
		if err == nil {
			t.Error("Expected error for nil data in JWT Verify")
		}

		_, err = hashModule.Verify(nil, "hash")
		if err == nil {
			t.Error("Expected error for nil data in Hash Verify")
		}
	})

	t.Run("Verify with empty hash/token", func(t *testing.T) {
		aesModule, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "test-key-12345678901234567890")
		jwtModule, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "test-key")
		hashModule, _ := cryptography.NewModule(cryptography.ModuleTypeHash, "sha256")

		// All should return errors, not panic
		_, err := aesModule.Verify("data", "")
		if err == nil {
			t.Error("Expected error for empty encrypted value")
		}

		_, err = jwtModule.Verify("data", "")
		if err == nil {
			t.Error("Expected error for empty token")
		}

		_, err = hashModule.Verify("data", "")
		if err == nil {
			t.Error("Expected error for empty hash")
		}
	})
}
