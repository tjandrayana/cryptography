package cryptography

import (
	"context"
	"testing"
	"time"
)

func TestEncryption_ContextSupport(t *testing.T) {
	encryption, err := NewEncryption(EncryptionAES256GCM, "test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	t.Run("EncryptWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		encrypted, err := encryption.Encrypt(ctx, "test data")
		if err != nil {
			t.Fatalf("EncryptWithContext() error = %v", err)
		}
		if encrypted == "" {
			t.Error("EncryptWithContext() returned empty string")
		}
	})

	t.Run("EncryptWithContext with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := encryption.Encrypt(ctx, "test data")
		if err == nil {
			t.Error("EncryptWithContext() should return error for cancelled context")
		}
		if err != context.Canceled {
			t.Errorf("EncryptWithContext() error = %v, want context.Canceled", err)
		}
	})

	t.Run("DecryptWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// First encrypt
		encrypted, err := encryption.Encrypt(context.Background(), "test data")
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Then decrypt with context
		decrypted, err := encryption.Decrypt(ctx, encrypted)
		if err != nil {
			t.Fatalf("DecryptWithContext() error = %v", err)
		}
		if decrypted == nil {
			t.Error("DecryptWithContext() returned nil")
		}
	})

	t.Run("VerifyWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		data := "test data"
		encrypted, err := encryption.Encrypt(context.Background(), data)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		valid, err := encryption.Verify(ctx, data, encrypted)
		if err != nil {
			t.Fatalf("VerifyWithContext() error = %v", err)
		}
		if !valid {
			t.Error("VerifyWithContext() returned false for valid data")
		}
	})
}

func TestToken_ContextSupport(t *testing.T) {
	token, err := NewToken(TokenJWT, "test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	t.Run("SignWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		signed, err := token.Sign(ctx, "test data")
		if err != nil {
			t.Fatalf("SignWithContext() error = %v", err)
		}
		if signed == "" {
			t.Error("SignWithContext() returned empty string")
		}
	})

	t.Run("VerifyTokenWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// First sign
		signed, err := token.Sign(context.Background(), "test data")
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		// Then verify with context
		verified, err := token.VerifyToken(ctx, signed)
		if err != nil {
			t.Fatalf("VerifyTokenWithContext() error = %v", err)
		}
		if verified == nil {
			t.Error("VerifyTokenWithContext() returned nil")
		}
	})

	t.Run("ValidateWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		data := "test data"
		signed, err := token.Sign(context.Background(), data)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		valid, err := token.Validate(ctx, data, signed)
		if err != nil {
			t.Fatalf("ValidateWithContext() error = %v", err)
		}
		if !valid {
			t.Error("ValidateWithContext() returned false for valid data")
		}
	})
}

func TestHash_ContextSupport(t *testing.T) {
	hash, err := NewHash(HashSHA256)
	if err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}

	t.Run("HashWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		hashed, err := hash.Hash(ctx, "test data")
		if err != nil {
			t.Fatalf("HashWithContext() error = %v", err)
		}
		if hashed == "" {
			t.Error("HashWithContext() returned empty string")
		}
	})

	t.Run("VerifyWithContext with timeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		data := "test data"
		hashed, err := hash.Hash(context.Background(), data)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}

		valid, err := hash.Verify(ctx, data, hashed)
		if err != nil {
			t.Fatalf("VerifyWithContext() error = %v", err)
		}
		if !valid {
			t.Error("VerifyWithContext() returned false for valid data")
		}
	})

	t.Run("HashWithContext with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := hash.Hash(ctx, "test data")
		if err == nil {
			t.Error("HashWithContext() should return error for cancelled context")
		}
		if err != context.Canceled {
			t.Errorf("HashWithContext() error = %v, want context.Canceled", err)
		}
	})
}

func TestContextHelpers(t *testing.T) {
	t.Run("WithTimeout", func(t *testing.T) {
		ctx, cancel := WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Context should be valid initially
		if ctx.Err() != nil {
			t.Error("WithTimeout() created context with error")
		}

		// Wait for timeout
		time.Sleep(150 * time.Millisecond)

		// Context should be cancelled after timeout
		if ctx.Err() == nil {
			t.Error("WithTimeout() context should be cancelled after timeout")
		}
		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("WithTimeout() error = %v, want context.DeadlineExceeded", ctx.Err())
		}
	})

	t.Run("WithDeadline", func(t *testing.T) {
		deadline := time.Now().Add(100 * time.Millisecond)
		ctx, cancel := WithDeadline(context.Background(), deadline)
		defer cancel()

		// Context should be valid initially
		if ctx.Err() != nil {
			t.Error("WithDeadline() created context with error")
		}

		// Wait for deadline
		time.Sleep(150 * time.Millisecond)

		// Context should be cancelled after deadline
		if ctx.Err() == nil {
			t.Error("WithDeadline() context should be cancelled after deadline")
		}
	})

	t.Run("WithCancel", func(t *testing.T) {
		ctx, cancel := WithCancel(context.Background())

		// Context should be valid initially
		if ctx.Err() != nil {
			t.Error("WithCancel() created context with error")
		}

		// Cancel the context
		cancel()

		// Context should be cancelled
		if ctx.Err() == nil {
			t.Error("WithCancel() context should be cancelled after cancel()")
		}
		if ctx.Err() != context.Canceled {
			t.Errorf("WithCancel() error = %v, want context.Canceled", ctx.Err())
		}
	})
}

