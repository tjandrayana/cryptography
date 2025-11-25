package bcrypt

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewBcryptModule(t *testing.T) {
	tests := []struct {
		name    string
		cost    int
		wantErr bool
	}{
		{
			name:    "default cost",
			cost:    10,
			wantErr: false,
		},
		{
			name:    "min cost",
			cost:    4,
			wantErr: false,
		},
		{
			name:    "max cost",
			cost:    31,
			wantErr: false,
		},
		{
			name:    "cost too low",
			cost:    3,
			wantErr: true,
		},
		{
			name:    "cost too high",
			cost:    32,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := NewBcryptModule(tt.cost)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBcryptModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewBcryptModule() returned nil module without error")
			}
		})
	}
}

func TestBcryptModule_Hash_Verify(t *testing.T) {
	module, err := NewBcryptModule(10)
	if err != nil {
		t.Fatalf("Failed to create bcrypt module: %v", err)
	}

	password := "mySecurePassword123"
	hash, err := module.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if hash == "" {
		t.Error("Hash() returned empty string")
	}

	// Bcrypt hash should start with $2a$ or $2b$
	if len(hash) < 10 {
		t.Error("Hash() returned hash that's too short")
	}

	// Verify should succeed
	valid, err := module.Verify(context.Background(), password, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() returned false for correct password")
	}

	// Verify with wrong password should fail
	valid, err = module.Verify(context.Background(), "wrongPassword", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() returned true for wrong password")
	}
}

func TestBcryptModule_DifferentHashes(t *testing.T) {
	module, err := NewBcryptModule(10)
	if err != nil {
		t.Fatalf("Failed to create bcrypt module: %v", err)
	}

	password := "testPassword"
	hash1, err := module.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	hash2, err := module.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Bcrypt should produce different hashes each time (due to salt)
	if hash1 == hash2 {
		t.Error("Bcrypt Hash() produces same hash for same input (should be different due to salt)")
	}

	// But both should verify correctly
	valid1, err := module.Verify(context.Background(), password, hash1)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	valid2, err := module.Verify(context.Background(), password, hash2)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid1 || !valid2 {
		t.Error("Verify() should succeed for both hashes")
	}
}

func TestBcryptModule_Decrypt_ReturnsError(t *testing.T) {
	module, err := NewBcryptModule(10)
	if err != nil {
		t.Fatalf("Failed to create bcrypt module: %v", err)
	}

	hash, err := module.Hash(context.Background(), "test")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Decrypt should return error (hashing is one-way)
	_, err = module.Decrypt(context.Background(), hash)
	if err == nil {
		t.Error("Decrypt() should return error for hash module")
	}
}

func TestBcryptModule_Verify_WithBcryptHash(t *testing.T) {
	module, err := NewBcryptModule(10)
	if err != nil {
		t.Fatalf("Failed to create bcrypt module: %v", err)
	}

	password := "testPassword"
	// Generate hash using standard bcrypt library
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash: %v", err)
	}

	// Our module should be able to verify standard bcrypt hashes
	valid, err := module.Verify(context.Background(), password, string(bcryptHash))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() should succeed with standard bcrypt hash")
	}
}
