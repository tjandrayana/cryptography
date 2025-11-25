package sha

import (
	"context"
	"testing"
)

func TestNewSHAModule(t *testing.T) {
	tests := []struct {
		name      string
		algorithm HashAlgorithm
		wantErr   bool
	}{
		{
			name:      "SHA-256",
			algorithm: HashSHA256,
			wantErr:   false,
		},
		{
			name:      "SHA-512",
			algorithm: HashSHA512,
			wantErr:   false,
		},
		{
			name:      "empty algorithm defaults to SHA-256",
			algorithm: "",
			wantErr:   false,
		},
		{
			name:      "invalid algorithm",
			algorithm: HashAlgorithm("invalid"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := NewSHAModule(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSHAModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewSHAModule() returned nil module without error")
			}
		})
	}
}

func TestSHAModule_Hash_Verify_SHA256(t *testing.T) {
	module, err := NewSHAModule(HashSHA256)
	if err != nil {
		t.Fatalf("Failed to create SHA module: %v", err)
	}

	data := "Hello, World!"
	hash, err := module.Hash(context.Background(), data)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if hash == "" {
		t.Error("Hash() returned empty string")
	}

	// SHA-256 produces 64 character hex string
	if len(hash) != 64 {
		t.Errorf("Hash() returned hash of length %d, want 64", len(hash))
	}

	// Verify should succeed
	valid, err := module.Verify(context.Background(), data, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() returned false for correct data")
	}

	// Verify with wrong data should fail
	valid, err = module.Verify(context.Background(), "wrong data", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() returned true for wrong data")
	}
}

func TestSHAModule_Hash_Verify_SHA512(t *testing.T) {
	module, err := NewSHAModule(HashSHA512)
	if err != nil {
		t.Fatalf("Failed to create SHA module: %v", err)
	}

	data := "Hello, World!"
	hash, err := module.Hash(context.Background(), data)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// SHA-512 produces 128 character hex string
	if len(hash) != 128 {
		t.Errorf("Hash() returned hash of length %d, want 128", len(hash))
	}

	// Verify should succeed
	valid, err := module.Verify(context.Background(), data, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() returned false for correct data")
	}
}

func TestSHAModule_ConsistentHashing(t *testing.T) {
	module, err := NewSHAModule(HashSHA256)
	if err != nil {
		t.Fatalf("Failed to create SHA module: %v", err)
	}

	data := "consistent test data"
	hash1, err := module.Hash(context.Background(), data)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	hash2, err := module.Hash(context.Background(), data)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Same input should produce same hash (deterministic)
	if hash1 != hash2 {
		t.Error("Hash() produces different hashes for same input")
	}
}

func TestSHAModule_Decrypt_ReturnsError(t *testing.T) {
	module, err := NewSHAModule(HashSHA256)
	if err != nil {
		t.Fatalf("Failed to create SHA module: %v", err)
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
