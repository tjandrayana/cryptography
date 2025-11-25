package cryptography

import (
	"context"
	"testing"
)

func TestNewHash_WithAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm HashAlgorithm
		wantErr   bool
	}{
		{
			name:      "sha256 algorithm",
			algorithm: HashSHA256,
			wantErr:   false,
		},
		{
			name:      "sha512 algorithm",
			algorithm: HashSHA512,
			wantErr:   false,
		},
		{
			name:      "bcrypt algorithm",
			algorithm: HashBcrypt,
			wantErr:   false,
		},
		{
			name:      "empty algorithm defaults to sha256",
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
			module, err := NewHash(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewHash() returned nil module without error")
			}

			// Test that the module works
			if !tt.wantErr {
				hash, err := module.Hash(context.Background(), "test")
				if err != nil {
					t.Errorf("Hash() error = %v", err)
				}
				if hash == "" {
					t.Error("Hash() returned empty string")
				}
			}
		})
	}
}

func TestNewEncryption_AES(t *testing.T) {
	module, err := NewEncryption(EncryptionAES256GCM, "test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("NewEncryption() error = %v", err)
	}

	if module == nil {
		t.Error("NewEncryption() returned nil module")
	}

	// Test that it works
	encrypted, err := module.Encrypt(context.Background(), "test")
	if err != nil {
		t.Errorf("Encrypt() error = %v", err)
	}
	if encrypted == "" {
		t.Error("Encrypt() returned empty string")
	}
}

func TestNewToken_JWT(t *testing.T) {
	module, err := NewToken(TokenJWT, "test-secret-key")
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}

	if module == nil {
		t.Error("NewToken() returned nil module")
	}

	// Test that it works
	token, err := module.Sign(context.Background(), "test")
	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}
	if token == "" {
		t.Error("Sign() returned empty string")
	}
}

func TestNewEncryption_InvalidAlgorithm(t *testing.T) {
	_, err := NewEncryption(EncryptionAlgorithm("invalid"), "key")
	if err == nil {
		t.Error("NewEncryption() should return error for invalid algorithm")
	}
}

func TestNewToken_InvalidStandard(t *testing.T) {
	_, err := NewToken(TokenStandard("invalid"), "key")
	if err == nil {
		t.Error("NewToken() should return error for invalid standard")
	}
}
