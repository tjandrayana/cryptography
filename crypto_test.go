package cryptography

import (
	"testing"
)

func TestNewModule_Hash_WithAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{
			name:      "sha256 algorithm",
			algorithm: "sha256",
			wantErr:   false,
		},
		{
			name:      "sha512 algorithm",
			algorithm: "sha512",
			wantErr:   false,
		},
		{
			name:      "bcrypt algorithm",
			algorithm: "bcrypt",
			wantErr:   false,
		},
		{
			name:      "empty algorithm defaults to sha256",
			algorithm: "",
			wantErr:   false,
		},
		{
			name:      "invalid algorithm",
			algorithm: "invalid",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := NewModule(ModuleTypeHash, tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewModule() returned nil module without error")
			}

			// Test that the module works
			if !tt.wantErr {
				hash, err := module.Encrypt("test")
				if err != nil {
					t.Errorf("Encrypt() error = %v", err)
				}
				if hash == "" {
					t.Error("Encrypt() returned empty string")
				}
			}
		})
	}
}

func TestNewModule_AES(t *testing.T) {
	module, err := NewModule(ModuleTypeAES, "test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("NewModule() error = %v", err)
	}

	if module == nil {
		t.Error("NewModule() returned nil module")
	}

	// Test that it works
	encrypted, err := module.Encrypt("test")
	if err != nil {
		t.Errorf("Encrypt() error = %v", err)
	}
	if encrypted == "" {
		t.Error("Encrypt() returned empty string")
	}
}

func TestNewModule_JWT(t *testing.T) {
	module, err := NewModule(ModuleTypeJWT, "test-secret-key")
	if err != nil {
		t.Fatalf("NewModule() error = %v", err)
	}

	if module == nil {
		t.Error("NewModule() returned nil module")
	}

	// Test that it works
	encrypted, err := module.Encrypt("test")
	if err != nil {
		t.Errorf("Encrypt() error = %v", err)
	}
	if encrypted == "" {
		t.Error("Encrypt() returned empty string")
	}
}

func TestNewModule_InvalidType(t *testing.T) {
	_, err := NewModule(ModuleType("invalid"), "key")
	if err == nil {
		t.Error("NewModule() should return error for invalid module type")
	}
}
