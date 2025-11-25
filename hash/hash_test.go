package hash

import (
	"testing"
)

func TestNewHashModule(t *testing.T) {
	tests := []struct {
		name      string
		algorithm HashAlgorithm
		key       string
		wantErr   bool
	}{
		{
			name:      "SHA-256",
			algorithm: HashSHA256,
			key:       "",
			wantErr:   false,
		},
		{
			name:      "SHA-512",
			algorithm: HashSHA512,
			key:       "",
			wantErr:   false,
		},
		{
			name:      "empty algorithm defaults to SHA-256",
			algorithm: "",
			key:       "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := NewHashModule(tt.algorithm, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHashModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewHashModule() returned nil module without error")
			}
		})
	}
}

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

func TestHashModule_Encrypt_Verify_SHA256(t *testing.T) {
	module, err := NewHashModule(HashSHA256, "")
	if err != nil {
		t.Fatalf("Failed to create hash module: %v", err)
	}

	data := "Hello, World!"
	hash, err := module.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if hash == "" {
		t.Error("Encrypt() returned empty string")
	}

	// SHA-256 produces 64 character hex string
	if len(hash) != 64 {
		t.Errorf("Encrypt() returned hash of length %d, want 64", len(hash))
	}

	// Verify should succeed
	valid, err := module.Verify(data, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() returned false for correct data")
	}

	// Verify with wrong data should fail
	valid, err = module.Verify("wrong data", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() returned true for wrong data")
	}
}

func TestHashModule_Encrypt_Verify_SHA512(t *testing.T) {
	module, err := NewHashModule(HashSHA512, "")
	if err != nil {
		t.Fatalf("Failed to create hash module: %v", err)
	}

	data := "Hello, World!"
	hash, err := module.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// SHA-512 produces 128 character hex string
	if len(hash) != 128 {
		t.Errorf("Encrypt() returned hash of length %d, want 128", len(hash))
	}

	// Verify should succeed
	valid, err := module.Verify(data, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() returned false for correct data")
	}
}

func TestHashModule_Encrypt_Verify_Bcrypt(t *testing.T) {
	module, err := NewBcryptModule(10)
	if err != nil {
		t.Fatalf("Failed to create bcrypt module: %v", err)
	}

	password := "mySecurePassword123"
	hash, err := module.Encrypt(password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if hash == "" {
		t.Error("Encrypt() returned empty string")
	}

	// Bcrypt hash should start with $2a$ or $2b$
	if len(hash) < 10 {
		t.Error("Encrypt() returned hash that's too short")
	}

	// Verify should succeed
	valid, err := module.Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() returned false for correct password")
	}

	// Verify with wrong password should fail
	valid, err = module.Verify("wrongPassword", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() returned true for wrong password")
	}
}

func TestHashModule_Encrypt_DifferentDataTypes(t *testing.T) {
	module, err := NewHashModule(HashSHA256, "")
	if err != nil {
		t.Fatalf("Failed to create hash module: %v", err)
	}

	tests := []struct {
		name string
		data interface{}
	}{
		{
			name: "string",
			data: "test string",
		},
		{
			name: "map",
			data: map[string]interface{}{
				"key": "value",
			},
		},
		{
			name: "struct",
			data: struct {
				Name string `json:"name"`
			}{Name: "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := module.Encrypt(tt.data)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			if hash == "" {
				t.Error("Encrypt() returned empty string")
			}

			// Verify should succeed
			valid, err := module.Verify(tt.data, hash)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			if !valid {
				t.Error("Verify() returned false for correct data")
			}
		})
	}
}

func TestHashModule_Decrypt_ReturnsError(t *testing.T) {
	module, err := NewHashModule(HashSHA256, "")
	if err != nil {
		t.Fatalf("Failed to create hash module: %v", err)
	}

	hash, err := module.Encrypt("test")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decrypt should return error (hashing is one-way)
	_, err = module.Decrypt(hash)
	if err == nil {
		t.Error("Decrypt() should return error for hash module")
	}
}

func TestHashModule_ConsistentHashing(t *testing.T) {
	module, err := NewHashModule(HashSHA256, "")
	if err != nil {
		t.Fatalf("Failed to create hash module: %v", err)
	}

	data := "consistent test data"
	hash1, err := module.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	hash2, err := module.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Same input should produce same hash (deterministic)
	if hash1 != hash2 {
		t.Error("Encrypt() produces different hashes for same input")
	}
}

func TestHashModule_Bcrypt_DifferentHashes(t *testing.T) {
	module, err := NewBcryptModule(10)
	if err != nil {
		t.Fatalf("Failed to create bcrypt module: %v", err)
	}

	password := "testPassword"
	hash1, err := module.Encrypt(password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	hash2, err := module.Encrypt(password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Bcrypt should produce different hashes each time (due to salt)
	if hash1 == hash2 {
		t.Error("Bcrypt Encrypt() produces same hash for same input (should be different due to salt)")
	}

	// But both should verify correctly
	valid1, err := module.Verify(password, hash1)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	valid2, err := module.Verify(password, hash2)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid1 || !valid2 {
		t.Error("Verify() should succeed for both hashes")
	}
}

func TestHashModule_DataToBytes(t *testing.T) {
	module, err := NewHashModule(HashSHA256, "")
	if err != nil {
		t.Fatalf("Failed to create hash module: %v", err)
	}

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
	}{
		{
			name:    "string",
			data:    "test",
			wantErr: false,
		},
		{
			name:    "byte slice",
			data:    []byte("test"),
			wantErr: false,
		},
		{
			name:    "map",
			data:    map[string]interface{}{"key": "value"},
			wantErr: false,
		},
		{
			name: "struct",
			data: struct {
				Name string `json:"name"`
			}{Name: "test"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := module.dataToBytes(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("dataToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) == 0 {
				t.Error("dataToBytes() returned empty bytes")
			}
		})
	}
}

