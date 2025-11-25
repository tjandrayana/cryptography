package aes

import (
	"context"
	"testing"
)

func TestNewAESModule(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid key",
			key:     "my-secret-key-12345678901234567890",
			wantErr: false,
		},
		{
			name:    "short key",
			key:     "short",
			wantErr: false, // Should derive key using SHA-256
		},
		{
			name:    "long key",
			key:     "this-is-a-very-long-key-that-exceeds-32-bytes-and-should-be-handled-properly",
			wantErr: false, // Should derive key using SHA-256
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := NewAESModule(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAESModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewAESModule() returned nil module without error")
			}
		})
	}
}

func TestAESModule_Encrypt_Decrypt_String(t *testing.T) {
	module, err := NewAESModule("test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	plaintext := "Hello, World!"
	encrypted, err := module.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if encrypted == "" {
		t.Error("Encrypt() returned empty string")
	}

	if encrypted == plaintext {
		t.Error("Encrypt() returned plaintext instead of encrypted data")
	}

	decrypted, err := module.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	decryptedStr, ok := decrypted.(string)
	if !ok {
		t.Fatalf("Decrypt() returned %T, expected string", decrypted)
	}

	if decryptedStr != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decryptedStr, plaintext)
	}
}

func TestAESModule_Encrypt_Decrypt_Map(t *testing.T) {
	module, err := NewAESModule("test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	data := map[string]interface{}{
		"user_id":  12345,
		"username": "john_doe",
		"email":    "john@example.com",
	}

	encrypted, err := module.Encrypt(context.Background(), data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := module.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	decryptedMap, ok := decrypted.(map[string]interface{})
	if !ok {
		t.Fatalf("Decrypt() returned %T, expected map[string]interface{}", decrypted)
	}

	if decryptedMap["user_id"].(float64) != 12345 {
		t.Errorf("Decrypt() user_id = %v, want %v", decryptedMap["user_id"], 12345)
	}

	if decryptedMap["username"].(string) != "john_doe" {
		t.Errorf("Decrypt() username = %v, want %v", decryptedMap["username"], "john_doe")
	}
}

func TestAESModule_Encrypt_Decrypt_Struct(t *testing.T) {
	module, err := NewAESModule("test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	type User struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	user := User{ID: 123, Username: "jane_doe", Email: "jane@example.com"}

	encrypted, err := module.Encrypt(context.Background(), user)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := module.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	// Decrypted should be a map (JSON unmarshaled)
	decryptedMap, ok := decrypted.(map[string]interface{})
	if !ok {
		t.Fatalf("Decrypt() returned %T, expected map[string]interface{}", decrypted)
	}

	if decryptedMap["id"].(float64) != 123 {
		t.Errorf("Decrypt() id = %v, want %v", decryptedMap["id"], 123)
	}
}

func TestAESModule_Decrypt_WithDifferentKey(t *testing.T) {
	module1, err := NewAESModule("key1-1234567890123456789012")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	module2, err := NewAESModule("key2-1234567890123456789012")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	plaintext := "Secret message"
	encrypted, err := module1.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decrypt with same key (default)
	decrypted, err := module1.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted.(string) != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}

	// Decrypt with different key should fail
	_, err = module2.Decrypt(context.Background(), encrypted)
	if err == nil {
		t.Error("Decrypt() with different key should fail")
	}

	// Decrypt with explicit different key
	_, err = module1.Decrypt(context.Background(), encrypted, "different-key-1234567890123456")
	if err == nil {
		t.Error("Decrypt() with explicit different key should fail")
	}
}

func TestAESModule_Verify(t *testing.T) {
	module, err := NewAESModule("test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	tests := []struct {
		name     string
		data     interface{}
		wantTrue bool
	}{
		{
			name:     "string data",
			data:     "Hello, World!",
			wantTrue: true,
		},
		{
			name: "map data",
			data: map[string]interface{}{
				"key": "value",
			},
			wantTrue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := module.Encrypt(context.Background(), tt.data)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			valid, err := module.Verify(context.Background(), tt.data, encrypted)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			if valid != tt.wantTrue {
				t.Errorf("Verify() = %v, want %v", valid, tt.wantTrue)
			}

			// Verify with wrong data should fail
			wrongData := "wrong data"
			valid, err = module.Verify(context.Background(), wrongData, encrypted)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			if valid {
				t.Error("Verify() with wrong data should return false")
			}
		})
	}
}

func TestAESModule_Decrypt_InvalidCiphertext(t *testing.T) {
	module, err := NewAESModule("test-key-12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create AES module: %v", err)
	}

	tests := []struct {
		name        string
		ciphertext  string
		wantErr     bool
		description string
	}{
		{
			name:        "empty string",
			ciphertext:  "",
			wantErr:     true,
			description: "empty ciphertext should fail",
		},
		{
			name:        "invalid base64",
			ciphertext:  "not-valid-base64!!!",
			wantErr:     true,
			description: "invalid base64 should fail",
		},
		{
			name:        "too short",
			ciphertext:  "dG9vX3Nob3J0",
			wantErr:     true,
			description: "ciphertext too short should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := module.Decrypt(context.Background(), tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v (%s)", err, tt.wantErr, tt.description)
			}
		})
	}
}

func TestPrepareAESKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		wantLen  int
		wantSame bool // Same key should produce same result
	}{
		{
			name:     "short key",
			key:      "short",
			wantLen:  32,
			wantSame: true,
		},
		{
			name:     "exact 32 bytes",
			key:      "12345678901234567890123456789012",
			wantLen:  32,
			wantSame: true,
		},
		{
			name:     "long key",
			key:      "this-is-a-very-long-key-that-exceeds-32-bytes",
			wantLen:  32,
			wantSame: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := prepareAESKey(tt.key)
			key2 := prepareAESKey(tt.key)

			if len(key1) != tt.wantLen {
				t.Errorf("prepareAESKey() length = %v, want %v", len(key1), tt.wantLen)
			}

			if tt.wantSame {
				// Same input should produce same output
				for i := range key1 {
					if key1[i] != key2[i] {
						t.Errorf("prepareAESKey() produces different results for same input")
						break
					}
				}
			}
		})
	}
}

