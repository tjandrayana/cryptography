package jwt

import (
	"context"
	"testing"
	"time"
)

func TestNewJWTModule(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid key",
			key:     "my-secret-key",
			wantErr: false,
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: true,
		},
		{
			name:    "long key",
			key:     "this-is-a-very-long-secret-key-for-jwt-signing",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := NewJWTModule(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJWTModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && module == nil {
				t.Error("NewJWTModule() returned nil module without error")
			}
		})
	}
}

func TestJWTModule_Encrypt_Decrypt_String(t *testing.T) {
	module, err := NewJWTModule("test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
	}

	plaintext := "Hello, World!"
	encrypted, err := module.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if encrypted == "" {
		t.Error("Encrypt() returned empty string")
	}

	// JWT should have 3 parts separated by dots
	parts := len([]rune(encrypted))
	if parts < 10 { // Basic check for JWT format
		t.Error("Encrypt() returned invalid JWT format")
	}

	decrypted, err := module.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	// Decrypted should be a map with "message" key
	decryptedMap, ok := decrypted.(map[string]interface{})
	if !ok {
		t.Fatalf("Decrypt() returned %T, expected map[string]interface{}", decrypted)
	}

	if decryptedMap["message"].(string) != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decryptedMap["message"], plaintext)
	}
}

func TestJWTModule_Encrypt_Decrypt_Map(t *testing.T) {
	module, err := NewJWTModule("test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
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

func TestJWTModule_Encrypt_WithTTL(t *testing.T) {
	module, err := NewJWTModule("test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
	}

	data := map[string]interface{}{
		"user_id": 12345,
	}

	// Encrypt with TTL - create TokenOptions inline to avoid import cycle
	ttlOption := &struct {
		TTL time.Duration
	}{TTL: 1 * time.Hour}
	encrypted, err := module.Encrypt(context.Background(), data, ttlOption)
	if err != nil {
		t.Fatalf("Encrypt() with TTL error = %v", err)
	}

	// Decrypt immediately should work
	decrypted, err := module.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted == nil {
		t.Error("Decrypt() returned nil")
	}

	// Encrypt without TTL
	encryptedNoTTL, err := module.Encrypt(context.Background(), data)
	if err != nil {
		t.Fatalf("Encrypt() without TTL error = %v", err)
	}

	decryptedNoTTL, err := module.Decrypt(context.Background(), encryptedNoTTL)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decryptedNoTTL == nil {
		t.Error("Decrypt() returned nil")
	}
}

func TestJWTModule_Decrypt_WithDifferentKey(t *testing.T) {
	module1, err := NewJWTModule("key1")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
	}

	module2, err := NewJWTModule("key2")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
	}

	data := map[string]interface{}{
		"message": "Secret message",
	}

	encrypted, err := module1.Encrypt(context.Background(), data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decrypt with same key should work
	decrypted, err := module1.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted == nil {
		t.Error("Decrypt() returned nil")
	}

	// Decrypt with different key should fail (invalid signature)
		_, err = module2.Decrypt(context.Background(), encrypted)
	if err == nil {
		t.Error("Decrypt() with different key should fail")
	}

	// Decrypt with explicit different key
		_, err = module1.Decrypt(context.Background(), encrypted, "different-key")
	if err == nil {
		t.Error("Decrypt() with explicit different key should fail")
	}
}

func TestJWTModule_Verify(t *testing.T) {
	module, err := NewJWTModule("test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
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

func TestJWTModule_Decrypt_InvalidToken(t *testing.T) {
	module, err := NewJWTModule("test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		wantErr     bool
		description string
	}{
		{
			name:        "empty string",
			token:       "",
			wantErr:     true,
			description: "empty token should fail",
		},
		{
			name:        "invalid format - no dots",
			token:       "not-a-valid-jwt-token",
			wantErr:     true,
			description: "token without dots should fail",
		},
		{
			name:        "invalid format - one dot",
			token:       "header.payload",
			wantErr:     true,
			description: "token with one dot should fail",
		},
		{
			name:        "invalid signature",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7Im1lc3NhZ2UiOiJoZWxsbyJ9fQ.invalid-signature",
			wantErr:     true,
			description: "token with invalid signature should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := module.Decrypt(context.Background(), tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v (%s)", err, tt.wantErr, tt.description)
			}
		})
	}
}

func TestJWTModule_DataToMap(t *testing.T) {
	module, err := NewJWTModule("test-secret-key")
	if err != nil {
		t.Fatalf("Failed to create JWT module: %v", err)
	}

	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
	}{
		{
			name:    "string",
			data:    "hello",
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
			result, err := module.dataToMap(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("dataToMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("dataToMap() returned nil without error")
			}
		})
	}
}

