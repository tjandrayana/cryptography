package cryptography_test

import (
	"context"
	"fmt"
	"time"

	"github.com/tjandrayana/cryptography"
)

// ExampleNewEncryption_AES demonstrates basic AES encryption and decryption
func ExampleNewEncryption_aes() {
	aesModule, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "my-secret-key-32-bytes-long!!")

	plaintext := "Hello, World!"
	encrypted, _ := aesModule.Encrypt(context.Background(), plaintext)
	decrypted, _ := aesModule.Decrypt(context.Background(), encrypted)

	if decryptedStr, ok := decrypted.(string); ok {
		fmt.Printf("Decrypted: %s\n", decryptedStr)
	}
	// Output:
	// Decrypted: Hello, World!
}

// ExampleNewToken_JWT demonstrates basic JWT token creation and verification
func ExampleNewToken_jwt() {
	jwtModule, _ := cryptography.NewToken(cryptography.TokenJWT, "my-jwt-secret-key")

	plaintext := "Hello, World!"
	token, _ := jwtModule.Sign(context.Background(), plaintext)
	decrypted, _ := jwtModule.VerifyToken(context.Background(), token)

	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		if message, ok := dataMap["message"].(string); ok {
			fmt.Printf("Decrypted message: %s\n", message)
		}
	}
	// Output:
	// Decrypted message: Hello, World!
}

// ExampleNewToken_JWT_StructuredData demonstrates JWT with structured data
func ExampleNewToken_jwtStructuredData() {
	jwtModule, _ := cryptography.NewToken(cryptography.TokenJWT, "my-jwt-secret-key")

	data := map[string]interface{}{
		"user_id":  12345,
		"username": "john_doe",
		"email":    "john@example.com",
	}

	token, _ := jwtModule.Sign(context.Background(), data)
	decrypted, _ := jwtModule.VerifyToken(context.Background(), token)

	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		fmt.Printf("User ID: %v\n", dataMap["user_id"])
		fmt.Printf("Username: %v\n", dataMap["username"])
	}
	// Output:
	// User ID: 12345
	// Username: john_doe
}

// ExampleNewToken_JWT_WithTTL demonstrates JWT with time-to-live
func ExampleNewToken_jwtWithTTL() {
	jwtModule, _ := cryptography.NewToken(cryptography.TokenJWT, "my-jwt-secret-key")

	data := map[string]interface{}{
		"user_id": 12345,
	}

	// Token expires in 1 hour
	token, _ := jwtModule.Sign(context.Background(), data, cryptography.WithTokenTTL(1*time.Hour))

	// Verify immediately (should work)
	decrypted, _ := jwtModule.VerifyToken(context.Background(), token)
	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		fmt.Printf("User ID: %v\n", dataMap["user_id"])
		fmt.Printf("Token valid: %v\n", dataMap["user_id"] != nil)
	}
	// Output:
	// User ID: 12345
	// Token valid: true
}

// ExampleNewEncryption_AES_StructuredData demonstrates AES encryption with structs
func ExampleNewEncryption_aesStructuredData() {
	aesModule, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "my-secret-key-32-bytes-long!!")

	type User struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	user := User{ID: 123, Username: "jane_doe", Email: "jane@example.com"}
	encrypted, _ := aesModule.Encrypt(context.Background(), user)
	decrypted, _ := aesModule.Decrypt(context.Background(), encrypted)

	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		fmt.Printf("ID: %v\n", dataMap["id"])
		fmt.Printf("Username: %v\n", dataMap["username"])
		fmt.Printf("Email: %v\n", dataMap["email"])
	}
	// Output:
	// ID: 123
	// Username: jane_doe
	// Email: jane@example.com
}

// ExampleNewEncryption_AES_KeyRotation demonstrates key rotation with AES
func ExampleNewEncryption_aesKeyRotation() {
	aesModule, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "original-key-32-bytes-long!!")

	// Encrypt with original key
	encrypted, _ := aesModule.Encrypt(context.Background(), "Secret message")

	// Decrypt with same key (default)
	decrypted1, _ := aesModule.Decrypt(context.Background(), encrypted)
	fmt.Printf("Decrypted with default key: %v\n", decrypted1)

	// Decrypt with different key (will fail)
	_, err := aesModule.Decrypt(context.Background(), encrypted, "different-key-32-bytes-long!!")
	if err != nil {
		fmt.Printf("Decrypt with different key failed: %v\n", err)
	}
	// Output:
	// Decrypted with default key: Secret message
	// Decrypt with different key failed: failed to decrypt: cipher: message authentication failed
}

// ExampleNewToken_JWT_KeyRotation demonstrates key rotation with JWT
func ExampleNewToken_jwtKeyRotation() {
	jwtModule, _ := cryptography.NewToken(cryptography.TokenJWT, "original-secret-key")

	// Sign with original key
	token, _ := jwtModule.Sign(context.Background(), "JWT message")

	// Verify with same key (default)
	decrypted1, _ := jwtModule.VerifyToken(context.Background(), token)
	fmt.Printf("Verified with default key: %v\n", decrypted1 != nil)

	// Verify with different key (will fail - invalid signature)
	_, err := jwtModule.VerifyToken(context.Background(), token, "different-secret-key")
	if err != nil {
		fmt.Printf("Verify with different key failed: %v\n", err)
	}
	// Output:
	// Verified with default key: true
	// Verify with different key failed: invalid signature
}

// ExampleNewHash_SHA256 demonstrates hash module usage
func ExampleNewHash_sha256() {
	// SHA-256 hash module
	hashModule, _ := cryptography.NewHash(cryptography.HashSHA256)

	data := "Hello, World!"
	hash, _ := hashModule.Hash(context.Background(), data)

	valid, _ := hashModule.Verify(context.Background(), data, hash)
	fmt.Printf("Hash length: %d\n", len(hash))
	fmt.Printf("Verification: %v\n", valid)
	// Output:
	// Hash length: 64
	// Verification: true
}

// ExampleNewHash_SHA512 demonstrates SHA-512 hashing
func ExampleNewHash_sha512() {
	hashModule, _ := cryptography.NewHash(cryptography.HashSHA512)

	data := "Hello, World!"
	hash, _ := hashModule.Hash(context.Background(), data)
	fmt.Printf("SHA-512 Hash length: %d\n", len(hash))

	valid, _ := hashModule.Verify(context.Background(), data, hash)
	fmt.Printf("Verification: %v\n", valid)
	// Output:
	// SHA-512 Hash length: 128
	// Verification: true
}

// ExampleNewBcrypt demonstrates bcrypt password hashing
func ExampleNewBcrypt() {
	hashModule, _ := cryptography.NewBcrypt(10)

	password := "mySecurePassword123"
	hash, _ := hashModule.Hash(context.Background(), password)

	valid, _ := hashModule.Verify(context.Background(), password, hash)
	if len(hash) >= 7 {
		fmt.Printf("Hash starts with: %s\n", hash[:7])
	} else {
		fmt.Printf("Hash: %s\n", hash)
	}
	fmt.Printf("Hash length: %d\n", len(hash))
	fmt.Printf("Verification: %v\n", valid)
	// Output:
	// Hash starts with: $2a$10$
	// Hash length: 60
	// Verification: true
}

// ExampleNewEncryption_Verify demonstrates verification functionality
func ExampleNewEncryption_verify() {
	aesModule, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "my-secret-key-32-bytes-long!!")

	data := "Hello, World!"
	encrypted, _ := aesModule.Encrypt(context.Background(), data)

	// Verify with correct data
	valid1, _ := aesModule.Verify(context.Background(), data, encrypted)
	fmt.Printf("Verify correct data: %v\n", valid1)

	// Verify with wrong data
	valid2, _ := aesModule.Verify(context.Background(), "Wrong data", encrypted)
	fmt.Printf("Verify wrong data: %v\n", valid2)
	// Output:
	// Verify correct data: true
	// Verify wrong data: false
}
