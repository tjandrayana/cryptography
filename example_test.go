package cryptography_test

import (
	"fmt"
	"time"

	"github.com/tjandrayana/cryptography"
)

// ExampleNewModule_AES demonstrates basic AES encryption and decryption
func ExampleNewModule_aes() {
	aesModule, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "my-secret-key-32-bytes-long!!")

	plaintext := "Hello, World!"
	encrypted, _ := aesModule.Encrypt(plaintext)
	decrypted, _ := aesModule.Decrypt(encrypted)

	if decryptedStr, ok := decrypted.(string); ok {
		fmt.Printf("Decrypted: %s\n", decryptedStr)
	}
	// Output:
	// Decrypted: Hello, World!
}

// ExampleNewModule_JWT demonstrates basic JWT token creation and decryption
func ExampleNewModule_jwt() {
	jwtModule, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "my-jwt-secret-key")

	plaintext := "Hello, World!"
	encrypted, _ := jwtModule.Encrypt(plaintext)
	decrypted, _ := jwtModule.Decrypt(encrypted)

	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		if message, ok := dataMap["message"].(string); ok {
			fmt.Printf("Decrypted message: %s\n", message)
		}
	}
	// Output:
	// Decrypted message: Hello, World!
}

// ExampleNewModule_JWT_StructuredData demonstrates JWT with structured data
func ExampleNewModule_jwtStructuredData() {
	jwtModule, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "my-jwt-secret-key")

	data := map[string]interface{}{
		"user_id":  12345,
		"username": "john_doe",
		"email":    "john@example.com",
	}

	token, _ := jwtModule.Encrypt(data)
	decrypted, _ := jwtModule.Decrypt(token)

	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		fmt.Printf("User ID: %v\n", dataMap["user_id"])
		fmt.Printf("Username: %v\n", dataMap["username"])
	}
	// Output:
	// User ID: 12345
	// Username: john_doe
}

// ExampleNewModule_JWT_WithTTL demonstrates JWT with time-to-live
func ExampleNewModule_jwtWithTTL() {
	jwtModule, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "my-jwt-secret-key")

	data := map[string]interface{}{
		"user_id": 12345,
	}

	// Token expires in 1 hour
	token, _ := jwtModule.Encrypt(data, cryptography.WithTTL(1*time.Hour))

	// Decrypt immediately (should work)
	decrypted, _ := jwtModule.Decrypt(token)
	if dataMap, ok := decrypted.(map[string]interface{}); ok {
		fmt.Printf("User ID: %v\n", dataMap["user_id"])
		fmt.Printf("Token valid: %v\n", dataMap["user_id"] != nil)
	}
	// Output:
	// User ID: 12345
	// Token valid: true
}

// ExampleNewModule_AES_StructuredData demonstrates AES encryption with structs
func ExampleNewModule_aesStructuredData() {
	aesModule, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "my-secret-key-32-bytes-long!!")

	type User struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	user := User{ID: 123, Username: "jane_doe", Email: "jane@example.com"}
	encrypted, _ := aesModule.Encrypt(user)
	decrypted, _ := aesModule.Decrypt(encrypted)

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

// ExampleNewModule_AES_KeyRotation demonstrates key rotation with AES
func ExampleNewModule_aesKeyRotation() {
	aesModule, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "original-key-32-bytes-long!!")

	// Encrypt with original key
	encrypted, _ := aesModule.Encrypt("Secret message")

	// Decrypt with same key (default)
	decrypted1, _ := aesModule.Decrypt(encrypted)
	fmt.Printf("Decrypted with default key: %v\n", decrypted1)

	// Decrypt with different key (will fail)
	_, err := aesModule.Decrypt(encrypted, "different-key-32-bytes-long!!")
	if err != nil {
		fmt.Printf("Decrypt with different key failed: %v\n", err)
	}
	// Output:
	// Decrypted with default key: Secret message
	// Decrypt with different key failed: failed to decrypt: cipher: message authentication failed
}

// ExampleNewModule_JWT_KeyRotation demonstrates key rotation with JWT
func ExampleNewModule_jwtKeyRotation() {
	jwtModule, _ := cryptography.NewModule(cryptography.ModuleTypeJWT, "original-secret-key")

	// Encrypt with original key
	token, _ := jwtModule.Encrypt("JWT message")

	// Decrypt with same key (default)
	decrypted1, _ := jwtModule.Decrypt(token)
	fmt.Printf("Decrypted with default key: %v\n", decrypted1 != nil)

	// Decrypt with different key (will fail - invalid signature)
	_, err := jwtModule.Decrypt(token, "different-secret-key")
	if err != nil {
		fmt.Printf("Decrypt with different key failed: %v\n", err)
	}
	// Output:
	// Decrypted with default key: true
	// Decrypt with different key failed: invalid signature
}

// ExampleNewModule_Hash demonstrates hash module usage
func ExampleNewModule_hash() {
	// SHA-256 hash module
	hashModule, _ := cryptography.NewModule(cryptography.ModuleTypeHash, "sha256")

	data := "Hello, World!"
	hash, _ := hashModule.Encrypt(data)

	valid, _ := hashModule.Verify(data, hash)
	fmt.Printf("Hash length: %d\n", len(hash))
	fmt.Printf("Verification: %v\n", valid)
	// Output:
	// Hash length: 64
	// Verification: true
}

// ExampleNewModule_Hash_SHA512 demonstrates SHA-512 hashing
func ExampleNewModule_hashSHA512() {
	hashModule, _ := cryptography.NewModule(cryptography.ModuleTypeHash, "sha512")

	data := "Hello, World!"
	hash, _ := hashModule.Encrypt(data)
	fmt.Printf("SHA-512 Hash length: %d\n", len(hash))

	valid, _ := hashModule.Verify(data, hash)
	fmt.Printf("Verification: %v\n", valid)
	// Output:
	// SHA-512 Hash length: 128
	// Verification: true
}

// ExampleNewModule_Hash_Bcrypt demonstrates bcrypt password hashing
func ExampleNewModule_hashBcrypt() {
	hashModule, _ := cryptography.NewModule(cryptography.ModuleTypeHash, "bcrypt")

	password := "mySecurePassword123"
	hash, _ := hashModule.Encrypt(password)

	valid, _ := hashModule.Verify(password, hash)
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

// ExampleNewModule_Verify demonstrates verification functionality
func ExampleNewModule_verify() {
	aesModule, _ := cryptography.NewModule(cryptography.ModuleTypeAES, "my-secret-key-32-bytes-long!!")

	data := "Hello, World!"
	encrypted, _ := aesModule.Encrypt(data)

	// Verify with correct data
	valid1, _ := aesModule.Verify(data, encrypted)
	fmt.Printf("Verify correct data: %v\n", valid1)

	// Verify with wrong data
	valid2, _ := aesModule.Verify("Wrong data", encrypted)
	fmt.Printf("Verify wrong data: %v\n", valid2)
	// Output:
	// Verify correct data: true
	// Verify wrong data: false
}
