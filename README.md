# Cryptography

A flexible, modular cryptography library for Go supporting encryption, token signing, and hashing with a unified interface.

## Features

- 🔄 **Modular Design**: Easy switching between module types
- 🔑 **Flexible Keys**: Key rotation and per-operation keys
- 📦 **Flexible Data Types**: Works with strings, maps, structs, or any data type
- ⏱️ **TTL Support**: Optional time-to-live for JWT tokens
- 🔒 **Production Ready**: Industry-standard algorithms (AES-256-GCM, HMAC-SHA256)
- 🔐 **Hashing**: SHA-256, SHA-512, and bcrypt for password hashing
- ⏰ **Context Support**: All operations support cancellation and timeouts

## Installation

```bash
go get github.com/tjandrayana/cryptography
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "github.com/tjandrayana/cryptography"
)

func main() {
    // Create encryption module
    encryption, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "my-secret-key-32-bytes-long!!")
    
    ctx := context.Background()
    encrypted, _ := encryption.Encrypt(ctx, "Hello, World!")
    decrypted, _ := encryption.Decrypt(ctx, encrypted)
    fmt.Println(decrypted) // Output: Hello, World!
}
```

## Usage Examples

### Encryption

```go
ctx := context.Background()
encryption, _ := cryptography.NewEncryption(cryptography.EncryptionAES256GCM, "my-secret-key-32-bytes-long!!")

// Encrypt any data type
encrypted, _ := encryption.Encrypt(ctx, "Hello, World!")
encrypted, _ := encryption.Encrypt(ctx, map[string]interface{}{"user_id": 123})
encrypted, _ := encryption.Encrypt(ctx, userStruct)

// Decrypt
decrypted, _ := encryption.Decrypt(ctx, encrypted)

// Decrypt with different key (key rotation)
decrypted, _ := encryption.Decrypt(ctx, encrypted, "different-key")
```

### JWT Tokens

```go
ctx := context.Background()
tokenModule, _ := cryptography.NewToken(cryptography.TokenJWT, "my-jwt-secret-key")

// Sign without TTL
token, _ := tokenModule.Sign(ctx, map[string]interface{}{"user_id": 123})

// Sign with TTL
token, _ := tokenModule.Sign(ctx, data, cryptography.WithTokenTTL(1*time.Hour))

// Verify
data, err := tokenModule.VerifyToken(ctx, token)
```

**Note**: JWT payloads are signed (not encrypted) - anyone can decode them, but only those with the key can verify authenticity.

### Hashing

```go
ctx := context.Background()

// SHA-256/SHA-512
hashModule, _ := cryptography.NewHash(cryptography.HashSHA256)
hash, _ := hashModule.Hash(ctx, "data")
isValid, _ := hashModule.Verify(ctx, "data", hash)

// Bcrypt (for passwords)
bcryptModule, _ := cryptography.NewBcrypt(10)
passwordHash, _ := bcryptModule.Hash(ctx, "password")
isValid, _ := bcryptModule.Verify(ctx, "password", passwordHash)
```

### Context and Timeouts

```go
// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
encrypted, err := encryption.Encrypt(ctx, "data")

// Or use convenience helper
ctx, cancel := cryptography.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
```

## API Reference

### Factory Functions

```go
NewEncryption(algorithm EncryptionAlgorithm, key string) (Encryption, error)
NewToken(standard TokenStandard, key string) (Token, error)
NewHash(algorithm HashAlgorithm) (Hash, error)
NewBcrypt(cost int) (Hash, error)
```

### Interfaces

```go
type Encryption interface {
    Encrypt(ctx context.Context, data interface{}, opts ...interface{}) (string, error)
    Decrypt(ctx context.Context, ciphertext string, key ...string) (interface{}, error)
    Verify(ctx context.Context, data interface{}, encrypted string) (bool, error)
}

type Token interface {
    Sign(ctx context.Context, data interface{}, opts ...interface{}) (string, error)
    VerifyToken(ctx context.Context, token string, key ...string) (interface{}, error)
    Validate(ctx context.Context, data interface{}, token string) (bool, error)
}

type Hash interface {
    Hash(ctx context.Context, data interface{}, opts ...interface{}) (string, error)
    Verify(ctx context.Context, data interface{}, hash string) (bool, error)
}
```

### Module Types

- **AES-256-GCM**: Encryption algorithm for confidentiality (data is encrypted)
- **JWT (JWS)**: Token format for authenticity/integrity (data is signed, not encrypted)
- **SHA-256/SHA-512**: Fast hashing for data integrity
- **Bcrypt**: Slow hashing for password storage

### Options

```go
// Token TTL
token, _ := tokenModule.Sign(ctx, data, cryptography.WithTokenTTL(1*time.Hour))
```

## Best Practices

1. **Key Management**: Store keys securely (environment variables, secret managers)
2. **Key Size**: Use 32 bytes for AES-256 (automatically derived from any key length)
3. **Error Handling**: Always check errors from operations
4. **Context**: Use timeouts in production code
5. **JWT vs Encryption**: Use JWT for tokens (authenticity), AES for secrets (confidentiality)

## Architecture

The library follows a clean, layered architecture based on SOLID principles and design patterns.

### Design Patterns

1. **Factory Pattern**: Centralized object creation through factory functions (`NewEncryption`, `NewToken`, `NewHash`)
2. **Interface Segregation**: Separate interfaces for distinct concerns (`Encryption`, `Token`, `Hash`)
3. **Dependency Inversion**: Clients depend on abstractions (interfaces), not concrete implementations

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Application                        │
│  Uses factory functions to create modules                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Factory Layer (crypto.go)                       │
│  • NewEncryption() → Returns Encryption interface           │
│  • NewToken() → Returns Token interface                     │
│  • NewHash() → Returns Hash interface                       │
│  • Centralized creation logic                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           Interface Layer (interfaces.go)                    │
│  • Encryption interface (Encrypt, Decrypt, Verify)          │
│  • Token interface (Sign, VerifyToken, Validate)             │
│  • Hash interface (Hash, Verify)                             │
│  • Defines contracts without implementation details         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Implementation Layer (subpackages)                   │
│  • encryption/aes/ → AES-256-GCM implementation             │
│  • token/jwt/ → JWT (JWS) implementation                    │
│  • hash/sha/ → SHA-256/SHA-512 implementation              │
│  • hash/bcrypt/ → Bcrypt implementation                     │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
cryptography/
├── crypto.go              # Factory functions
├── interfaces.go           # Interface definitions
├── types.go               # Configuration types (TokenOptions)
├── context.go             # Context helper functions
├── encryption/
│   └── aes/
│       ├── aes.go         # AES-256-GCM implementation
│       └── aes_test.go
├── token/
│   └── jwt/
│       ├── jwt.go         # JWT (JWS) implementation
│       └── jwt_test.go
└── hash/
    ├── sha/
    │   ├── sha.go         # SHA-256/SHA-512 implementation
    │   └── sha_test.go
    └── bcrypt/
        ├── bcrypt.go      # Bcrypt implementation
        └── bcrypt_test.go
```

### Key Architectural Principles

1. **Separation of Concerns**: Each module type (Encryption, Token, Hash) has its own interface and implementation
2. **Open/Closed Principle**: Easy to add new algorithms without modifying existing code
3. **Single Responsibility**: Each package handles one specific algorithm or standard
4. **Context-Aware**: All operations accept `context.Context` for cancellation and timeouts
5. **Type Safety**: Strong typing prevents misuse (e.g., can't use encryption algorithm where token is expected)

### Data Flow

1. **Client** calls factory function (`NewEncryption`, `NewToken`, or `NewHash`)
2. **Factory** selects appropriate implementation based on algorithm/standard type
3. **Factory** returns interface type (not concrete implementation)
4. **Client** uses interface methods with `context.Context`
5. **Implementation** performs cryptographic operations with context support

### Extensibility

To add a new algorithm:

1. Create new implementation in appropriate subpackage (e.g., `encryption/des/`)
2. Implement the corresponding interface (`Encryption`, `Token`, or `Hash`)
3. Add algorithm constant to `crypto.go`
4. Add case to factory function in `crypto.go`

The existing code remains unchanged, following the Open/Closed Principle.

## Contributing

Contributions welcome! The codebase follows clean architecture principles with factory functions in `crypto.go`, interfaces in `interfaces.go`, and implementations in subpackages.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

**TJ (tjandrayana)** - [@tjandrayana](https://github.com/tjandrayana)
