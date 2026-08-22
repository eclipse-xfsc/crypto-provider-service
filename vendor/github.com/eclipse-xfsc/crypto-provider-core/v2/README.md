# Crypto Provider Core

The **Crypto Provider Core** is a Go library that abstracts cryptographic providers behind a common interface. It enables applications to communicate with different cryptographic backends without depending on a specific implementation.

The library currently supports remote gRPC-based crypto providers and provides a common API for key management, signing, verification, encryption and decryption.

## Features

- Common crypto provider interface
- gRPC client implementation
- Provider abstraction
- Key management
- Digital signatures
- Signature verification
- Encryption / Decryption
- Standardized provider tests
- Connection readiness verification

## Architecture

```
                    +----------------------+
                    |   Your Application   |
                    +----------+-----------+
                               |
                               |
                      Crypto Provider Core
                               |
                     Common Provider Interface
                               |
                     gRPC Crypto Provider Client
                               |
                               |
                 +-------------+--------------+
                 |                            |
      Vault / OpenBao Plugin         Local Plugin
                 |                            |
                 +-------------+--------------+
                               |
                         Cryptographic Keys
```

The core itself performs no cryptographic operations. All operations are delegated to a compatible crypto provider.

---

# Installation

```bash
go get github.com/eclipse-xfsc/crypto-provider-core/v2
```

---

# Supported Operations

The `CryptoProvider` interface exposes the following functionality:

- Generate keys
- Delete keys
- Rotate keys
- List keys
- Retrieve key metadata
- Sign data
- Verify signatures
- Encrypt
- Decrypt
- Query supported key algorithms
- Query supported hash algorithms

Supported key types include:

- Ed25519
- ECDSA P-256
- ECDSA P-384
- ECDSA P-512
- RSA-2048
- RSA-3072
- RSA-4096
- AES-256-GCM

The exact algorithms depend on the connected provider.  [oai_citation:0‡Go-Pakete](https://pkg.go.dev/github.com/eclipse-xfsc/crypto-provider-core/v2/types?utm_source=chatgpt.com)

---

# Creating a Crypto Provider

A crypto provider is created by establishing a connection to a remote gRPC service.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

provider, cleanup, err := core.CreateCryptoEngine(
    ctx,
    "localhost:50051",
    insecure.NewCredentials(),
)
if err != nil {
    log.Fatal(err)
}
defer cleanup()
```

After a successful call the returned provider is ready to use.

---

# Connection Readiness

## Why

Previous versions created a gRPC client without verifying that the remote crypto provider was actually reachable.

Because gRPC connections are established lazily, applications could start successfully although no crypto provider was available.

This typically resulted in misleading runtime errors such as:

```text
unsupported key type: ecdsa-p256
```

while the real problem was an unavailable crypto provider.

---

## New Behavior

`CreateCryptoEngine()` now verifies that the remote provider becomes available before returning.

If the provider cannot be reached before the supplied context expires, an error is returned immediately.

Applications therefore fail fast during startup instead of failing later during cryptographic operations.

---

# Example

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

provider, cleanup, err := core.CreateCryptoEngine(
    ctx,
    grpcAddress,
    insecure.NewCredentials(),
)
if err != nil {
    return err
}
defer cleanup()

keys := provider.GetSupportedKeysAlgs()
```

---

# Kubernetes

The readiness verification is especially useful in Kubernetes environments.

Instead of accepting requests before the crypto provider is available, applications can now:

- fail during startup
- implement Kubernetes readiness probes
- avoid runtime failures caused by unavailable crypto providers

Typical startup sequence:

```
Application
      │
      ▼
CreateCryptoEngine()
      │
      ▼
Wait until gRPC connection is READY
      │
      ├── READY
      │      ▼
      │   Application starts
      │
      └── timeout
             ▼
        Startup fails
```

---

# Standardized Provider Tests

The library contains reusable tests that can be used by provider implementations.

Included tests cover:

- RSA signing
- Ed25519 signing
- AES encryption
- Key management

Provider implementations are encouraged to execute these tests as part of their CI pipeline.  [oai_citation:1‡Go-Pakete](https://pkg.go.dev/github.com/eclipse-xfsc/crypto-provider-core/v2?utm_source=chatgpt.com)

---

# Unit Tests

The connection readiness is covered by dedicated tests.

The tests verify the public API instead of internal helper functions.

Covered scenarios include:

- successful connection to a running gRPC server
- timeout when no provider is available
- cancelled context

This guarantees the externally visible behavior of `CreateCryptoEngine()`.

---

# Configuration

No mandatory configuration is required when using `CreateCryptoEngine()` directly.

The convenience function

```go
CryptoEngine()
```

uses the following environment variable:

| Variable | Description | Default |
|----------|-------------|---------|
| `CRYPTO_GRPC_ADDR` | Address of the remote crypto provider | `localhost:50051` |

 [oai_citation:2‡Go-Pakete](https://pkg.go.dev/github.com/eclipse-xfsc/crypto-provider-core/v2?utm_source=chatgpt.com)

---

# Error Handling

Typical initialization errors include:

- invalid gRPC address
- connection timeout
- cancelled context
- unavailable crypto provider

Applications should treat initialization errors as fatal because no cryptographic operations can be executed without a provider.

---

# Migration Guide

Previous versions:

```go
provider, cleanup := core.CreateCryptoEngine(
    addr,
    insecure.NewCredentials(),
)
```

Current version:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

provider, cleanup, err := core.CreateCryptoEngine(
    ctx,
    addr,
    insecure.NewCredentials(),
)
if err != nil {
    return err
}
```

---

# License

Apache License 2.0
