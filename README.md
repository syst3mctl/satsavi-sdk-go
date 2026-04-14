<p align="center">
  <h1 align="center">satsavi-sdk-go</h1>
  <p align="center">
    <strong>Move fast and stay secure with Satsavi.</strong><br>
    A Go library for secure, zero-knowledge Machine-to-Machine communication.
  </p>
  <p align="center">
    <a href="https://goreportcard.com/report/github.com/syst3mctl/satsavi-sdk-go"><img src="https://goreportcard.com/badge/github.com/syst3mctl/satsavi-sdk-go?style=flat-square" alt="Go Report Card"></a>
    <a href="https://pkg.go.dev/github.com/syst3mctl/satsavi-sdk-go"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?style=flat-square&logo=go&logoColor=white" alt="Go Reference"></a>
    <a href="https://github.com/syst3mctl/satsavi-sdk-go/releases"><img src="https://img.shields.io/github/v/tag/syst3mctl/satsavi-sdk-go?style=flat-square&color=blue&label=version" alt="Version"></a>
    <a href="https://codecov.io/gh/syst3mctl/satsavi-sdk-go"><img src="https://img.shields.io/codecov/c/github/syst3mctl/satsavi-sdk-go?style=flat-square&logo=codecov" alt="Codecov"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT"></a>
  </p>
</p>

## Quickstart

```bash
go get github.com/syst3mctl/satsavi-sdk-go
```

```go
import (
    "context"
    satsavi "github.com/syst3mctl/satsavi-sdk-go"
)

func main() {
    client := satsavi.NewClient("https://api.satsavi.com")
    err := client.Login(context.Background(), "role-id", "secret-id")
    // ... create, list, and decrypt secrets
}
```

## Why Satsavi?

API secrets and credentials often drift between development and production. Managing them securely shouldn't be an afterthought.

Satsavi's SDK enforces **True Blindness**:
- **Zero Knowledge Encryption**: All information is encrypted on your device before it reaches our infrastructure.
- **Client-Side Wrapping**: The Data Encryption Key (DEK) is wrapped using RSA-OAEP locally.
- **Open Source transparency**: Built on open-source foundations to ensure full auditability.

## What It Does

- **Secure Creation**: Generate local AES-256 DEKs and wrap them before upload.
- **Incremental Updates**: Merge new keys into existing bundles locally without exposing other secrets.
- **Lifecycle Management**: Comprehensive support for listing, fetching, and deleting secret bundles.
- **Automatic Decryption**: Fetches encrypted blobs and unwraps DEKs via authenticated session for local decryption.

## Core API

### `NewClient(baseURL string) *Client`
Initializes a new Satsavi client.

### `client.Login(ctx, roleID, secretID) error`
Authenticates with the Satsavi API using AppRole credentials.

### `client.CreateSecret(ctx, projectID, name, data) (*Secret, error)`
Creates a new zero-knowledge secret bundle (implements True Blindness).

### `client.CreateSecretFromEnv(ctx, projectID, name, rawEnv string) (*Secret, error)`
Convenience method that parses a raw `.env` file content and creates a new secret bundle.

### `client.UpdateSecretFromEnv(ctx, projectID, secretID, name, rawEnv string) (*Secret, error)`
Convenience method that parses a raw `.env` file content and updates an existing bundle incrementally.

### `client.GetSecret(ctx, secretID) (map[string]string, error)`
Retrieves and decrypts a secret bundle locally.

### `satsavi.ParseEnv(rawEnv string) (map[string]string, error)`
Utility function to securely parse a `.env` file content string into a map, respecting quotes, comments, and edge cases.

## Contributing

See [CONTRIBUTING.md](https://github.com/syst3mctl/satsavi-sdk-go/blob/main/CONTRIBUTING.md) for guidelines on code standards and submitting pull requests.

## License

MIT — see [LICENSE](https://github.com/syst3mctl/satsavi-sdk-go/blob/main/LICENSE).

## About

Satsavi is building the next standard in secure password and secret management.
[satsavi.com](https://satsavi.com)
