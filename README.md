# Satsavi M2M Go SDK Documentation

A Go library for secure, zero-knowledge Machine-to-Machine communication with the Satsavi API.

## Installation

In your external Go project, run:
```bash
go get github.com/syst3mctl/satsavi-sdk-go
```

## Usage

Import the package in your Go files:
```go
import (
    "context"
    "fmt"
    "log"
    "github.com/syst3mctl/satsavi-sdk-go"
)

func main() {
    ctx := context.Background()
    client := sdk.NewClient("https://api.satsavi.com")

    // Authenticate
    err := client.Login(ctx, "your-role-id", "your-secret-id")
    if err != nil {
        log.Fatal(err)
    }

    // Create a new secret bundle
    newSecret, err := client.CreateSecret(ctx, "project-uuid", "my-app-secrets", map[string]string{
        "API_KEY":    "super-secret-key",
        "DB_PASS":    "another-secret",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created secret: %s\n", newSecret.Name)

    // List all secrets
    secrets, err := client.ListSecrets(ctx, "project-uuid")
    if err != nil {
        log.Fatal(err)
    }
    for _, s := range secrets {
        fmt.Printf("Secret: %s (ID: %s)\n", s.Name, s.ID)
    }

    // 3. Update a secret incrementally
    // (Zero-Knowledge: fetches existing, merges new keys locally, then re-encrypts)
    log.Println("Updating secret with a new key...")
    _, err = client.UpdateSecret(ctx, "project-uuid", newSecret.ID, "my-app-secrets", map[string]string{
        "NEW_FEATURE_FLAGS": "enabled", // This will be ADDED to the existing API_KEY and DB_PASS
    })
    if err != nil {
        log.Fatal(err)
    }

    // 4. Verify the merge
    data, _ := client.GetSecret(ctx, newSecret.ID)
    fmt.Printf("Secrets count: %d (expected 3)\n", len(data))

    // 5. Delete specific keys incrementally
    log.Println("Removing a specific key...")
    _, err = client.DeleteSecretEntries(ctx, "project-uuid", newSecret.ID, "my-app-secrets", []string{"DB_PASS"})
    if err != nil {
        log.Fatal(err)
    }

    // 6. Delete the entire secret bundle
    err = client.DeleteSecret(ctx, newSecret.ID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Secret deleted successfully")
}
```

## API Reference

### `NewClient(baseURL string) *Client`
Initializes a new Satsavi client.
- **Parameters**: `baseURL` (the URL of your Satsavi instance)
- **Returns**: `*Client`

---

### `client.Login(ctx context.Context, roleID, secretID string) error`
Authenticates with the Satsavi API using Vault AppRole credentials.
- **Parameters**: 
    - `ctx`: A `context.Context` for the request.
    - `roleID`: The AppRole Role ID.
    - `secretID`: The AppRole Secret ID.
- **Returns**: `error` (nil if authentication was successful)

---

### `client.GetPublicKey(ctx context.Context) (string, error)`
Retrieves the RSA public key used for client-side wrapping of the Data Encryption Key (DEK). This is typically called internally by `CreateSecret`.
- **Parameters**: `ctx`
- **Returns**: `string` (PEM encoded public key), `error`

---

### `client.ListSecrets(ctx context.Context, projectID string) ([]Secret, error)`
Lists all secret bundles (metadata only) associated with a project.
- **Parameters**: 
    - `ctx`: A `context.Context`.
    - `projectID`: The UUID of the project.
- **Returns**: `[]Secret` (list of secret bundles), `error`

---

### `client.CreateSecret(ctx context.Context, projectID, name string, data map[string]string) (*Secret, error)`
Creates a new zero-knowledge secret bundle. This function implements "True Blindness":
1. Generates a local 256-bit AES DEK.
2. Encrypts the `data` (JSON-encoded) locally using the DEK and a random IV.
3. Retrieves the Satsavi public key and wraps the DEK locally using RSA-OAEP.
4. Uploads the encrypted blob, wrapped key, and IV to the server.
- **Parameters**: 
    - `ctx`: A `context.Context`.
    - `projectID`: The UUID of the project.
    - `name`: A name for the secret bundle (must be unique within the project).
    - `data`: A map of key-value pairs to encrypt.
- **Returns**: `*Secret` (the created bundle metadata), `error`

---

### `client.UpdateSecret(ctx context.Context, projectID, secretID, name string, data map[string]string) (*Secret, error)`
Updates an existing zero-knowledge secret bundle (Incremental). Like `CreateSecret`, this implements "True Blindness":
1. Fetches the existing encrypted data and decrypts it locally.
2. Merges the new `data` into the existing entries.
3. Generates a new local 256-bit AES DEK.
4. Encrypts the merged `data` locally.
5. Wraps the new DEK locally using the public key.
6. Uploads the update to the server.

> [!NOTE]
> This is an **incremental update**. If you only provide one key-value pair, it will be added to the existing bundle (or update it if the key already exists). Other existing keys are preserved.

- **Parameters**:
    - `ctx`: A `context.Context`.
    - `projectID`: The UUID of the project.
    - `secretID`: The ID of the secret to update.
    - `name`: The (possibly new) name for the secret bundle.
    - `data`: The map of key-value pairs to add or update.
- **Returns**: `*Secret`, `error`

---

### `client.DeleteSecretEntries(ctx context.Context, projectID, secretID, name string, keys []string) (*Secret, error)`
Removes specific keys from an existing zero-knowledge secret bundle (Incremental Deletion).
1. Fetches the existing encrypted data and decrypts it locally.
2. Removes the specified `keys` from the local data map.
3. Re-encrypts the modified data and wraps a new DEK.
4. Uploads the update to the server.

- **Parameters**:
    - `ctx`: A `context.Context`.
    - `projectID`: The UUID of the project.
    - `secretID`: The ID of the secret to modify.
    - `name`: The name for the secret bundle.
    - `keys`: A slice of strings representing the keys to delete.
- **Returns**: `*Secret`, `error`

---

### `client.DeleteSecret(ctx context.Context, secretID string) error`
Deletes a secret bundle from the vault.
- **Parameters**: `secretID` (the UUID of the secret)
- **Returns**: `error`

---

### `client.GetSecret(ctx context.Context, secretID string) (map[string]string, error)`
Retrieves and decrypts a secret bundle by its ID or Name.
1. Fetches the encrypted bundle from the API.
2. Requests the API to unwrap the DEK using the server-side private key (Vault).
3. Decrypts the data locally using the unwrapped DEK.
- **Parameters**:
    - `ctx`: A `context.Context`.
    - `secretID`: The ID or unique name of the secret bundle.
- **Returns**: `map[string]string` (the decrypted secrets), `error`

---

## Data Structures

### `type Client struct`
The main client for interacting with the Satsavi API.
```go
type Client struct {
    BaseURL    string
    VaultToken string // Populated after Login
}
```

### `type Secret struct`
Represents a secret bundle metadata and its encrypted components.
```go
type Secret struct {
    ID          string      `json:"id"`
    Name        string      `json:"name"`
    Notes       string      `json:"notes"`
    EntriesBlob string      `json:"entries_blob"` // Encrypted JSON blob
    WrappedKey  string      `json:"wrapped_key"`   // DEK wrapped with RSA
    IV          string      `json:"iv"`            // Base64 encoded IV
    Entries     []SecretKey `json:"entries,omitempty"` // Key names only
}
```

### `type SecretKey struct`
Metadata about a specific key within a bundle.
```go
type SecretKey struct {
    Key string `json:"key"`
}
```

---

## Zero-Knowledge Architecture (True Blindness)

The SDK enforces "True Blindness" for all secret creation:
- **Client-Side Wrapping**: The Data Encryption Key (DEK) is wrapped using RSA-OAEP on the developer's machine *before* being sent to the server.
- **Local Decryption**: Plaintext secrets never leave your environment. The server only sees encrypted blobs and wrapped keys.
- **Key Separation**: Even if the server database is compromised, the secrets remain encrypted. Decryption requires an authenticated session to unwrap the DEK.

## Publishing Guide

To use this SDK in your own project:
1. Ensure your Go module matches the repository path: `module github.com/syst3mctl/satsavi-sdk-go`.
2. Tag your releases (e.g., `git tag v1.0.1`).
3. Import it using `go get github.com/syst3mctl/satsavi-sdk-go`.

---

## Testing

To run the unit tests for the SDK, ensure you have Go installed and run the following command in the root of the repository:

```bash
go test -v ./...
```

The tests cover:
- Authentication (Login) flow.
- Secret creation with "True Blindness".
- Incremental updates (verifying that old keys are preserved during updates).
- Secret listing and exhaustive deletion tests (including lifecycle verification and error handling).
- Cryptographic primitives (wrapping, encryption/decryption).
