package satsavi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateSecretRequest matches the API request for /m2m/secrets
type CreateSecretRequest struct {
	ID          string        `json:"id,omitempty"`
	Name        string        `json:"name"`
	ProjectID   *string       `json:"project_id,omitempty"`
	EntriesBlob string        `json:"entries_blob"`
	WrappedKey  string        `json:"wrapped_key"`
	IV          string        `json:"iv"`
	Entries     []SecretEntry `json:"entries"`
}

// SecretEntry represents a single key inside an encrypted bundle
type SecretEntry struct {
	Key            string `json:"key"`
	EncryptedValue string `json:"encrypted_value"`
}

// CreateSecret performs the full Zero-Knowledge encryption and storage flow
func (c *Client) CreateSecret(ctx context.Context, projectID string, name string, data map[string]string) (*Secret, error) {
	// 0. Ensure name is unique within the project
	existing, err := c.ListSecrets(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify secret name uniqueness: %w", err)
	}
	for _, s := range existing {
		if s.Name == name {
			return nil, fmt.Errorf("secret with name %q already exists in project %s", name, projectID)
		}
	}

	// 1. Generate local DEK (Data Encryption Key)
	key, err := Generate256BitKey()
	if err != nil {
		return nil, err
	}

	// 2. Encrypt all entries as a JSON blob
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	res, err := Encrypt(jsonBytes, key)
	if err != nil {
		return nil, err
	}

	// 3. Wrap DEK locally via Public Key (True Blindness)
	pubKey, err := c.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for local wrapping: %w", err)
	}

	wrappedKey, err := WrapKeyRSA(key, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key locally: %w", err)
	}

	// 4. Prepare metadata entries (just keys, no values)
	entries := make([]SecretEntry, 0, len(data))
	for k := range data {
		entries = append(entries, SecretEntry{
			Key:            k,
			EncryptedValue: "consolidated_in_blob",
		})
	}

	// 5. Store the encrypted bundle via API
	reqBody := CreateSecretRequest{
		Name:        name,
		ProjectID:   &projectID,
		EntriesBlob: res.CiphertextB64,
		WrappedKey:  wrappedKey,
		IV:          res.IVB64,
		Entries:     entries,
	}

	resp, err := c.doRequest(ctx, "POST", "/m2m/secrets", reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create secret: status %d", resp.StatusCode)
	}

	var secret Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// GetSecret retrieves and decrypts a secret bundle by ID or Name (if implemented by server)
func (c *Client) GetSecret(ctx context.Context, secretID string) (map[string]string, error) {
	// 1. Fetch encrypted bundle
	resp, err := c.doRequest(ctx, "GET", "/m2m/secrets/"+secretID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch secret: status %d", resp.StatusCode)
	}

	var secret Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	// 2. Unwrap DEK via API (Server uses Vault Private Key)
	unwrapResp, err := c.doRequest(ctx, "POST", "/m2m/unwrap", map[string]string{
		"ciphertext": secret.WrappedKey,
	})
	if err != nil {
		return nil, err
	}
	defer unwrapResp.Body.Close()

	if unwrapResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to unwrap key: status %d", unwrapResp.StatusCode)
	}

	var unwrapData struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(unwrapResp.Body).Decode(&unwrapData); err != nil {
		return nil, err
	}

	rawKey, err := base64.StdEncoding.DecodeString(unwrapData.Plaintext)
	if err != nil {
		return nil, err
	}

	// 3. Decrypt data locally
	jsonStr, err := Decrypt(secret.EntriesBlob, secret.IV, rawKey)
	if err != nil {
		return nil, err
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, err
	}

	return data, nil
}

// ListSecrets lists all secrets in a project
func (c *Client) ListSecrets(ctx context.Context, projectID string) ([]Secret, error) {
	resp, err := c.doRequest(ctx, "GET", "/m2m/secrets?project_id="+projectID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list secrets: status %d", resp.StatusCode)
	}

	var secrets []Secret
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, err
	}

	return secrets, nil
}

// UpdateSecret updates an existing secret bundle with new data (incremental)
func (c *Client) UpdateSecret(ctx context.Context, projectID string, secretID string, name string, data map[string]string) (*Secret, error) {
	// 1. Fetch existing secret data for incremental update
	existingData, err := c.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing secret for incremental update: %w", err)
	}

	// 2. Merge new data into existing data
	for k, v := range data {
		existingData[k] = v
	}

	// 3. Generate local DEK
	key, err := Generate256BitKey()
	if err != nil {
		return nil, err
	}

	// 4. Encrypt merged entries as a JSON blob
	jsonBytes, err := json.Marshal(existingData)
	if err != nil {
		return nil, err
	}

	res, err := Encrypt(jsonBytes, key)
	if err != nil {
		return nil, err
	}

	// 5. Wrap DEK locally via Public Key
	pubKey, err := c.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for local wrapping: %w", err)
	}

	wrappedKey, err := WrapKeyRSA(key, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key locally: %w", err)
	}

	// 6. Prepare metadata entries (just keys, no values)
	entries := make([]SecretEntry, 0, len(existingData))
	for k := range existingData {
		entries = append(entries, SecretEntry{
			Key:            k,
			EncryptedValue: "consolidated_in_blob",
		})
	}

	// 7. Update the encrypted bundle via API
	reqBody := CreateSecretRequest{
		ID:          secretID,
		Name:        name,
		ProjectID:   &projectID,
		EntriesBlob: res.CiphertextB64,
		WrappedKey:  wrappedKey,
		IV:          res.IVB64,
		Entries:     entries,
	}

	resp, err := c.doRequest(ctx, "PUT", "/m2m/secrets/"+secretID, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update secret: status %d", resp.StatusCode)
	}

	var secret Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// DeleteSecretEntries removes specific keys from an existing secret bundle (incremental deletion)
func (c *Client) DeleteSecretEntries(ctx context.Context, projectID string, secretID string, name string, keys []string) (*Secret, error) {
	// 1. Fetch existing secret data
	existingData, err := c.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing secret for partial deletion: %w", err)
	}

	// 2. Remove specified keys
	for _, k := range keys {
		delete(existingData, k)
	}

	// 3. Generate local DEK
	key, err := Generate256BitKey()
	if err != nil {
		return nil, err
	}

	// 4. Encrypt modified entries as a JSON blob
	jsonBytes, err := json.Marshal(existingData)
	if err != nil {
		return nil, err
	}

	res, err := Encrypt(jsonBytes, key)
	if err != nil {
		return nil, err
	}

	// 5. Wrap DEK locally via Public Key
	pubKey, err := c.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for local wrapping: %w", err)
	}

	wrappedKey, err := WrapKeyRSA(key, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key locally: %w", err)
	}

	// 6. Prepare metadata entries (just keys, no values)
	entries := make([]SecretEntry, 0, len(existingData))
	for k := range existingData {
		entries = append(entries, SecretEntry{
			Key:            k,
			EncryptedValue: "consolidated_in_blob",
		})
	}

	// 7. Update the encrypted bundle via API
	reqBody := CreateSecretRequest{
		ID:          secretID,
		Name:        name,
		ProjectID:   &projectID,
		EntriesBlob: res.CiphertextB64,
		WrappedKey:  wrappedKey,
		IV:          res.IVB64,
		Entries:     entries,
	}

	resp, err := c.doRequest(ctx, "PUT", "/m2m/secrets/"+secretID, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update secret during partial deletion: status %d", resp.StatusCode)
	}

	var secret Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// DeleteSecret deletes a secret bundle by ID
func (c *Client) DeleteSecret(ctx context.Context, secretID string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/m2m/secrets/"+secretID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete secret: status %d", resp.StatusCode)
	}

	return nil
}
