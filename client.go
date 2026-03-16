package satsavi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the main Satsavi M2M SDK client (Encryption Proxy)
type Client struct {
	BaseURL    string
	VaultToken string
	httpClient *http.Client
}

type AuthResponse struct {
	VaultToken string `json:"vault_token"`
	TTL        int    `json:"ttl"`
}

// NewClient creates a new Satsavi SDK client
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Login authenticates using M2M AppRole credentials
func (c *Client) Login(ctx context.Context, roleID, secretID string) error {
	payload := map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	resp, err := c.doRequest(ctx, "POST", "/m2m/auth", payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: status %d", resp.StatusCode)
	}

	var auth AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return err
	}

	c.VaultToken = auth.VaultToken
	return nil
}

// GetPublicKey retrieves the RSA public key for client-side wrapping
func (c *Client) GetPublicKey(ctx context.Context) (string, error) {
	resp, err := c.doRequest(ctx, "GET", "/m2m/public-key", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get public key: status %d", resp.StatusCode)
	}

	var data struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	return data.PublicKey, nil
}

// Secret represents a Satsavi secret bundle
type Secret struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Notes       string      `json:"notes"`
	EntriesBlob string      `json:"entries_blob"`
	WrappedKey  string      `json:"wrapped_key"`
	IV          string      `json:"iv"`
	Entries     []SecretKey `json:"entries,omitempty"`
}

type SecretKey struct {
	Key string `json:"key"`
}

// doRequest performs an authenticated HTTP request
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyJson, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewBuffer(bodyJson)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.VaultToken != "" {
		req.Header.Set("X-Vault-Token", c.VaultToken)
	}

	return c.httpClient.Do(req)
}
