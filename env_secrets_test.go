package satsavi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_CreateSecretFromEnv(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	var receivedEntries []SecretEntry
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m2m/public-key":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"public_key": string(pubPEM),
			})
		case "/m2m/secrets":
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode([]Secret{})
				return
			}
			if r.Method == "POST" {
				var req CreateSecretRequest
				json.NewDecoder(r.Body).Decode(&req)
				receivedEntries = req.Entries

				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(Secret{
					ID:   "new-secret-id",
					Name: req.Name,
				})
				return
			}
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.VaultToken = "test-token"

	rawEnv := `# Database config
DB_HOST=localhost
DB_PORT=5432
DB_PASSWORD="super secret"
API_KEY=sk_live_abc123
`

	secret, err := client.CreateSecretFromEnv(context.Background(), "project-id", "prod-config", rawEnv)
	if err != nil {
		t.Fatalf("CreateSecretFromEnv failed: %v", err)
	}

	if secret.ID != "new-secret-id" {
		t.Errorf("Expected secret ID 'new-secret-id', got %s", secret.ID)
	}

	// Verify all 4 keys were sent as metadata entries
	expectedKeys := map[string]bool{
		"DB_HOST":     false,
		"DB_PORT":     false,
		"DB_PASSWORD": false,
		"API_KEY":     false,
	}
	for _, e := range receivedEntries {
		if _, ok := expectedKeys[e.Key]; ok {
			expectedKeys[e.Key] = true
		}
	}
	for k, found := range expectedKeys {
		if !found {
			t.Errorf("Expected key %q in entries, not found", k)
		}
	}
}

func TestClient_CreateSecretFromEnv_ParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/m2m/secrets" && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]Secret{})
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.VaultToken = "test-token"

	// Malformed .env — unclosed quote
	rawEnv := `KEY="unclosed value`

	_, err := client.CreateSecretFromEnv(context.Background(), "project-id", "bad-config", rawEnv)
	if err == nil {
		t.Fatal("Expected error for malformed .env, got nil")
	}
	if !contains(err.Error(), "unclosed double quote") {
		t.Errorf("Expected error about unclosed quote, got: %v", err)
	}
}

func TestClient_UpdateSecretFromEnv(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// Existing encrypted data
	key := make([]byte, 32)
	existingData := map[string]string{"OLD_KEY": "OLD_VAL"}
	existingBytes, _ := json.Marshal(existingData)
	res, _ := Encrypt(existingBytes, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m2m/public-key":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"public_key": string(pubPEM),
			})
		case "/m2m/secrets/secret-id":
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(Secret{
					ID:          "secret-id",
					Name:        "test-secret",
					EntriesBlob: res.CiphertextB64,
					IV:          res.IVB64,
					WrappedKey:  "dummy-wrapped",
				})
				return
			}
			if r.Method == "PUT" {
				var req CreateSecretRequest
				json.NewDecoder(r.Body).Decode(&req)

				// Verify both old and new keys are present
				foundOld := false
				foundNew := false
				for _, e := range req.Entries {
					if e.Key == "OLD_KEY" {
						foundOld = true
					}
					if e.Key == "NEW_FROM_ENV" {
						foundNew = true
					}
				}
				if !foundOld {
					t.Errorf("OLD_KEY missing from updated entries")
				}
				if !foundNew {
					t.Errorf("NEW_FROM_ENV missing from updated entries")
				}

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(Secret{ID: "secret-id", Name: "test-secret"})
				return
			}
		case "/m2m/unwrap":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString(key),
			})
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)

	rawEnv := "NEW_FROM_ENV=new_value"

	_, err := client.UpdateSecretFromEnv(context.Background(), "project-id", "secret-id", "test-secret", rawEnv)
	if err != nil {
		t.Fatalf("UpdateSecretFromEnv failed: %v", err)
	}
}
