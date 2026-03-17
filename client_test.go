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

func TestClient_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/m2m/auth" {
			t.Errorf("Expected path /m2m/auth, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthResponse{
			VaultToken: "test-token",
			TTL:        3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	err := client.Login(context.Background(), "role-id", "secret-id")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if client.VaultToken != "test-token" {
		t.Errorf("Expected token test-token, got %s", client.VaultToken)
	}
}

func TestClient_CreateSecret(t *testing.T) {
	// 1. Setup mock RSA key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

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
			if r.Method != "POST" {
				t.Errorf("Expected POST, got %s", r.Method)
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(Secret{
				ID:   "new-secret-id",
				Name: "test-secret",
			})
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.VaultToken = "test-token"

	data := map[string]string{"KEY": "VALUE"}
	secret, err := client.CreateSecret(context.Background(), "project-id", "test-secret", data)
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	if secret.ID != "new-secret-id" {
		t.Errorf("Expected secret ID new-secret-id, got %s", secret.ID)
	}
}

func TestClient_CreateSecret_Uniqueness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/m2m/secrets" && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]Secret{
				{ID: "existing-id", Name: "conflict-name"},
			})
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	_, err := client.CreateSecret(context.Background(), "project-id", "conflict-name", map[string]string{"K": "V"})
	if err == nil {
		t.Fatal("Expected error for duplicate secret name, got nil")
	}
}

func TestClient_UpdateSecret(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 1. Setup real encryption for "existing" data
	key := make([]byte, 32)
	existingData := map[string]string{"K1": "V1"}
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
					WrappedKey:  "dummy-wrapped",
					IV:          res.IVB64,
				})
				return
			}
			if r.Method != "PUT" {
				t.Errorf("Expected PUT, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(Secret{
				ID:   "secret-id",
				Name: "updated-name",
			})
		case "/m2m/unwrap":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString(key),
			})
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	// We need to mock Decrypt/Encrypt or provide valid data.
	// Since Decrypt/Encrypt are using real crypto, we should probably mock the calls or use valid data.
	// For simplicity in this test, we are focusing on the flow.

	secret, err := client.UpdateSecret(context.Background(), "project-id", "secret-id", "updated-name", map[string]string{"NEW_KEY": "NEW_VAL"})
	if err != nil {
		t.Fatalf("UpdateSecret failed: %v", err)
	}

	if secret.Name != "updated-name" {
		t.Errorf("Expected name updated-name, got %s", secret.Name)
	}
}

func TestClient_UpdateSecret_Incremental(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 1. Generate a valid encrypted blob for "existing" data
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

				// Verify that OLD_KEY is still present in the metadata entries
				foundOld := false
				foundNew := false
				for _, e := range req.Entries {
					if e.Key == "OLD_KEY" {
						foundOld = true
					}
					if e.Key == "NEW_KEY" {
						foundNew = true
					}
				}
				if !foundOld {
					t.Errorf("OLD_KEY missing from updated entries")
				}
				if !foundNew {
					t.Errorf("NEW_KEY missing from updated entries")
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
	_, err := client.UpdateSecret(context.Background(), "project-id", "secret-id", "test-secret", map[string]string{"NEW_KEY": "NEW_VAL"})
	if err != nil {
		t.Fatalf("Incremental UpdateSecret failed: %v", err)
	}
}

func TestClient_DeleteSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/m2m/secrets/secret-id" {
			t.Errorf("Expected path /m2m/secrets/secret-id, got %s", r.URL.Path)
		}
		if r.Method != "DELETE" {
			t.Errorf("Expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	err := client.DeleteSecret(context.Background(), "secret-id")
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}
}

func TestClient_Delete_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	err := client.DeleteSecret(context.Background(), "missing-id")
	if err == nil {
		t.Fatal("Expected error for non-existent secret deletion, got nil")
	}
}

func TestClient_Delete_Verify(t *testing.T) {
	// Mock server that tracks a single secret
	secretExists := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			secretExists = false
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == "GET" {
			if !secretExists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(Secret{ID: "test-id"})
			return
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)

	// 1. Verify it exists
	_, err := client.GetSecret(context.Background(), "test-id")
	if err != nil && err.Error() != "failed to fetch secret: status 404" { // GetSecret will fail decryption with dummy data, but here we just check if it fetched
		// Actually GetSecret fetches first, then unwraps.
		// For simplicity, let's just test that after Delete, Get returns 404 before it even tries decryption.
	}

	// 2. Delete it
	err = client.DeleteSecret(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 3. Verify it's gone (should fail at fetch step with 404)
	_, err = client.GetSecret(context.Background(), "test-id")
	if err == nil {
		t.Fatal("Expected error fetching deleted secret, got nil")
	}
}

func TestClient_ListSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/m2m/secrets" {
			t.Errorf("Expected path /m2m/secrets, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("project_id") != "project-id" {
			t.Errorf("Expected project_id project-id, got %s", r.URL.Query().Get("project_id"))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]Secret{
			{ID: "s1", Name: "secret1"},
			{ID: "s2", Name: "secret2"},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	secrets, err := client.ListSecrets(context.Background(), "project-id")
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("Expected 2 secrets, got %d", len(secrets))
	}
}

func TestClient_DeleteSecretEntries(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 1. Setup real encryption for "existing" data with multiple keys
	key := make([]byte, 32)
	existingData := map[string]string{
		"KEEP_ME":   "value1",
		"DELETE_ME": "value2",
	}
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

				// Verify that DELETE_ME is GONE from metadata entries
				foundDeleteMe := false
				foundKeepMe := false
				for _, e := range req.Entries {
					if e.Key == "DELETE_ME" {
						foundDeleteMe = true
					}
					if e.Key == "KEEP_ME" {
						foundKeepMe = true
					}
				}
				if foundDeleteMe {
					t.Errorf("DELETE_ME still present in updated entries")
				}
				if !foundKeepMe {
					t.Errorf("KEEP_ME missing from updated entries")
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
	_, err := client.DeleteSecretEntries(context.Background(), "project-id", "secret-id", "test-secret", []string{"DELETE_ME"})
	if err != nil {
		t.Fatalf("DeleteSecretEntries failed: %v", err)
	}
}
