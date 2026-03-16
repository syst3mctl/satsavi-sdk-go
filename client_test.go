package satsavi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"context"
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
