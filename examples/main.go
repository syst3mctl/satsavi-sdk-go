package main

import (
	"context"
	"log"
	"os"

	satsavi "github.com/syst3mctl/satsavi-sdk-go"
)

func main() {
	// 1. Initialize Client
	// Use your local API URL
	apiURL := os.Getenv("SATSAVI_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8112"
	}

	client := satsavi.NewClient(apiURL)

	// 2. Login
	// Get these from the Satsavi Dashboard (M2M Credentials tab)
	roleID := os.Getenv("SATSAVI_ROLE_ID")
	secretID := os.Getenv("SATSAVI_SECRET_ID")
	projectID := os.Getenv("SATSAVI_PROJECT_ID")

	if roleID == "" || secretID == "" || projectID == "" {
		log.Fatal("Please set SATSAVI_ROLE_ID, SATSAVI_SECRET_ID, and SATSAVI_PROJECT_ID environment variables")
	}

	log.Println("Authenticating...")
	err := client.Login(context.Background(), roleID, secretID)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	log.Println("Successfully authenticated!")

	// 3. Create a Secret Bundle
	// Zero-Knowledge: The SDK generates a key locally, encrypts the data,
	// and wraps the key using Vault's Public Key before sending to the server.
	secretName := "Production-Config"
	secretData := map[string]string{
		"DB_PASSWORD":     "super-secret-password-123",
		"API_KEY":         "sk_live_51M...",
		"REDIS_URL":       "redis://localhost:6379",
		"ENCRYPTION_SALT": "random-salt-xyz",
	}

	log.Printf("Creating secret '%s'...\n", secretName)
	newSecret, err := client.CreateSecret(context.Background(), projectID, secretName, secretData)
	if err != nil {
		log.Fatalf("Failed to create secret: %v", err)
	}
	log.Printf("Secret created successfully! ID: %s\n", newSecret.ID)

	// 3.5. Create Secret from .env file content
	rawEnv := `
# A sample configuration block
APP_ENV=production
APP_DEBUG=false
APP_SECRET="another-secret-token"
export PORT=8080
`
	log.Printf("Creating .env secret...\n")
	envSecret, err := client.CreateSecretFromEnv(context.Background(), projectID, "Env-Config", rawEnv)
	if err != nil {
		log.Fatalf("Failed to create secret from env: %v", err)
	}
	log.Printf(".env Secret created successfully! ID: %s\n", envSecret.ID)

	// 4. List Secrets (confirm it exists)
	log.Println("Listing secrets in project...")
	secrets, err := client.ListSecrets(context.Background(), projectID)
	if err != nil {
		log.Fatalf("Failed to list secrets: %v", err)
	}
	for _, s := range secrets {
		log.Printf("- %s (ID: %s)\n", s.Name, s.ID)
	}

	// 5. Fetch and Decrypt the Secret
	// Zero-Knowledge: The SDK fetches the encrypted bundle, asks the server to unwrap
	// the key (via Vault's Private Key), and then decrypts the data locally.
	log.Printf("Fetching and decrypting secret '%s'...\n", newSecret.ID)
	decryptedData, err := client.GetSecret(context.Background(), newSecret.ID)
	if err != nil {
		log.Fatalf("Failed to decrypt secret: %v", err)
	}

	log.Println("Decrypted Data:")
	for k, v := range decryptedData {
		log.Printf("  %s: %s\n", k, v)
	}

	// 6. Partial Deletion (Delete specific keys)
	log.Printf("Removing 'REDIS_URL' from secret '%s'...\n", newSecret.ID)
	_, err = client.DeleteSecretEntries(context.Background(), projectID, newSecret.ID, secretName, []string{"REDIS_URL"})
	if err != nil {
		log.Fatalf("Failed to remove keys: %v", err)
	}
	log.Println("Key removed successfully!")

	// 7. Verify partial deletion
	log.Println("Verifying partial deletion...")
	remainingData, err := client.GetSecret(context.Background(), newSecret.ID)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}
	if _, exists := remainingData["REDIS_URL"]; exists {
		log.Fatal("REDIS_URL still exists after deletion!")
	}
	log.Printf("Verified! Remaining keys: %d\n", len(remainingData))

	// 8. Delete the entire Secret
	log.Printf("Deleting entire secret '%s'...\n", newSecret.ID)
	err = client.DeleteSecret(context.Background(), newSecret.ID)
	if err != nil {
		log.Fatalf("Failed to delete secret: %v", err)
	}
	log.Println("Secret deleted successfully!")

	log.Println("\nM2M SDK Demo completed successfully!")
}
