package satsavi

import "context"

// CreateSecretFromEnv parses raw .env file content and creates a new secret bundle.
//
// This is a convenience wrapper around ParseEnv + CreateSecret.
// The raw content can be a whole .env file pasted as a string.
//
// Example:
//
//	raw := "DB_HOST=localhost\nDB_PORT=5432\nAPI_KEY=\"sk_live_abc\""
//	secret, err := client.CreateSecretFromEnv(ctx, projectID, "prod-config", raw)
func (c *Client) CreateSecretFromEnv(ctx context.Context, projectID, name, rawEnv string) (*Secret, error) {
	data, err := ParseEnv(rawEnv)
	if err != nil {
		return nil, err
	}
	return c.CreateSecret(ctx, projectID, name, data)
}

// UpdateSecretFromEnv parses raw .env file content and updates an existing secret bundle.
//
// This is a convenience wrapper around ParseEnv + UpdateSecret.
// New entries are merged into the existing bundle (incremental update).
//
// Example:
//
//	raw := "NEW_KEY=new_value\nUPDATED_KEY=updated_value"
//	secret, err := client.UpdateSecretFromEnv(ctx, projectID, secretID, "prod-config", raw)
func (c *Client) UpdateSecretFromEnv(ctx context.Context, projectID, secretID, name, rawEnv string) (*Secret, error) {
	data, err := ParseEnv(rawEnv)
	if err != nil {
		return nil, err
	}
	return c.UpdateSecret(ctx, projectID, secretID, name, data)
}
