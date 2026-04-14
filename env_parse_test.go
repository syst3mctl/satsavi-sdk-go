package satsavi

import (
	"testing"
)

func TestParseEnv(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "basic key-value",
			input:    "DB_HOST=localhost",
			expected: map[string]string{"DB_HOST": "localhost"},
		},
		{
			name:     "multiple entries",
			input:    "A=1\nB=2\nC=3",
			expected: map[string]string{"A": "1", "B": "2", "C": "3"},
		},
		{
			name:     "comments skipped",
			input:    "# this is a comment\nKEY=VAL",
			expected: map[string]string{"KEY": "VAL"},
		},
		{
			name:     "empty lines skipped",
			input:    "\n\nKEY=VAL\n\n",
			expected: map[string]string{"KEY": "VAL"},
		},
		{
			name:     "double-quoted value",
			input:    `KEY="hello world"`,
			expected: map[string]string{"KEY": "hello world"},
		},
		{
			name:     "single-quoted value",
			input:    "KEY='hello world'",
			expected: map[string]string{"KEY": "hello world"},
		},
		{
			name:     "inline comment stripped",
			input:    "KEY=val # this is a comment",
			expected: map[string]string{"KEY": "val"},
		},
		{
			name:     "inline comment preserved inside double quotes",
			input:    `KEY="val # not a comment"`,
			expected: map[string]string{"KEY": "val # not a comment"},
		},
		{
			name:     "inline comment preserved inside single quotes",
			input:    "KEY='val # not a comment'",
			expected: map[string]string{"KEY": "val # not a comment"},
		},
		{
			name:     "export prefix stripped",
			input:    "export KEY=VAL",
			expected: map[string]string{"KEY": "VAL"},
		},
		{
			name:     "export with quotes",
			input:    `export SECRET="my secret value"`,
			expected: map[string]string{"SECRET": "my secret value"},
		},
		{
			name:     "empty value included (SDK-friendly)",
			input:    "DEBUG=",
			expected: map[string]string{"DEBUG": ""},
		},
		{
			name:     "value with equals sign",
			input:    "DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=disable",
			expected: map[string]string{"DATABASE_URL": "postgres://user:pass@host:5432/db?sslmode=disable"},
		},
		{
			name:     "whitespace trimming",
			input:    "  KEY = VALUE  ",
			expected: map[string]string{"KEY": "VALUE"},
		},
		{
			name:     "mixed comments and entries",
			input:    "# Database\nDB_HOST=localhost\nDB_PORT=5432\n\n# API\nAPI_KEY=abc123",
			expected: map[string]string{"DB_HOST": "localhost", "DB_PORT": "5432", "API_KEY": "abc123"},
		},
		{
			name: "real-world .env block",
			input: `# Production Config
DB_HOST=prod-db.example.com
DB_PORT=5432
DB_USER=admin
DB_PASSWORD="super secret password"
API_KEY=sk_live_51M
REDIS_URL=redis://cache:6379
DEBUG=
export NODE_ENV=production
SENTRY_DSN='https://key@sentry.io/123'
`,
			expected: map[string]string{
				"DB_HOST":     "prod-db.example.com",
				"DB_PORT":     "5432",
				"DB_USER":     "admin",
				"DB_PASSWORD": "super secret password",
				"API_KEY":     "sk_live_51M",
				"REDIS_URL":   "redis://cache:6379",
				"DEBUG":       "",
				"NODE_ENV":    "production",
				"SENTRY_DSN":  "https://key@sentry.io/123",
			},
		},
		// Error cases
		{
			name:    "no equals sign",
			input:   "INVALID_LINE",
			wantErr: true,
			errMsg:  "line 1: invalid format",
		},
		{
			name:    "unclosed double quote",
			input:   `KEY="unclosed value`,
			wantErr: true,
			errMsg:  "line 1: unclosed double quote",
		},
		{
			name:    "unclosed single quote",
			input:   "KEY='unclosed value",
			wantErr: true,
			errMsg:  "line 1: unclosed single quote",
		},
		{
			name:    "empty key",
			input:   "=VALUE",
			wantErr: true,
			errMsg:  "line 1: empty key",
		},
		{
			name:    "error on specific line",
			input:   "GOOD=value\nBAD_LINE\nALSO_GOOD=value",
			wantErr: true,
			errMsg:  "line 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseEnv(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMsg)
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got: %v", tt.errMsg, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d entries, got %d: %v", len(tt.expected), len(result), result)
			}

			for k, v := range tt.expected {
				got, ok := result[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				if got != v {
					t.Errorf("key %q: expected %q, got %q", k, v, got)
				}
			}
		})
	}
}

func TestParseEnv_EmptyInput(t *testing.T) {
	result, err := ParseEnv("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty map, got %v", result)
	}
}

func TestParseEnv_OnlyComments(t *testing.T) {
	result, err := ParseEnv("# comment 1\n# comment 2\n# comment 3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty map, got %v", result)
	}
}

func TestParseEnv_DuplicateKeys_LastWins(t *testing.T) {
	input := "KEY=first\nKEY=second"
	result, err := ParseEnv(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["KEY"] != "second" {
		t.Errorf("expected last value 'second', got %q", result["KEY"])
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
