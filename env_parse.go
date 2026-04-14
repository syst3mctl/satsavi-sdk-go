package satsavi

import (
	"bufio"
	"fmt"
	"strings"
)

// ParseEnv parses raw .env file content into a map[string]string.
//
// It supports:
//   - KEY=VALUE pairs
//   - Comment lines (# ...)
//   - Empty lines (skipped)
//   - Double-quoted values ("...")
//   - Single-quoted values ('...')
//   - Inline comments (KEY=val # comment) — only outside quotes
//   - export prefix (export KEY=VALUE)
//   - Empty values (KEY=) — included with empty string
//   - Values containing = signs (URL=postgres://host/db?opt=1)
//   - Whitespace trimming around keys and values
//
// Returns descriptive errors with line numbers for malformed input.
func ParseEnv(raw string) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip "export " prefix
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimPrefix(line, "export ")
			line = strings.TrimSpace(line)
		}

		// Must contain '=' to be a valid entry
		eqIdx := strings.Index(line, "=")
		if eqIdx == -1 {
			return nil, fmt.Errorf("line %d: invalid format (missing '='): %s", lineNum, line)
		}

		key := strings.TrimSpace(line[:eqIdx])
		rawValue := line[eqIdx+1:]

		// Validate key is not empty
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNum)
		}

		// Parse the value (handle quotes, inline comments)
		value, err := parseValue(rawValue, lineNum)
		if err != nil {
			return nil, err
		}

		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read env content: %w", err)
	}

	return result, nil
}

// parseValue handles quote stripping and inline comment removal for a raw value.
func parseValue(raw string, lineNum int) (string, error) {
	raw = strings.TrimSpace(raw)

	// Empty value — valid (SDK-friendly)
	if raw == "" {
		return "", nil
	}

	// Double-quoted value
	if strings.HasPrefix(raw, "\"") {
		closeIdx := strings.Index(raw[1:], "\"")
		if closeIdx == -1 {
			return "", fmt.Errorf("line %d: unclosed double quote", lineNum)
		}
		// Return the content inside the quotes (preserves spaces, #, etc.)
		return raw[1 : closeIdx+1], nil
	}

	// Single-quoted value
	if strings.HasPrefix(raw, "'") {
		closeIdx := strings.Index(raw[1:], "'")
		if closeIdx == -1 {
			return "", fmt.Errorf("line %d: unclosed single quote", lineNum)
		}
		// Return the content inside the quotes
		return raw[1 : closeIdx+1], nil
	}

	// Unquoted value — strip inline comments (# preceded by whitespace)
	if commentIdx := strings.Index(raw, " #"); commentIdx != -1 {
		raw = raw[:commentIdx]
	}

	return strings.TrimSpace(raw), nil
}
