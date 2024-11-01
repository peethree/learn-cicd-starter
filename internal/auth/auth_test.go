package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	// ErrNoAuthHeaderIncluded is returned when no authorization header is included
	var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectError error
	}{
		{
			name:        "Valid Authorization Header",
			headers:     http.Header{"Authorization": []string{"ApiKey my-api-key"}},
			expectedKey: "my-api-key",
			expectError: nil,
		},
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectError: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header - Missing ApiKey prefix",
			headers:     http.Header{"Authorization": []string{"Bearer my-api-key"}},
			expectedKey: "",
			expectError: errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization Header - Missing Key",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectError: errors.New("malformed authorization header"),
		},
		// {
		// 	name:        "Malformed Authorization Header - Empty Value",
		// 	headers:     http.Header{"Authorization": []string{"ApiKey "}},
		// 	expectedKey: "",
		// 	expectError: errors.New("malformed authorization header"),
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("expected key: %s, got: %s", tt.expectedKey, key)
			}
			if err != nil && tt.expectError != nil && err.Error() != tt.expectError.Error() {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
			if err == nil && tt.expectError != nil {
				t.Errorf("expected error: %v, got no error", tt.expectError)
			}
			if err != nil && tt.expectError == nil {
				t.Errorf("did not expect an error, got: %v", err)
			}
		})
	}
}
