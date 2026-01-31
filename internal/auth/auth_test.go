package auth

import (
    "net/http"
    "testing"
)

func TestGetAPIKey(t *testing.T) {
	type testCase struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		expectError   bool
	}

	tests := []testCase{
		{
			name:          "no auth header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			expectError:   true,
		},
		{
			name: "malformed auth header - wrong format",
			headers: http.Header{
				"Authorization": []string{"Bearer"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed auth header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer 12345"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-token"},
			},
			expectedKey:   "my-secret-token",
			expectedError: nil,
			expectError:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.headers)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tc.expectedError != nil && err != tc.expectedError {
					t.Errorf("Expected error %v, got %v", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error, but got: %v", err)
				}
			}

			if gotKey != tc.expectedKey {
				t.Errorf("Expected key %q, got %q", tc.expectedKey, gotKey)
			}
		})
	}
}