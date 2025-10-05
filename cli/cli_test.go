package cli

import (
	"fmt"
	"testing"

	"Vaverka/rule"
)

// Replace the ParseRule function
var ParseRuleFunc = rule.ParseRule

func TestParseArguments(t *testing.T) {
	// Mock the ParseRule function for testing
	originalParseRule := ParseRuleFunc
	ParseRuleFunc = func(ruleString string) (rule.Rule, error) {
		if ruleString == "invalid_rule" {
			return rule.Rule{}, fmt.Errorf("invalid rule: %s", ruleString)
		}
		return rule.Rule{}, nil
	}
	defer func() { ParseRuleFunc = originalParseRule }()

	testCases := []struct {
		name          string
		args          []string
		expectedIsAPI bool
		expectedRules []rule.Rule
		expectError   bool
	}{
		// Valid arguments
		{
			name:          "API mode only",
			args:          []string{"api"},
			expectedIsAPI: true,
			expectedRules: nil,
			expectError:   false,
		},
		{
			name:          "Single rule - localhost",
			args:          []string{"localhost"},
			expectedIsAPI: false,
			expectedRules: []rule.Rule{{}},
			expectError:   false,
		},
		{
			name:          "Multiple rules with flags",
			args:          []string{"localhost", "192.168.1.100/24:80,443,1000-2000:p:s:pps=1000000"},
			expectedIsAPI: false,
			expectedRules: []rule.Rule{{}, {}},
			expectError:   false,
		},
		// Invalid arguments
		{
			name:        "No arguments provided",
			args:        []string{},
			expectError: true,
		},
		{
			name:        "Invalid rule",
			args:        []string{"invalid_rule"},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := ParseArguments(tc.args)

			// Check for errors
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check rules
			if len(rules) != len(tc.expectedRules) {
				t.Errorf("Expected %d rules, but got %d", len(tc.expectedRules), len(rules))
			}
		})
	}
}
