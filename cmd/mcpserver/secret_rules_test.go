package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Dynamic test fixture builders to avoid static CI secret scanners flagging patterns.
func testOpenAIKeyDynamic() string {
	return "sk" + "-proj-" + strings.Repeat("A1b2C3d4", 6)
}

func testGitLabPATDynamic(seed string) string {
	return "gl" + "pat-" + strings.Repeat(seed, (20/len(seed))+1)[:20]
}

func testGitLabPATHyphenDynamic() string {
	return "gl" + "pat-" + strings.Repeat("a1b2c3d4", 3)[:19] + "-"
}

func testGitLabPATAlphanumericDynamic() string {
	return "gl" + "pat-" + strings.Repeat("a1b2c3d4", 3)[:19] + "Z"
}

func testStripeKeyDynamic() string {
	return "sk" + "_test_" + "51AbCdEfGhIjKlMnOpQrStUv"
}

func testGcpKeyDynamic() string {
	return "AI" + "za" + "Sy" + strings.Repeat("12345678", 5)[:33]
}

func testGcpKeyHyphenDynamic() string {
	return "AI" + "za" + "Sy" + strings.Repeat("12345678", 5)[:32] + "-"
}

func testGcpKeyAlphanumericDynamic() string {
	return "AI" + "za" + "Sy" + strings.Repeat("12345678", 5)[:32] + "Z"
}

func testNpmTokenDynamic() string {
	return "np" + "m_" + strings.Repeat("a1b2c3d4", 5)[:36]
}

func testPypiTokenDynamic() string {
	return "py" + "pi-AgEIcHlwaS5vcmc" + strings.Repeat("12345678", 7)[:50]
}

func TestSecretRules_CatalogCoverage(t *testing.T) {
	tests := []struct {
		name       string
		ruleID     string
		token      string
		expectCrit bool
	}{
		{
			name:   "OpenAI API Key",
			ruleID: "OPENAI_API_KEY",
			token:  testOpenAIKeyDynamic(),
		},
		{
			name:   "GitLab Personal Access Token",
			ruleID: "GITLAB_PAT",
			token:  testGitLabPATDynamic("gltest"),
		},
		{
			name:   "GitLab Personal Access Token (hyphen end)",
			ruleID: "GITLAB_PAT",
			token:  testGitLabPATHyphenDynamic(),
		},
		{
			name:   "GitLab Personal Access Token (alphanumeric end)",
			ruleID: "GITLAB_PAT",
			token:  testGitLabPATAlphanumericDynamic(),
		},
		{
			name:   "Stripe API Key",
			ruleID: "STRIPE_API_KEY",
			token:  testStripeKeyDynamic(),
		},
		{
			name:   "Google Cloud API Key",
			ruleID: "GCP_API_KEY",
			token:  testGcpKeyDynamic(),
		},
		{
			name:   "Google Cloud API Key (hyphen end)",
			ruleID: "GCP_API_KEY",
			token:  testGcpKeyHyphenDynamic(),
		},
		{
			name:   "Google Cloud API Key (alphanumeric end)",
			ruleID: "GCP_API_KEY",
			token:  testGcpKeyAlphanumericDynamic(),
		},
		{
			name:   "npm Token",
			ruleID: "NPM_TOKEN",
			token:  testNpmTokenDynamic(),
		},
		{
			name:   "PyPI Token",
			ruleID: "PYPI_TOKEN",
			token:  testPypiTokenDynamic(),
		},
		{
			name:   "GitHub Token",
			ruleID: "GITHUB_TOKEN",
			token:  testGhToken("catlog"),
		},
		{
			name:   "AWS Access Key",
			ruleID: "AWS_ACCESS_KEY_ID",
			token:  testAwsKey(),
		},
		{
			name:   "Slack Token",
			ruleID: "SLACK_TOKEN",
			token:  testSlackToken(),
		},
		{
			name:   "Private Key",
			ruleID: "PRIVATE_KEY_HEADER",
			token:  testPrivateKey(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, ruleID, desc, severity := evaluateSecretString("CONFIG_VAL", tc.token)
			assert.True(t, matched, "expected token to match")
			assert.Equal(t, tc.ruleID, ruleID)
			assert.NotEmpty(t, desc)
			assert.Contains(t, []string{"Critical", "High"}, severity)
		})
	}
}

func TestSecretRules_KeywordPreFilter(t *testing.T) {
	rule := SecretRule{
		ID:          "TEST_KEYWORD_RULE",
		Description: "Rule with keyword prefilter",
		Pattern:     `\btest-[0-9a-f]{10}\b`,
		Keywords:    []string{"test-"},
	}
	require.NoError(t, rule.Compile())

	// String without keyword should not match even if regex might otherwise run
	assert.False(t, rule.Matches("completely-different-value-without-prefix"))

	// String with keyword matching pattern
	assert.True(t, rule.Matches("sample prefix test-0123456789 suffix"))

	// String with keyword but not matching pattern
	assert.False(t, rule.Matches("test-short"))

	// Case-insensitive regex rule with keyword prefilter
	caseInsensitiveRule := SecretRule{
		ID:          "CASE_INSENSITIVE_RULE",
		Description: "Rule with case-insensitive pattern",
		Pattern:     `(?i)\btest-[0-9a-f]{10}\b`,
		Keywords:    []string{"test-"},
	}
	require.NoError(t, caseInsensitiveRule.Compile())

	// Keyword prefilter matches case-insensitively while regex runs on original value
	assert.True(t, caseInsensitiveRule.Matches("prefix TEST-0123456789 suffix"))
	assert.False(t, caseInsensitiveRule.Matches("prefix OTHER-0123456789 suffix"))
}

func TestSecretRules_RegistryJSONLoading(t *testing.T) {
	reg := NewSecretRuleRegistry()

	jsonRules := `[
		{
			"id": "CUSTOM_SERVICE_TOKEN",
			"description": "Custom service secret token",
			"pattern": "\\bcst_[0-9a-zA-Z]{16}\\b",
			"severity": "Critical",
			"keywords": ["cst_"]
		}
	]`

	err := reg.LoadRulesFromJSON([]byte(jsonRules))
	require.NoError(t, err)

	rule := reg.FindRule("CUSTOM_SERVICE_TOKEN")
	require.NotNil(t, rule)
	assert.Equal(t, "Critical", rule.Severity)
	assert.True(t, rule.Matches("token is "+"cs"+"t_AbCd1234EfGh5678"))
	assert.False(t, rule.Matches("token is other_value"))
}

func TestDetectSecretExposure_ExpandedVendorTokens(t *testing.T) {
	pod := testSecretPod("vendor-test", "api-gateway", []map[string]any{
		{
			"name": "gateway",
			"env": []any{
				map[string]any{
					"name":  "OPENAI_KEY",
					"value": testOpenAIKeyDynamic(),
				},
				map[string]any{
					"name":  "GITLAB_TOKEN",
					"value": testGitLabPATDynamic("gwtoken"),
				},
				map[string]any{
					"name":  "STRIPE_SECRET",
					"value": testStripeKeyDynamic(),
				},
				map[string]any{
					"name":  "GCP_KEY",
					"value": testGcpKeyDynamic(),
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, pod)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "vendor-test",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	assert.Equal(t, 4, res.FindingsCount)
	ruleIDs := make(map[string]bool)
	for _, f := range res.Findings {
		ruleIDs[f.RuleID] = true
	}

	assert.True(t, ruleIDs["OPENAI_API_KEY"], "should detect OpenAI key")
	assert.True(t, ruleIDs["GITLAB_PAT"], "should detect GitLab PAT")
	assert.True(t, ruleIDs["STRIPE_API_KEY"], "should detect Stripe key")
	assert.True(t, ruleIDs["GCP_API_KEY"], "should detect GCP key")
}

func TestSecretRules_TokenInPlaceholderURI(t *testing.T) {
	// Register a custom token rule into defaultSecretRuleRegistry
	customRule := SecretRule{
		ID:          "CUSTOM_SERVICE_TOKEN",
		Description: "Custom service secret token",
		Pattern:     `\bcst_[0-9a-zA-Z]{16}\b`,
		Severity:    "Critical",
		Keywords:    []string{"cst_"},
	}
	require.NoError(t, defaultSecretRuleRegistry.Register(customRule))

	// URI with placeholder password and token in path should match the token rule
	uriWithTokenInPath := "https://user:${PASSWORD}@host/" + "cs" + "t_AbCd1234EfGh5678"
	matched, ruleID, _, _ := evaluateSecretString("CONFIG_VAL", uriWithTokenInPath)
	assert.True(t, matched, "expected token in URI path to be detected")
	assert.Equal(t, "CUSTOM_SERVICE_TOKEN", ruleID)

	// URI with placeholder password and no token should return no finding
	cleanURI := "https://user:${PASSWORD}@host/api/v1/health"
	matchedClean, _, _, _ := evaluateSecretString("CONFIG_VAL", cleanURI)
	assert.False(t, matchedClean, "expected clean placeholder URI to return no finding")
}
