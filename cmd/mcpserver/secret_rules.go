package mcpserver

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// SecretRule defines an established secret pattern specification, aligned with
// standard secret detection frameworks like Gitleaks and TruffleHog.
type SecretRule struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Pattern     string         `json:"pattern,omitempty"`
	Regex       *regexp.Regexp `json:"-"`
	Severity    string         `json:"severity"`
	Keywords    []string       `json:"keywords,omitempty"`
	SecretGroup int            `json:"secretGroup,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// Compile compiles the rule's Pattern into Regex if not already set.
func (r *SecretRule) Compile() error {
	if r.Regex != nil {
		return nil
	}
	if r.Pattern == "" {
		return fmt.Errorf("rule %q has no pattern", r.ID)
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern for rule %q: %w", r.ID, err)
	}
	r.Regex = re
	return nil
}

// Matches evaluates whether the target string matches the rule.
// If Keywords are defined, a fast substring check runs before regex matching,
// drastically reducing regex invocation overhead on high-throughput scans.
func (r *SecretRule) Matches(val string) bool {
	if r.Regex == nil {
		return false
	}
	if len(r.Keywords) > 0 {
		lowerVal := strings.ToLower(val)
		hasKeyword := false
		for _, kw := range r.Keywords {
			if strings.Contains(lowerVal, strings.ToLower(kw)) {
				hasKeyword = true
				break
			}
		}
		if !hasKeyword {
			return false
		}
	}
	return r.Regex.MatchString(val)
}

// SecretRuleRegistry manages a thread-safe catalog of secret detection rules.
type SecretRuleRegistry struct {
	mu    sync.RWMutex
	rules []SecretRule
}

// NewSecretRuleRegistry constructs a new registry with the provided rules.
func NewSecretRuleRegistry(rules ...SecretRule) *SecretRuleRegistry {
	reg := &SecretRuleRegistry{
		rules: make([]SecretRule, 0, len(rules)),
	}
	for _, r := range rules {
		_ = reg.Register(r)
	}
	return reg
}

// Register adds a rule to the registry. If Regex is nil, it compiles the Pattern.
func (reg *SecretRuleRegistry) Register(r SecretRule) error {
	if err := r.Compile(); err != nil {
		return err
	}
	if r.Severity == "" {
		r.Severity = "High"
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.rules = append(reg.rules, r)
	return nil
}

// Rules returns a snapshot slice of all registered rules.
func (reg *SecretRuleRegistry) Rules() []SecretRule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	cp := make([]SecretRule, len(reg.rules))
	copy(cp, reg.rules)
	return cp
}

// FindRule returns a pointer to a registered rule by ID, or nil if not found.
func (reg *SecretRuleRegistry) FindRule(id string) *SecretRule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	for i := range reg.rules {
		if reg.rules[i].ID == id {
			r := reg.rules[i]
			return &r
		}
	}
	return nil
}

// MatchToken checks whether val matches any token-detection rule (excluding composite URI rules).
func (reg *SecretRuleRegistry) MatchToken(val string) *SecretRule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	for i := range reg.rules {
		if reg.rules[i].ID == "URI_CREDENTIALS" {
			continue
		}
		if reg.rules[i].Matches(val) {
			r := reg.rules[i]
			return &r
		}
	}
	return nil
}

// LoadRulesFromJSON parses a JSON array of Gitleaks-style rules and registers them.
func (reg *SecretRuleRegistry) LoadRulesFromJSON(data []byte) error {
	var rules []SecretRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse secret rules json: %w", err)
	}
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			return err
		}
	}
	return nil
}

// Built-in rule regexes
var (
	privateKeyRegex     = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)
	awsAccessKeyRegex   = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubTokenRegex    = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`)
	slackTokenRegex     = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]+\b`)
	jwtTokenRegex       = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+\b`)
	uriCredentialsRegex = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://((?:\{\{[^{}]*\}\}|[^:\s@/?#])+):((?:\{\{[^{}]*\}\}|[^\s/?#])+)@[^/?#,;|\s"'` + "`" + `]+`)

	// Standard expanded rulesets aligned with Gitleaks
	openaiKeyRegex = regexp.MustCompile(`\b(?:sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_\-]{40,})\b`)
	gitlabPatRegex = regexp.MustCompile(`\bglpat-[0-9a-zA-Z_\-]{20,}(?:[^0-9a-zA-Z_\-]|\z)`)
	stripeKeyRegex = regexp.MustCompile(`\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b`)
	gcpApiKeyRegex = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}(?:[^0-9A-Za-z_\-]|\z)`)
	npmTokenRegex  = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)
	pypiTokenRegex = regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b`)
)

// defaultSecretRuleDefinitions defines the battle-tested, established standard secret ruleset.
var defaultSecretRuleDefinitions = []SecretRule{
	{
		ID:          "PRIVATE_KEY_HEADER",
		Description: "Private key detected in configuration data",
		Pattern:     `-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`,
		Regex:       privateKeyRegex,
		Severity:    "Critical",
		Keywords:    []string{"-----BEGIN"},
		Tags:        []string{"key", "asymmetric"},
	},
	{
		ID:          "GITHUB_TOKEN",
		Description: "GitHub personal access token detected in configuration data",
		Pattern:     `\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`,
		Regex:       githubTokenRegex,
		Severity:    "Critical",
		Keywords:    []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Tags:        []string{"token", "github"},
	},
	{
		ID:          "OPENAI_API_KEY",
		Description: "OpenAI API key detected in configuration data",
		Pattern:     `\b(?:sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_\-]{40,})\b`,
		Regex:       openaiKeyRegex,
		Severity:    "Critical",
		Keywords:    []string{"sk-", "sk-proj-"},
		Tags:        []string{"token", "openai"},
	},
	{
		ID:          "GITLAB_PAT",
		Description: "GitLab Personal Access Token detected in configuration data",
		Pattern:     `\bglpat-[0-9a-zA-Z_\-]{20,}(?:[^0-9a-zA-Z_\-]|\z)`,
		Regex:       gitlabPatRegex,
		Severity:    "Critical",
		Keywords:    []string{"glpat-"},
		Tags:        []string{"token", "gitlab"},
	},
	{
		ID:          "STRIPE_API_KEY",
		Description: "Stripe API key detected in configuration data",
		Pattern:     `\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b`,
		Regex:       stripeKeyRegex,
		Severity:    "Critical",
		Keywords:    []string{"sk_test_", "sk_live_", "rk_test_", "rk_live_"},
		Tags:        []string{"token", "stripe"},
	},
	{
		ID:          "AWS_ACCESS_KEY_ID",
		Description: "AWS Access Key ID detected in configuration data",
		Pattern:     `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
		Regex:       awsAccessKeyRegex,
		Severity:    "High",
		Keywords:    []string{"AKIA", "ASIA"},
		Tags:        []string{"key", "aws"},
	},
	{
		ID:          "GCP_API_KEY",
		Description: "Google Cloud API key detected in configuration data",
		Pattern:     `\bAIza[0-9A-Za-z_\-]{35}(?:[^0-9A-Za-z_\-]|\z)`,
		Regex:       gcpApiKeyRegex,
		Severity:    "High",
		Keywords:    []string{"AIza"},
		Tags:        []string{"key", "gcp"},
	},
	{
		ID:          "SLACK_TOKEN",
		Description: "Slack API token detected in configuration data",
		Pattern:     `\bxox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]+\b`,
		Regex:       slackTokenRegex,
		Severity:    "High",
		Keywords:    []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
		Tags:        []string{"token", "slack"},
	},
	{
		ID:          "NPM_TOKEN",
		Description: "npm access token detected in configuration data",
		Pattern:     `\bnpm_[A-Za-z0-9]{36}\b`,
		Regex:       npmTokenRegex,
		Severity:    "High",
		Keywords:    []string{"npm_"},
		Tags:        []string{"token", "npm"},
	},
	{
		ID:          "PYPI_TOKEN",
		Description: "PyPI upload token detected in configuration data",
		Pattern:     `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b`,
		Regex:       pypiTokenRegex,
		Severity:    "High",
		Keywords:    []string{"pypi-AgEIcHlwaS5vcmc"},
		Tags:        []string{"token", "pypi"},
	},
	{
		ID:          "JWT_TOKEN",
		Description: "JSON Web Token (JWT) detected in configuration data",
		Pattern:     `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+\b`,
		Regex:       jwtTokenRegex,
		Severity:    "High",
		Keywords:    []string{"eyJ"},
		Tags:        []string{"token", "jwt"},
	},
	{
		ID:          "URI_CREDENTIALS",
		Description: "Connection URI with embedded credentials detected in configuration data",
		Pattern:     `\b[a-zA-Z][a-zA-Z0-9+.-]*://((?:\{\{[^{}]*\}\}|[^:\s@/?#])+):((?:\{\{[^{}]*\}\}|[^\s/?#])+)@[^/?#,;|\s"'` + "`" + `]+`,
		Regex:       uriCredentialsRegex,
		Severity:    "High",
		Keywords:    []string{"://"},
		Tags:        []string{"uri", "credentials"},
	},
}

// defaultSecretRuleRegistry is the global default registry for detect_secret_exposure.
var defaultSecretRuleRegistry = NewSecretRuleRegistry(defaultSecretRuleDefinitions...)

// isHighConfidenceToken checks if a string matches any registered token pattern.
func isHighConfidenceToken(val string) bool {
	return defaultSecretRuleRegistry.MatchToken(val) != nil
}
