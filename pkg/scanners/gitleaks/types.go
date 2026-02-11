// Package gitleaks provides a scanner implementation for the Gitleaks secret detection tool.
package gitleaks

import (
	"encoding/json"
	"fmt"
	"io"
)

// Finding represents a secret finding from gitleaks JSON output.
// This matches the gitleaks report format.
type Finding struct {
	// Rule information
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`

	// Location
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`

	// Content
	Match  string `json:"Match"`  // Full matched line
	Secret string `json:"Secret"` // The detected secret value

	// Git metadata
	Commit      string        `json:"Commit"`
	Author      string        `json:"Author"`
	Email       string        `json:"Email"`
	Date        string        `json:"Date"`
	Message     string        `json:"Message"`
	SymlinkFile string        `json:"Symlinkfile"`
	Fingerprint string        `json:"Fingerprint"`
	Tags        []interface{} `json:"Tags"`

	// Analysis
	Entropy float64 `json:"Entropy"`
}

// Report represents a gitleaks scan report.
type Report struct {
	Findings []Finding
}

// ParseJSON parses gitleaks JSON output from a reader.
func ParseJSON(r io.Reader) ([]Finding, error) {
	var findings []Finding
	if err := json.NewDecoder(r).Decode(&findings); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks JSON: %w", err)
	}
	return findings, nil
}

// ParseJSONBytes parses gitleaks JSON output from bytes.
func ParseJSONBytes(data []byte) ([]Finding, error) {
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks JSON: %w", err)
	}
	return findings, nil
}

// SecretType maps gitleaks rule IDs to secret types.
var SecretType = map[string]string{
	"aws-access-key-id":         "aws_access_key",
	"aws-secret-access-key":     "aws_secret_key",
	"github-pat":                "github_token",
	"github-oauth":              "github_oauth",
	"github-app-token":          "github_app_token",
	"github-refresh-token":      "github_refresh_token",
	"gitlab-pat":                "gitlab_token",
	"gitlab-ptt":                "gitlab_trigger_token",
	"gitlab-rrt":                "gitlab_runner_token",
	"slack-webhook-url":         "slack_webhook",
	"slack-bot-token":           "slack_token",
	"slack-user-token":          "slack_token",
	"slack-app-level-token":     "slack_token",
	"stripe-api-key":            "stripe_api_key",
	"stripe-secret-key":         "stripe_secret_key",
	"twilio-api-key":            "twilio_api_key",
	"sendgrid-api-key":          "sendgrid_api_key",
	"mailchimp-api-key":         "mailchimp_api_key",
	"mailgun-api-key":           "mailgun_api_key",
	"npm-access-token":          "npm_token",
	"pypi-api-token":            "pypi_token",
	"nuget-api-key":             "nuget_api_key",
	"dockerhub-password":        "docker_password",
	"google-api-key":            "google_api_key",
	"gcp-api-key":               "gcp_api_key",
	"azure-storage-key":         "azure_storage_key",
	"heroku-api-key":            "heroku_api_key",
	"digitalocean-token":        "digitalocean_token",
	"alibaba-access-key-id":     "alibaba_access_key",
	"alibaba-secret-access-key": "alibaba_secret_key",
	"jwt":                       "jwt_token",
	"private-key":               "private_key",
	"generic-api-key":           "api_key",
	"password-in-url":           "password",
	"basic-auth-credentials":    "basic_auth",
}

// ServiceName maps gitleaks rule IDs to service names.
var ServiceName = map[string]string{
	"aws-access-key-id":         "AWS",
	"aws-secret-access-key":     "AWS",
	"github-pat":                "GitHub",
	"github-oauth":              "GitHub",
	"github-app-token":          "GitHub",
	"github-refresh-token":      "GitHub",
	"gitlab-pat":                "GitLab",
	"gitlab-ptt":                "GitLab",
	"gitlab-rrt":                "GitLab",
	"slack-webhook-url":         "Slack",
	"slack-bot-token":           "Slack",
	"slack-user-token":          "Slack",
	"slack-app-level-token":     "Slack",
	"stripe-api-key":            "Stripe",
	"stripe-secret-key":         "Stripe",
	"twilio-api-key":            "Twilio",
	"sendgrid-api-key":          "SendGrid",
	"mailchimp-api-key":         "Mailchimp",
	"mailgun-api-key":           "Mailgun",
	"npm-access-token":          "NPM",
	"pypi-api-token":            "PyPI",
	"nuget-api-key":             "NuGet",
	"dockerhub-password":        "Docker Hub",
	"google-api-key":            "Google",
	"gcp-api-key":               "GCP",
	"azure-storage-key":         "Azure",
	"heroku-api-key":            "Heroku",
	"digitalocean-token":        "DigitalOcean",
	"alibaba-access-key-id":     "Alibaba Cloud",
	"alibaba-secret-access-key": "Alibaba Cloud",
	"jwt":                       "JWT",
	"private-key":               "SSH/TLS",
	"generic-api-key":           "Generic",
	"password-in-url":           "Generic",
	"basic-auth-credentials":    "Generic",
}

// GetSecretType returns the secret type for a rule ID.
func GetSecretType(ruleID string) string {
	if t, ok := SecretType[ruleID]; ok {
		return t
	}
	return "secret"
}

// GetServiceName returns the service name for a rule ID.
func GetServiceName(ruleID string) string {
	if s, ok := ServiceName[ruleID]; ok {
		return s
	}
	return "Unknown"
}
