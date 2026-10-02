package core

import (
	"context"
	"testing"
)

func TestValidateExtraArgs(t *testing.T) {
	allowed := [][]string{
		nil,
		{},
		{"-severity", "critical,high"},
		{"-rate-limit", "50", "-timeout=10"},
		{"--exclude-tags", "dos"},
		{"-", "--"},
		{"-tags", "cve"},
		{"-rl", "150"}, // nuclei/dnsx rate limit, not subfinder's -rL list
	}
	for _, args := range allowed {
		if err := ValidateExtraArgs(args); err != nil {
			t.Errorf("ValidateExtraArgs(%q) = %v, want nil", args, err)
		}
	}

	rejected := [][]string{
		{"-proxy", "http://attacker:8080"},
		{"-proxy=http://attacker:8080"},
		{"-PROXY", "http://attacker:8080"},
		{" -t ", "/tmp/evil.yaml"},
		{"--templates=/tmp/evil"},
		{"-u", "http://169.254.169.254/"},
		{"-l", "/etc/targets"},
		{"--interactsh-url", "oast.attacker"},
		{"--headless"},
		{"-r", "1.2.3.4"},
		{"-o", "/etc/cron.d/x"},
		{"-severity", "high", "--config=/tmp/rules.yml"},
		// Dash count does not matter to Go's flag package.
		{"--o", "/etc/cron.d/x"},
		{"---proxy", "http://attacker:8080"},
		{"-config", "/tmp/evil.yaml"},
		{"-headless"},
		{"-interactsh-url=oast.attacker"},
		{"--il", "/etc/targets"},
		// naabu runs -nmap-cli as a command.
		{"-nmap-cli", "sh -c id"},
		{"--nmap-cli=sh -c id"},
		// Remote templates, code protocol, file exports.
		{"-tu", "https://attacker/evil.yaml"},
		{"-code"},
		{"-je", "/tmp/out.json"},
		{"--sarif-output=/etc/x"},
	}
	for _, args := range rejected {
		if err := ValidateExtraArgs(args); err == nil {
			t.Errorf("ValidateExtraArgs(%q) = nil, want an error", args)
		}
	}
}

// The base scanner must refuse a dangerous extra arg before it starts the
// tool, not pass it through.
func TestBaseScannerRejectsDangerousExtraArgs(t *testing.T) {
	s := &BaseScanner{}
	_, err := s.Scan(context.Background(), "example.com", &ScanOptions{ExtraArgs: []string{"-proxy", "http://attacker:8080"}})
	if err == nil {
		t.Fatal("Scan with -proxy in ExtraArgs returned nil error")
	}
}
