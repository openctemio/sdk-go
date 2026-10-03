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
		{"-timeout=10"},
		{"--exclude-tags", "dos"},
		{"-", "--"},
		{"-tags", "cve"},
		{"-etags", "intrusive"},
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

// Every nuclei v3.11 flag that loads code, file, self-contained or headless
// templates, switches signature checking off, or pulls templates or targets
// from somewhere the sensor did not choose is refused, in every spelling.
func TestValidateExtraArgsRefusesTemplateTrustFlags(t *testing.T) {
	rejected := []string{
		"-code", "--code", "-CODE", "-code=true",
		"-file", "-esc", "-enable-self-contained", "-egm",
		"-dut=false", "-disable-unsigned-templates=false", "-sign",
		"-headless", "-ho", "-cdpe", "-sc", "-dast", "-fuzz",
		"-turl", "-wurl", "-ai", "-prompt", "-tp", "-profile", "-it", "-vfp",
		"-targets-inline", "-uncover", "-uq", "-sa", "-resume",
		"-p", "-pi",
		"-cc", "-client-key", "-ca",
		"-pd", "-dashboard-upload", "-auth", "-dts", "-hae", "-ep",
		"-up", "-ut", "-ud", "-reset", "-pe", "-project-path",
	}
	for _, arg := range rejected {
		if err := ValidateExtraArgs([]string{arg}); err == nil {
			t.Errorf("ValidateExtraArgs(%q) = nil, want an error", arg)
		}
	}
}

// Rate-limit flags never arrive as extra args: the typed options are capped
// by the sensor, a free-form flag would not be.
func TestValidateExtraArgsRefusesRateLimitFlags(t *testing.T) {
	rejected := [][]string{
		{"-rate-limit", "100000"},
		{"-rl", "100000"},
		{"--rate-limit=100000"},
		{"-per-host-rate-limit"},
		{"-bs", "1000"},
		{"-bulk-size=1000"},
		{"-c", "500"},
		{"-concurrency", "500"},
		{"-pc", "500"},
		{"-rate", "100000"}, // naabu
		{"-threads", "500"},
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
