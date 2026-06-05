package tenable

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

const sampleNessus = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Rolling batch 1">
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
        <tag name="host-fqdn">web01.corp.local</tag>
        <tag name="operating-system">Linux Kernel 5.4</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="4" pluginID="98765" pluginName="OpenSSL Heartbleed" pluginFamily="General">
        <synopsis>Information disclosure vulnerability.</synopsis>
        <description>The version of OpenSSL is vulnerable to Heartbleed.</description>
        <solution>Upgrade OpenSSL to 1.0.1g or later.</solution>
        <cvss_base_score>5.0</cvss_base_score>
        <cvss3_base_score>7.5</cvss3_base_score>
        <vpr_score>8.9</vpr_score>
        <exploit_available>true</exploit_available>
        <cpe>cpe:/a:openssl:openssl</cpe>
        <cve>CVE-2014-0160</cve>
        <cve>CVE-2014-0346</cve>
        <see_also>https://heartbleed.com</see_also>
        <plugin_output>TLSv1.1 heartbeat extension enabled.</plugin_output>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
        <synopsis>Scan info.</synopsis>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.6">
      <HostProperties><tag name="host-ip">10.0.0.6</tag></HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func TestConvert_ReportShapeAndMapping(t *testing.T) {
	rep, err := Convert(strings.NewReader(sampleNessus), ConvertOptions{
		ScanSessionID: "batch-1",
		ToolName:      "tenable",
		Now:           time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	// Safety-critical report shape (scoped auto-resolve).
	if rep.Tool == nil || rep.Tool.Name != "tenable" {
		t.Fatalf("tool name must be set, got %+v", rep.Tool)
	}
	if rep.Metadata.ID != "batch-1" || rep.Metadata.CoverageType != "full" {
		t.Fatalf("metadata id/coverage wrong: %+v", rep.Metadata)
	}
	if rep.Metadata.Branch == nil || !rep.Metadata.Branch.IsDefaultBranch {
		t.Fatal("synthetic default branch required for auto-resolve")
	}

	if len(rep.Assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(rep.Assets))
	}
	if rep.Assets[0].Value != "web01.corp.local" {
		t.Fatalf("FQDN preferred, got %q", rep.Assets[0].Value)
	}
	if rep.Assets[1].Type != ctis.AssetTypeIPAddress {
		t.Fatalf("ip-only host should be ip_address, got %s", rep.Assets[1].Type)
	}

	// MinSeverity 0 → includes the info item.
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(rep.Findings))
	}
	var crit *ctis.Finding
	for i := range rep.Findings {
		if rep.Findings[i].RuleID == "98765" {
			crit = &rep.Findings[i]
		}
	}
	if crit == nil {
		t.Fatal("heartbleed finding missing")
	}
	if crit.Severity != ctis.SeverityCritical {
		t.Fatalf("severity 4 → critical, got %q", crit.Severity)
	}
	if crit.Vulnerability == nil || len(crit.Vulnerability.CVEIDs) != 2 ||
		crit.Vulnerability.VPRScore != 8.9 || !crit.Vulnerability.ExploitAvailable ||
		crit.Vulnerability.CVSSScore != 7.5 {
		t.Fatalf("vuln details wrong: %+v", crit.Vulnerability)
	}
	if crit.Network == nil || crit.Network.Port != 443 || crit.Network.Service != "https" {
		t.Fatalf("network wrong: %+v", crit.Network)
	}
	if !strings.Contains(crit.Evidence, "heartbeat") {
		t.Fatalf("evidence wrong: %q", crit.Evidence)
	}
	if crit.Fingerprint != "nessus:web01.corp.local:98765:443/tcp" {
		t.Fatalf("fingerprint wrong: %q", crit.Fingerprint)
	}
}

func TestConvert_MinSeverityFilter(t *testing.T) {
	rep, _ := Convert(strings.NewReader(sampleNessus), ConvertOptions{ScanSessionID: "x", MinSeverity: 1})
	if len(rep.Findings) != 1 {
		t.Fatalf("MinSeverity=1 should drop info item, got %d", len(rep.Findings))
	}
}

func TestConvert_InvalidXML(t *testing.T) {
	if _, err := Convert(strings.NewReader("nope <<<"), ConvertOptions{}); err == nil {
		t.Fatal("expected error on invalid XML")
	}
}
