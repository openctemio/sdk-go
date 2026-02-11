// Example: Building a Custom Connector
//
// This example demonstrates how to build a custom connector
// by extending BaseConnector with rate limiting and authentication.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/openctemio/sdk-go/pkg/connectors"
	"github.com/openctemio/sdk-go/pkg/core"
)

// ShodanConnector is a connector for the Shodan API.
type ShodanConnector struct {
	*connectors.BaseConnector
}

// NewShodanConnector creates a new Shodan connector.
func NewShodanConnector(apiKey string, verbose bool) *ShodanConnector {
	baseConnector := connectors.NewBaseConnector(&connectors.BaseConnectorConfig{
		Name:    "shodan",
		Type:    "osint",
		BaseURL: "https://api.shodan.io",
		Config: &core.ConnectorConfig{
			APIKey:     apiKey,
			RateLimit:  1, // Shodan free tier: 1 req/sec
			BurstLimit: 1,
		},
		Verbose: verbose,
	})

	return &ShodanConnector{
		BaseConnector: baseConnector,
	}
}

// TestConnection verifies the Shodan API connection.
func (c *ShodanConnector) TestConnection(ctx context.Context) error {
	if err := c.WaitForRateLimit(ctx); err != nil {
		return err
	}

	req, err := c.NewRequest(ctx, "GET", "/api-info?key="+c.Config().APIKey, nil)
	if err != nil {
		return err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("shodan connection test: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("shodan auth failed: %s - %s", resp.Status, string(body))
	}

	if c.Verbose() {
		var info struct {
			QueryCredits int `json:"query_credits"`
			ScanCredits  int `json:"scan_credits"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err == nil {
			fmt.Printf("[shodan] Credits - Query: %d, Scan: %d\n", info.QueryCredits, info.ScanCredits)
		}
	}

	return nil
}

// SearchHost searches for information about a specific host.
func (c *ShodanConnector) SearchHost(ctx context.Context, ip string) (*HostInfo, error) {
	if err := c.WaitForRateLimit(ctx); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/shodan/host/%s?key=%s", ip, c.Config().APIKey)
	req, err := c.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("search host: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search host failed: %s - %s", resp.Status, string(body))
	}

	var info HostInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode host info: %w", err)
	}

	return &info, nil
}

// HostInfo represents Shodan host information.
type HostInfo struct {
	IP         string   `json:"ip_str"`
	Hostnames  []string `json:"hostnames"`
	Ports      []int    `json:"ports"`
	OS         string   `json:"os"`
	Org        string   `json:"org"`
	ISP        string   `json:"isp"`
	Country    string   `json:"country_name"`
	LastUpdate string   `json:"last_update"`
	Vulns      []string `json:"vulns"`
}

func main() {
	ctx := context.Background()

	// Create Shodan connector
	connector := NewShodanConnector(os.Getenv("SHODAN_API_KEY"), true)

	// Connect
	if err := connector.Connect(ctx); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer connector.Close()

	// Test connection
	if err := connector.TestConnection(ctx); err != nil {
		fmt.Printf("Connection test failed: %v\n", err)
		os.Exit(1)
	}

	// Search for a host
	ip := "8.8.8.8" // Google DNS
	info, err := connector.SearchHost(ctx, ip)
	if err != nil {
		fmt.Printf("Failed to search host: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nHost: %s\n", info.IP)
	fmt.Printf("Organization: %s\n", info.Org)
	fmt.Printf("Country: %s\n", info.Country)
	fmt.Printf("Open Ports: %v\n", info.Ports)
	if len(info.Vulns) > 0 {
		fmt.Printf("Vulnerabilities: %v\n", info.Vulns)
	}
}
