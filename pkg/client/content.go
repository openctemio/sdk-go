package client

import (
	"net/http"

	"github.com/openctemio/sdk-go/pkg/sensorkit/contentcache"
)

// ContentPath is the prefix of the platform's sensor content routes:
// desired state, packs by digest, a pack's file index and its files.
const ContentPath = "/api/v2/sensor/content"

// ContentFetcher is the sensor's content fetcher on this client's
// connection and credentials: content comes from the platform only, never
// from upstreams (research/139).
func (c *Client) ContentFetcher() *contentcache.HTTPFetcher {
	return &contentcache.HTTPFetcher{BaseURL: c.baseURL + ContentPath, Do: c.doContent}
}

// doContent sends one authenticated content request (bearer key, or the
// key-bound transport's signature) with the client's user agent.
func (c *Client) doContent(req *http.Request) (*http.Response, error) {
	if err := c.checkBaseURL(); err != nil {
		return nil, err
	}
	c.setAuth(req)
	req.Header.Set("User-Agent", c.userAgentHeader())
	return c.httpFor(req.Context()).Do(req)
}
