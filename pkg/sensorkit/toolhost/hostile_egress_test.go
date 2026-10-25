package toolhost

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// egressSilent sends a plain HTTP request to its target through the proxy;
// the target never answers, so the tool gives up after a second (as
// nuclei's host breaker does) and exits with what it found.
func egressSilent() int {
	proxyAddr := strings.TrimPrefix(os.Getenv("HTTP_PROXY"), "http://")
	if c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second); err == nil {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		target := os.Getenv("TOOLHOST_TARGET")
		fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		_, _ = bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
	}
	fmt.Printf(`{"version":"1.3","metadata":{"timestamp":"2026-01-01T00:00:00Z"},"findings":[{"type":"misconfiguration","title":"gave up","severity":"low"}]}` + "\n")
	return 0
}
