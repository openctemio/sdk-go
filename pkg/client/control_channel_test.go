package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

func controlTestStatus() *core.SensorStatus {
	return &core.SensorStatus{Name: "t", Status: core.SensorStateRunning, Control: &core.ControlStats{IntervalSeconds: 30}}
}

// A heartbeat does not wait for a connection the data plane holds: it has a
// connection pool of its own (api RFC-035 §5.1).
func TestHeartbeat_OwnConnectionPool(t *testing.T) {
	block, dataIn := make(chan struct{}), make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "heartbeat") {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		dataIn <- struct{}{}
		<-block // a slow upload
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	defer close(block)

	c := New(&Config{BaseURL: srv.URL, APIKey: "k", Protocol: ProtocolV1, MaxRetries: 1, RetryDelay: time.Millisecond})
	// One connection to the platform for the data plane, held by the upload.
	c.httpClient.Transport.(*http.Transport).MaxConnsPerHost = 1
	go func() {
		_, _ = c.doRequest(context.Background(), http.MethodPost, srv.URL+"/api/v1/ingest", []byte(`{}`))
	}()
	<-dataIn

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := c.SendHeartbeat(ctx, controlTestStatus()); err != nil {
		t.Fatalf("heartbeat behind a held data connection: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("heartbeat took %s", d)
	}
}

// A failed heartbeat is sent again at most once (the sensor's loop sends a
// fresh one soon), not three times with 30 s timeouts.
func TestHeartbeat_RetriedOnceAtMost(t *testing.T) {
	var beats atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "heartbeat") {
			beats.Add(1)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "k", Protocol: ProtocolV1, MaxRetries: 3, RetryDelay: time.Millisecond})
	if err := c.SendHeartbeat(context.Background(), controlTestStatus()); err == nil {
		t.Fatal("want the error")
	}
	if n := beats.Load(); n != 1+controlRetries {
		t.Fatalf("heartbeat sent %d times, want %d", n, 1+controlRetries)
	}
}

// A heartbeat the platform does not answer gives up after ControlTimeout,
// whatever the data plane's timeout.
func TestHeartbeat_ControlTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := New(&Config{BaseURL: srv.URL, APIKey: "k", Protocol: ProtocolV1, Timeout: 30 * time.Second,
		ControlTimeout: 150 * time.Millisecond, RetryDelay: time.Millisecond})
	start := time.Now()
	if err := c.SendHeartbeat(context.Background(), controlTestStatus()); err == nil {
		t.Fatal("want a timeout")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("heartbeat gave up after %s, want about 2 x 150ms", d)
	}
	if c.controlHTTP().Timeout != 150*time.Millisecond || c.httpClient.Timeout != 30*time.Second {
		t.Fatalf("timeouts: control %s, data %s", c.controlHTTP().Timeout, c.httpClient.Timeout)
	}
}

// The control client keeps the API client's transport settings (proxy, TLS,
// dial guard) and never outlives its timeout.
func TestControlHTTP_ClonesTheAPITransport(t *testing.T) {
	c := New(&Config{BaseURL: "https://platform.example", APIKey: "k", Timeout: 5 * time.Second})
	base := c.httpClient.Transport.(*http.Transport)
	ctl := c.controlHTTP()
	tr, ok := ctl.Transport.(*http.Transport)
	if !ok || tr == base {
		t.Fatal("the control client shares the data plane's transport")
	}
	if tr.Proxy == nil || tr.DialContext == nil || (base.TLSClientConfig != nil) != (tr.TLSClientConfig != nil) {
		t.Fatal("the control transport lost the API transport's settings")
	}
	if ctl.Timeout != 5*time.Second { // never above the API client's timeout
		t.Fatalf("control timeout %s", ctl.Timeout)
	}
	if ctl.CheckRedirect == nil {
		t.Fatal("the control client follows redirects")
	}
	// The data plane is untouched.
	if c.httpFor(context.Background()) != c.httpClient || c.httpFor(withControl(context.Background())) != ctl {
		t.Fatal("httpFor picks the wrong client")
	}
}

// The heartbeat goes through the platform path's proxy (api RFC-034,
// SENSOR_CONTROL_PROXY), like every other request to the platform.
func TestControlHTTP_UsesTheControlProxy(t *testing.T) {
	setting, err := httpsec.ParseProxySetting("http://proxy.internal:3128", "")
	if err != nil {
		t.Fatal(err)
	}
	httpsec.SetAPIProxy(setting)
	t.Cleanup(func() { httpsec.SetAPIProxy(httpsec.ProxySetting{}) })
	c := New(&Config{BaseURL: "https://platform.example", APIKey: "k"})
	req, _ := http.NewRequest(http.MethodPost, "https://platform.example/api/v2/sensor/heartbeat", nil)
	u, err := c.controlHTTP().Transport.(*http.Transport).Proxy(req)
	if err != nil || u == nil || u.Host != "proxy.internal:3128" {
		t.Fatalf("control proxy = %v, %v; want proxy.internal:3128", u, err)
	}
}
