package conformance

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The detect.services suite: loopback servers of six common protocols, each a
// credential sentinel. A service detection tool runs at tier 1, so it may
// read what a server sends, send a protocol greeting and a TLS handshake, and
// nothing that logs in: a fixture that receives an authentication payload (an
// SSH user authentication of any method, a MySQL handshake response, a Redis
// AUTH, an SMTP AUTH or a relay attempt, an LDAP bind, an HTTP Authorization
// header or a state-changing HTTP method) records it and the suite fails.
//
// The suite also checks what the tool reports: every service it reports is
// one it was given (same value), the six are identified (application
// protocol, TLS for the TLS fixture), the Redis fixture, which requires
// authentication, is never reported as anonymous, and every string is
// bounded and clean: a banner of at most MaxServiceBanner bytes of valid
// UTF-8 with no control character, at most MaxServiceDetails details of at
// most MaxServiceDetailValue bytes each. The SMTP fixture's greeting is
// hostile on purpose (terminal escapes, CR/LF inside a multi-line greeting,
// markup, invalid UTF-8, more than 512 bytes).

// Bounds of a detect.services record.
const (
	MaxServiceBanner      = 512
	MaxServiceDetails     = 16
	MaxServiceDetailValue = 256
	// maxServiceString bounds product, version, CPE and the other strings.
	maxServiceString = 256
	maxServiceKey    = 64
)

// Fixture names.
const (
	FixtureSSH   = "ssh"
	FixtureRedis = "redis"
	FixtureMySQL = "mysql"
	FixtureSMTP  = "smtp"
	FixtureHTTP  = "http"
	FixtureTLS   = "tls"
	FixtureLDAP  = "ldap"
)

// hostileSMTPGreeting is the SMTP fixture's greeting: a valid multi-line 220
// reply whose text carries what a banner must never pass on raw.
var hostileSMTPGreeting = "220-conformance.example ESMTP \x1b]0;owned\x07\x1b[31mred\x1b[0m\r\n" +
	"220-<script>alert(1)</script> \xff\xfe\x00 not utf-8\r\n" +
	"220 " + strings.Repeat("A", 700) + "\r\n"

// expectedProtocols are the application protocol names a tool may report for
// each fixture (IANA service names and the usual tool spellings); the
// platform normalises them. The TLS fixture must also be reported as TLS.
var expectedProtocols = map[string][]string{
	FixtureSSH:   {"ssh"},
	FixtureRedis: {"redis"},
	FixtureMySQL: {"mysql"},
	FixtureSMTP:  {"smtp", "esmtp", "smtps"},
	FixtureHTTP:  {"http", "www", "www-http", "http-alt"},
	FixtureTLS:   {"https", "http", "http2", "h2", "ssl/http", "ssl/https"},
}

// ServiceFixtures are the running fixtures of the detect.services suite.
type ServiceFixtures struct {
	mu       sync.Mutex
	attempts []string
	addrs    map[string]string // fixture -> host:port
	closers  []func()
}

// StartServiceFixtures starts the fixtures on 127.0.0.1. Close them when done.
func StartServiceFixtures() (*ServiceFixtures, error) {
	f := &ServiceFixtures{addrs: map[string]string{}}
	starts := []struct {
		name  string
		start func() (string, func(), error)
	}{
		{FixtureSSH, f.startSSH},
		{FixtureRedis, func() (string, func(), error) { return f.serveTCP(f.redisConn) }},
		{FixtureMySQL, func() (string, func(), error) { return f.serveTCP(f.mysqlConn) }},
		{FixtureSMTP, func() (string, func(), error) { return f.serveTCP(f.smtpConn) }},
		{FixtureLDAP, func() (string, func(), error) { return f.serveTCP(f.ldapConn) }},
		{FixtureHTTP, func() (string, func(), error) { return f.startHTTP(false) }},
		{FixtureTLS, func() (string, func(), error) { return f.startHTTP(true) }},
	}
	for _, s := range starts {
		addr, closeFn, err := s.start()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("fixture %s: %w", s.name, err)
		}
		f.addrs[s.name] = addr
		f.closers = append(f.closers, closeFn)
	}
	return f, nil
}

// Close stops every fixture.
func (f *ServiceFixtures) Close() {
	for _, c := range f.closers {
		c()
	}
	f.closers = nil
}

// Value is the CTIS service value of a fixture ("127.0.0.1:port/tcp").
func (f *ServiceFixtures) Value(name string) string {
	if a, ok := f.addrs[name]; ok {
		return a + "/tcp"
	}
	return ""
}

// Targets are the fixtures as service targets, in a stable order.
func (f *ServiceFixtures) Targets() []tool.Target {
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range f.addrs {
			if !yield(n) {
				return
			}
		}
	})
	out := make([]tool.Target, 0, len(names))
	for i, n := range names {
		out = append(out, tool.Target{Ref: "s" + strconv.Itoa(i), Type: string(ctis.AssetTypeService), Value: f.Value(n)})
	}
	return out
}

// CredentialAttempts are the authentication payloads the fixtures received,
// one line each ("ssh: password authentication as admin").
func (f *ServiceFixtures) CredentialAttempts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attempts)
}

func (f *ServiceFixtures) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.attempts) < 100 {
		f.attempts = append(f.attempts, fmt.Sprintf(format, args...))
	}
}

// Problems checks a tool's report on the fixtures: the credential sentinel
// first, then identification, then the bounds of every reported service.
func (f *ServiceFixtures) Problems(rep *ctis.Report) []string {
	var out []string
	for _, a := range f.CredentialAttempts() {
		out = append(out, "credential sentinel: "+a)
	}
	if rep == nil {
		// The run failed (reported by the caller): only the sentinel speaks.
		return out
	}
	inputs := map[string]string{}
	for n := range f.addrs {
		inputs[f.Value(n)] = n
	}
	found := map[string]*ctis.ServiceTechnical{}
	{
		for _, a := range rep.Assets {
			if a.Type != ctis.AssetTypeService {
				continue
			}
			name, ok := inputs[a.Value]
			if !ok {
				out = append(out, fmt.Sprintf("reported service %s, which it was not given (a service keeps the value of its input port)", clipFor(a.Value)))
				continue
			}
			if a.Technical == nil || a.Technical.Service == nil {
				out = append(out, fmt.Sprintf("%s: service %s has no technical.service", name, a.Value))
				continue
			}
			found[name] = a.Technical.Service
			out = append(out, serviceBounds(name, a.Technical.Service)...)
		}
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range expectedProtocols {
			if !yield(n) {
				return
			}
		}
	}) {
		s := found[name]
		if s == nil {
			out = append(out, fmt.Sprintf("%s: the fixture on %s was not reported", name, f.Value(name)))
			continue
		}
		if !slices.Contains(expectedProtocols[name], strings.ToLower(s.AppProtocol)) {
			out = append(out, fmt.Sprintf("%s: app_protocol %s, want one of %v", name, clipFor(s.AppProtocol), expectedProtocols[name]))
		}
		if name == FixtureTLS && !s.IsTLS {
			out = append(out, "tls: the TLS fixture was not reported with is_tls")
		}
		if name != FixtureTLS && s.IsTLS {
			out = append(out, name+": a plain-text fixture was reported with is_tls")
		}
	}
	if s := found[FixtureRedis]; s != nil && s.HasAnonymousAccess {
		out = append(out, "redis: reported has_anonymous_access, but the fixture answers every command with NOAUTH")
	}
	return out
}

// serviceBounds checks the strings of one reported service.
func serviceBounds(name string, s *ctis.ServiceTechnical) []string {
	var out []string
	check := func(field, v string, max int) {
		if len(v) > max {
			out = append(out, fmt.Sprintf("%s: %s is %d bytes, at most %d", name, field, len(v), max))
		}
		if p := dirtyText(v); p != "" {
			out = append(out, fmt.Sprintf("%s: %s %s", name, field, p))
		}
	}
	check("banner", s.Banner, MaxServiceBanner)
	check("extra_info", s.ExtraInfo, MaxServiceBanner)
	check("app_protocol", s.AppProtocol, maxServiceKey)
	check("product", s.Product, maxServiceString)
	check("version", s.Version, maxServiceString)
	check("cpe", s.CPE, maxServiceString)
	if len(s.Details) > MaxServiceDetails {
		out = append(out, fmt.Sprintf("%s: %d details, at most %d", name, len(s.Details), MaxServiceDetails))
	}
	for k, v := range s.Details {
		check("details key", k, maxServiceKey)
		check("details["+clipFor(k)+"]", v, MaxServiceDetailValue)
	}
	for _, m := range s.AuthMethods {
		check("auth_methods", m, maxServiceKey)
	}
	return out
}

// dirtyText says what is wrong with a reported string: invalid UTF-8 or a
// control character (C0, DEL, C1: ESC, CR, LF, NUL and the rest). Empty when
// clean.
func dirtyText(v string) string {
	if !utf8.ValidString(v) {
		return "is not valid UTF-8"
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Sprintf("carries the control character %U", r)
		}
	}
	return ""
}

func clipFor(v string) string {
	if len(v) > 64 {
		v = v[:64]
	}
	return strconv.Quote(v)
}

// DetectServicesParams are the standard params a detect.services suite task
// carries: every probe allowed (thorough, since the fixtures listen on
// random ports, not their protocols' usual ones), TCP, a short timeout.
func DetectServicesParams() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"depth":      json.RawMessage(`"thorough"`),
		"transports": json.RawMessage(`["tcp"]`),
		"timeout_ms": json.RawMessage(`1500`),
		"rate":       json.RawMessage(`50`),
	}
}

// DetectServicesSuite runs the detect.services suite with run, which runs
// one task of the tool under test and returns its report: a tool compiled
// into a sensor passes a function that runs it with pkg/testkit, an exec
// tool is checked by RunContractSuite. The task carries the fixtures as
// service targets and DetectServicesParams.
func DetectServicesSuite(t T, run func(tool.Task) (*ctis.Report, error)) {
	t.Helper()
	f, err := StartServiceFixtures()
	if err != nil {
		t.Fatalf("detect.services fixtures: %v", err)
		return
	}
	defer f.Close()
	rep, err := run(tool.Task{Capability: "detect.services@1", Targets: f.Targets(), Params: DetectServicesParams()})
	if err != nil {
		t.Errorf("detect.services: %v", err)
	}
	for _, p := range f.Problems(rep) {
		t.Errorf("detect.services: %s", p)
	}
}

// --- fixtures ---

// serveTCP accepts connections on 127.0.0.1 and hands each to handle (with a
// deadline, so a tool that holds a connection open cannot stall the suite).
func (f *ServiceFixtures) serveTCP(handle func(net.Conn)) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				handle(c)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); wg.Wait() }, nil
}

// startSSH is an SSH server whose every authentication callback (none,
// password, public key, keyboard-interactive) records the attempt.
func (f *ServiceFixtures) startSSH() (string, func(), error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return "", nil, err
	}
	refuse := errors.New("refused")
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.6 conformance",
		NoClientAuth:  true,
		NoClientAuthCallback: func(m ssh.ConnMetadata) (*ssh.Permissions, error) {
			f.record("ssh: authentication (method none) as %s", clipFor(m.User()))
			return nil, refuse
		},
		PasswordCallback: func(m ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			f.record("ssh: password authentication as %s", clipFor(m.User()))
			return nil, refuse
		},
		PublicKeyCallback: func(m ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			f.record("ssh: public key authentication as %s", clipFor(m.User()))
			return nil, refuse
		},
		KeyboardInteractiveCallback: func(m ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			f.record("ssh: keyboard-interactive authentication as %s", clipFor(m.User()))
			return nil, refuse
		},
	}
	cfg.AddHostKey(signer)
	return f.serveTCP(func(c net.Conn) {
		if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
			go ssh.DiscardRequests(reqs)
			for ch := range chans {
				_ = ch.Reject(ssh.Prohibited, "conformance")
			}
			_ = sc.Close()
		}
	})
}

// redisConn answers every command with NOAUTH (the server requires a
// password) and records AUTH and HELLO ... AUTH.
func (f *ServiceFixtures) redisConn(c net.Conn) {
	br := bufio.NewReaderSize(c, 4096)
	for range 64 {
		args, err := readRESP(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		if cmd == "AUTH" || (cmd == "HELLO" && slices.ContainsFunc(args[1:], func(a string) bool { return strings.EqualFold(a, "AUTH") })) {
			f.record("redis: %s command (authentication)", cmd)
		}
		if _, err := io.WriteString(c, "-NOAUTH Authentication required.\r\n"); err != nil {
			return
		}
	}
}

// readRESP reads one Redis command: a RESP array of bulk strings or an
// inline command line.
func readRESP(br *bufio.Reader) ([]string, error) {
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 || n > 64 {
		return nil, errors.New("bad array")
	}
	out := make([]string, 0, n)
	for range n {
		h, err := readLine(br)
		if err != nil || !strings.HasPrefix(h, "$") {
			return nil, errors.New("bad bulk")
		}
		size, err := strconv.Atoi(h[1:])
		if err != nil || size < 0 || size > 4096 {
			return nil, errors.New("bad bulk size")
		}
		b := make([]byte, size+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		out = append(out, string(b[:size]))
	}
	return out, nil
}

func readLine(br *bufio.Reader) (string, error) {
	b, err := br.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// mysqlConn sends a protocol 10 handshake; the client's first packet after
// it is a handshake response (a login) or a TLS request that precedes one,
// so any byte the client sends is recorded.
func (f *ServiceFixtures) mysqlConn(c net.Conn) {
	if _, err := c.Write(mysqlGreeting()); err != nil {
		return
	}
	buf := make([]byte, 512)
	if n, _ := c.Read(buf); n > 0 {
		f.record("mysql: the client answered the handshake (%d bytes: a login or a TLS request before one)", n)
	}
}

// mysqlGreeting is a protocol 10 initial handshake packet.
func mysqlGreeting() []byte {
	var p bytes.Buffer
	p.WriteByte(10)
	p.WriteString("8.0.36-conformance")
	p.WriteByte(0)
	p.Write([]byte{0x2a, 0, 0, 0})                                // connection id
	p.WriteString("abcdefgh")                                     // auth-plugin-data part 1
	p.WriteByte(0)                                                // filler
	p.Write([]byte{0xff, 0xf7})                                   // capability flags (lower)
	p.WriteByte(0xff)                                             // character set
	p.Write([]byte{0x02, 0x00})                                   // status flags
	p.Write([]byte{0xff, 0xdf})                                   // capability flags (upper)
	p.WriteByte(21)                                               // auth-plugin-data length
	p.Write(make([]byte, 10))                                     // reserved
	p.WriteString("ijklmnopqrst")                                 // auth-plugin-data part 2
	p.WriteByte(0)                                                //
	p.WriteString("caching_sha2_password")                        // auth plugin name
	p.WriteByte(0)                                                //
	hdr := binary.LittleEndian.AppendUint32(nil, uint32(p.Len())) //nolint:gosec // a fixed packet of under 100 bytes
	hdr[3] = 0                                                    // sequence id
	return append(hdr, p.Bytes()...)
}

// smtpConn greets with the hostile greeting, answers EHLO with AUTH
// advertised, and records AUTH and the relay commands (MAIL, RCPT, DATA).
func (f *ServiceFixtures) smtpConn(c net.Conn) {
	if _, err := io.WriteString(c, hostileSMTPGreeting); err != nil {
		return
	}
	br := bufio.NewReaderSize(c, 4096)
	for range 32 {
		line, err := readLine(br)
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.SplitN(strings.TrimSpace(line), " ", 2)[0])
		var reply string
		switch verb {
		case "EHLO", "HELO":
			reply = "250-conformance.example\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10240000\r\n"
		case "AUTH":
			f.record("smtp: AUTH command (authentication)")
			reply = "535 5.7.8 refused\r\n"
		case "MAIL", "RCPT", "DATA":
			f.record("smtp: %s command (a mail transaction or relay test)", verb)
			reply = "550 refused\r\n"
		case "STARTTLS":
			reply = "454 TLS not available\r\n"
		case "QUIT":
			_, _ = io.WriteString(c, "221 bye\r\n")
			return
		default:
			reply = "502 5.5.2 not implemented\r\n"
		}
		if _, err := io.WriteString(c, reply); err != nil {
			return
		}
	}
}

// ldapConn answers a search with an empty successful result and records a
// bind request (BER tag [APPLICATION 0]).
func (f *ServiceFixtures) ldapConn(c net.Conn) {
	buf := make([]byte, 4096)
	for range 16 {
		n, _ := c.Read(buf)
		if n == 0 {
			return
		}
		id, op, ok := ldapMessage(buf[:n])
		if !ok {
			return
		}
		switch op {
		case 0x60:
			f.record("ldap: bind request (authentication)")
			// bindResponse invalidCredentials
			_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00})
		case 0x63:
			// searchResDone success
			_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		default:
			return
		}
	}
}

// ldapMessage reads the message id (one byte) and the protocol op tag of an
// LDAPMessage.
func ldapMessage(b []byte) (id, op byte, ok bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, 0, false
	}
	i := 2
	if b[1]&0x80 != 0 {
		i += int(b[1] & 0x7f)
	}
	if len(b) < i+4 || b[i] != 0x02 || b[i+1] != 0x01 {
		return 0, 0, false
	}
	return b[i+2], b[i+3], true
}

// startHTTP is an HTTP (or HTTPS with ALPN h2 and http/1.1) server that
// records credentials and state-changing methods.
func (f *ServiceFixtures) startHTTP(useTLS bool) (string, func(), error) {
	name := FixtureHTTP
	if useTLS {
		name = FixtureTLS
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, hdr := range []string{"Authorization", "Proxy-Authorization"} {
			if r.Header.Get(hdr) != "" {
				f.record("%s: %s header (credentials)", name, hdr)
			}
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			f.record("%s: %s request (state-changing method)", name, clipFor(r.Method))
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><head><title>"+fixtureTitle+"</title></head><body>index</body></html>")
	})
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // a tool's probes of other protocols are expected
	if useTLS {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}
	return srv.Listener.Addr().String(), srv.Close, nil
}
