package egress

import (
	"errors"
	"io"
	"sync/atomic"
	"time"
)

// Requests on a tunnel the forwarder does not read.
//
// A connection the forwarder passes through (CONNECT or SOCKS5 with no
// guard: ordinary HTTPS) takes its share when it is opened: one token of the
// host's rate and one of the host's connection slots. A tool that keeps the
// tunnel alive and sends request after request on it would otherwise get
// any number of requests for that one token. The forwarder does not
// terminate TLS (it would break every check that inspects the certificate
// and put every scan's plaintext here), so it cannot read those requests.
// It can count them from the outside, and tunnelMeter does:
//
//   - On a TLS tunnel it reads the record headers the client sends (five
//     plaintext bytes per record: the type and the length; nothing is
//     decrypted). An application-data record that follows bytes from the
//     host starts a new request: HTTP/1.1 sends a request only after the
//     answer to the one before. The tunnel's first request is covered by the
//     connection's own token; every further one waits for a token of the
//     host's rate (and of its address's) before its first byte is passed
//     on. Handshake records cost nothing (in TLS 1.3 the client's Finished
//     travels as an application-data record: the first one is taken for
//     it, unless the client sent a TLS 1.2 Finished before; a TLS 1.3
//     handshake the server restarts, HelloRetryRequest, is read as TLS 1.2
//     and its Finished then counts as the tunnel's first request, so that
//     tunnel takes one token more, never fewer).
//   - A client that offers HTTP/2 (the "h2" protocol in its ClientHello,
//     which is plaintext) may multiplex: several requests travel without
//     the host speaking between them. On such a tunnel every
//     application-data record of the client takes a token, one for each
//     tunnelTurnBytes of it, whether the host spoke or not. A client that
//     writes each request in a record of its own (Go's HTTP/2 client does,
//     and nuclei, httpx and katana are built on it) is then counted once
//     per request or more (a window update or a request body is a record
//     too); the connection's first record, with the client's settings, is
//     the connection's own.
//   - On a tunnel that is not TLS, bytes from the client that follow bytes
//     from the host start a new request, counted the same way.
//   - Bytes: a token also covers at most tunnelTurnBytes of client data;
//     more than that without the host speaking takes another token. This
//     bounds what the counting above cannot see (see below) in bytes.
//   - Health: a request that follows bytes from the host says the host
//     answered the one before; that is reported to the host's rate
//     controller, so the rate of a host worked over kept-alive tunnels
//     climbs as it does over new connections.
//   - Lifetime: a tunnel older than tunnelLifetime carries no further
//     request; it is closed where the next one would start, before any byte
//     of it is passed on, so the tool's client opens a new connection (and
//     takes a token for it) and repeats the request.
//   - A request the host's breaker refuses (the host is backed off) closes
//     the tunnel the same way: an open breaker stops kept-alive tunnels
//     too, not only new connections.
//
// What this guarantees: for HTTP/1.1 over TLS (and over a raw tunnel), one
// request at a time per connection, the requests a host receives per second
// are within the host's rate exactly as on plain HTTP, and the requests in
// flight are within the host's connection slots. For any protocol, the
// client bytes a host receives per second on tunnels are at most the rate
// times the larger of tunnelTurnBytes and one TLS record (16 KiB).
//
// What it does not guarantee: the number of requests of a client that
// packs several into one TLS record (an HTTP/2 client that batches its
// frames, as a browser does when it starts many requests at once), or that
// pipelines HTTP/1.1 requests back to back without offering HTTP/2: there
// the count is too low, and only the byte bound (tunnelTurnBytes of
// requests per token) and the lifetime hold. For those, the tool's own
// rate flags (derived from the same budget) are the enforcement. It also
// cannot tell an upload from a second request: an upload of more than
// tunnelTurnBytes takes more tokens than one (it is slower, never faster).
const (
	// tunnelTurnBytes is the client data one rate token covers on a tunnel.
	// A scan's requests are a few hundred bytes to a couple of kilobytes,
	// so an ordinary request never takes a second token; a smaller value
	// would charge ordinary requests twice, a larger one would let more
	// small requests through per token where they cannot be told apart.
	// A single TLS record larger than this (up to 16 KiB) is one token.
	tunnelTurnBytes = 4 << 10
	// tunnelLifetime is how long a tunnel may carry requests: long enough
	// for a tool's connection reuse to save the handshakes of a burst of
	// requests, short enough that a tunnel whose requests the forwarder
	// cannot count (HTTP/2) takes a new token at least this often.
	tunnelLifetime = 2 * time.Minute
)

// errTunnelLifetime ends a tunnel that is older than tunnelLifetime.
var errTunnelLifetime = errors.New("egress: the tunnel reached its lifetime")

// TLS record types (RFC 8446 §5.1).
const (
	recChangeCipherSpec = 20 // 21 is an alert
	recHandshake        = 22
	recApplicationData  = 23
	// maxRecordLen is the most a record body may be (2^14 plus the
	// expansion TLS 1.2 allows).
	maxRecordLen = 16384 + 2048
)

type tunnelMode int

const (
	tunnelUnknown tunnelMode = iota
	tunnelTLS
	tunnelRaw
)

// tunnelMeter is the writer toward the host of one passed-through tunnel:
// it passes every byte on unchanged and makes each further request wait for
// charge (see above). It is used by one goroutine; hostSpoke is set by the
// other direction.
type tunnelMeter struct {
	w io.Writer
	// charge waits for one more request's rate tokens; an error ends the
	// tunnel. answered says the host sent bytes since the request before:
	// it answered that one.
	charge func(answered bool) error
	// born is when the tunnel was opened; now is replaced in tests.
	born time.Time
	now  func() time.Time
	// hostSpoke: the host sent bytes since the last request started.
	hostSpoke atomic.Bool

	mode tunnelMode
	// hdr holds the bytes of a record header read so far, remain the bytes
	// of the current record's body still to pass.
	hdr    [5]byte
	hdrN   int
	remain int
	// ccs: the client sent ChangeCipherSpec; tls12: it sent a handshake
	// record after it (the TLS 1.2 Finished), so every application-data
	// record is application data; finSeen: the TLS 1.3 Finished was taken.
	ccs, tls12, finSeen bool
	// tiny counts application-data records in a row that are too short to
	// hold a request (tinyRecord).
	tiny int
	// h2: the client's hello offers HTTP/2 (alpn found the protocol id in
	// it), so requests may travel without the host speaking between them:
	// every record takes a token. alpn is the matcher's state while the
	// hello passes; hello is set while the current record is part of it.
	h2    bool
	alpn  int
	hello bool
	// started: the tunnel's first request (covered by the dial) began; bytes
	// is the client data since the last token.
	started bool
	bytes   int
	// charged counts the tokens taken (tests).
	charged int
}

// tinyRecord is the longest application-data record that cannot hold a
// request by itself: a TLS alert (the close_notify that ends every
// connection is 19 bytes in TLS 1.3, 18 to 26 in TLS 1.2) or an HTTP/2
// settings acknowledgement. The shortest request is longer in every cipher
// suite (an HTTP/2 frame header alone is 9 bytes, 27 with the record's
// overhead; "GET / HTTP/1.0" is 35). One such record costs nothing: charged
// as a request, every connection took two tokens and its close waited for a
// token. Two in a row are counted, so a request cannot be passed as a
// string of short records.
const tinyRecord = 26

func newTunnelMeter(w io.Writer, charge func(answered bool) error) *tunnelMeter {
	return &tunnelMeter{w: w, charge: charge, born: time.Now(), now: time.Now}
}

// request accounts for n bytes of client data that begin at a point where a
// new request may start, and takes a token when one is due: when the host
// spoke since the request before, when the client data since the last
// token is over tunnelTurnBytes, and for every record of a client that may
// multiplex (one token for each tunnelTurnBytes of it).
func (m *tunnelMeter) request(n int) error {
	spoke := m.hostSpoke.Swap(false)
	if !m.started {
		m.started, m.bytes = true, n
		return nil
	}
	tokens := 1
	if m.h2 {
		tokens = max(1, (n+tunnelTurnBytes-1)/tunnelTurnBytes)
	} else if !spoke && m.bytes+n <= tunnelTurnBytes {
		m.bytes += n
		return nil
	}
	if m.now().Sub(m.born) > tunnelLifetime {
		return errTunnelLifetime
	}
	for i := range tokens {
		if err := m.charge(spoke && i == 0); err != nil {
			return err
		}
		m.charged++
	}
	m.bytes = n
	return nil
}

// offersH2 scans the bytes of the client's hello for the HTTP/2 protocol
// id as the ALPN extension writes it: a length byte of 2 and "h2". The
// hello is plaintext. A chance match in its random bytes (about one hello
// in ten thousand) only makes the count stricter.
func (m *tunnelMeter) offersH2(p []byte) {
	for _, b := range p {
		switch {
		case m.alpn == 1 && b == 'h':
			m.alpn = 2
		case m.alpn == 2 && b == '2':
			m.h2 = true
			return
		case b == 2:
			m.alpn = 1
		default:
			m.alpn = 0
		}
	}
}

// Write passes p on, taking a token before the first byte of each further
// request. It reports p as written when at most four bytes of a record
// header are held back for the rest of the header (Flush passes them on
// when the client's side ends).
//
// Whether the tunnel is TLS is read from its first bytes: a handshake
// record (0x16, 0x03). A tunnel that starts with anything else is counted
// as a raw one at once; nothing of it is held back.
func (m *tunnelMeter) Write(p []byte) (int, error) {
	done := 0
	for len(p) > 0 {
		if m.mode == tunnelUnknown && m.hdrN == 0 && p[0] != recHandshake {
			m.mode = tunnelRaw
		}
		if m.mode == tunnelRaw {
			if err := m.request(len(p)); err != nil {
				return done, err
			}
			n, err := m.w.Write(p)
			return done + n, err
		}
		if m.remain > 0 {
			n := min(m.remain, len(p))
			if m.hello && !m.h2 {
				m.offersH2(p[:n])
			}
			w, err := m.w.Write(p[:n])
			done += w
			if err != nil {
				return done, err
			}
			m.remain -= n
			p = p[n:]
			continue
		}
		take := min(len(m.hdr)-m.hdrN, len(p))
		copy(m.hdr[m.hdrN:], p[:take])
		m.hdrN += take
		p = p[take:]
		done += take
		if m.hdrN >= 2 && m.hdr[1] != 0x03 {
			// Not a TLS record: a raw tunnel. What was held goes on.
			m.mode = tunnelRaw
			if err := m.flushHeader(); err != nil {
				return done, err
			}
			continue
		}
		if m.hdrN < len(m.hdr) {
			return done, nil
		}
		typ, length := m.hdr[0], int(m.hdr[3])<<8|int(m.hdr[4])
		if typ < recChangeCipherSpec || typ > recApplicationData || length > maxRecordLen || (m.mode == tunnelUnknown && typ != recHandshake) {
			// Not a TLS record stream after all: count it as a raw tunnel.
			m.mode = tunnelRaw
			if err := m.flushHeader(); err != nil {
				return done, err
			}
			continue
		}
		m.mode = tunnelTLS
		// The client's hello: its handshake records before anything else.
		m.hello = typ == recHandshake && !m.ccs && !m.finSeen && !m.started
		switch typ {
		case recChangeCipherSpec:
			m.ccs = true
		case recHandshake:
			if m.ccs {
				m.tls12 = true
			}
		case recApplicationData:
			if !m.tls12 && !m.finSeen {
				m.finSeen = true // the TLS 1.3 Finished
				break
			}
			if length <= tinyRecord {
				if m.tiny++; m.tiny < 2 {
					break // an alert or a control frame, not a request
				}
			}
			m.tiny = 0
			if err := m.request(length); err != nil {
				return done, err
			}
		}
		if err := m.flushHeader(); err != nil {
			return done, err
		}
		m.remain = length
	}
	return done, nil
}

// flushHeader passes the held header bytes on.
func (m *tunnelMeter) flushHeader() error {
	n := m.hdrN
	m.hdrN = 0
	if n == 0 {
		return nil
	}
	_, err := m.w.Write(m.hdr[:n])
	return err
}

// Flush passes on what Write held back (a partial record header at the end
// of the client's side).
func (m *tunnelMeter) Flush() error { return m.flushHeader() }

// spokeReader marks on the meter that the host sent bytes.
type spokeReader struct {
	r io.Reader
	m *tunnelMeter
}

func (s spokeReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.m.hostSpoke.Store(true)
	}
	return n, err
}
