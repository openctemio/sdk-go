package netctx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Iface is one network interface as detection sees it.
type Iface struct {
	Name  string
	Flags net.Flags
	// Addrs are the interface's addresses with their prefix lengths.
	Addrs []netip.Prefix
}

// Route is one routing table entry.
type Route struct {
	Prefix  netip.Prefix
	Gateway netip.Addr // zero: on-link
	Iface   string
}

// Sources are where detection reads from. The zero value reads the host
// (DefaultSources); tests replace each one.
type Sources struct {
	// Interfaces lists the host's interfaces.
	Interfaces func() ([]Iface, error)
	// RouteV4 and RouteV6 return the Linux routing tables
	// (/proc/net/route, /proc/net/ipv6_route); nil, or an error, means
	// "unknown" (other systems).
	RouteV4, RouteV6 func() ([]byte, error)
	// ResolvConf returns /etc/resolv.conf.
	ResolvConf func() ([]byte, error)
	// Lookup reads the environment (SENSOR_DNS_RESOLVERS).
	Lookup func(string) (string, bool)
}

// DefaultSources reads this host.
func DefaultSources() Sources {
	s := Sources{
		Interfaces: hostInterfaces,
		ResolvConf: func() ([]byte, error) { return os.ReadFile("/etc/resolv.conf") },
		Lookup:     os.LookupEnv,
	}
	if runtime.GOOS == "linux" {
		s.RouteV4 = func() ([]byte, error) { return os.ReadFile("/proc/net/route") }
		s.RouteV6 = func() ([]byte, error) { return os.ReadFile("/proc/net/ipv6_route") }
	}
	return s
}

func hostInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, in := range ifs {
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		it := Iface{Name: in.Name, Flags: in.Flags}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ad, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			ad = ad.Unmap()
			if ad.Is4() && ones > 32 {
				ones -= 96
			}
			it.Addrs = append(it.Addrs, netip.PrefixFrom(ad, ones))
		}
		out = append(out, it)
	}
	return out, nil
}

// Detected is what detection found on the host.
type Detected struct {
	// OnLink are the prefixes of the host's own interfaces (container and
	// virtual bridges left out), sorted.
	OnLink []netip.Prefix
	// RoutesKnown: the routing table could be read.
	RoutesKnown bool
	// Routes are the usable routes (rejected and loopback left out).
	Routes []Route
	// DefaultV4 and DefaultV6: a default route exists (meaningful only
	// when RoutesKnown).
	DefaultV4, DefaultV6 bool
	// Gateways are the default routes' next hops, sorted.
	Gateways []netip.Addr
	// SystemResolvers are resolv.conf's name servers; Resolvers are the
	// ones the sensor's tools use (SENSOR_DNS_RESOLVERS when set).
	SystemResolvers, Resolvers []netip.Addr
	// ResolversFromEnv: Resolvers come from SENSOR_DNS_RESOLVERS.
	ResolversFromEnv bool
	// ResolvConfRead: resolv.conf could be read.
	ResolvConfRead bool
	// SearchDomains are resolv.conf's search (or domain) entries.
	SearchDomains []string
}

// virtualIfacePrefixes name container, overlay and hypervisor bridges: their
// prefixes are not networks the sensor sits on.
var virtualIfacePrefixes = []string{
	"docker", "br-", "veth", "cni", "flannel", "cali", "cilium", "weave", "virbr", "vxlan",
	"podman", "lxcbr", "lxdbr", "kube-", "vnet", "tunl0", "nodelocaldns",
}

func virtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Detect reads the host's network facts from src. It makes no network call.
// A source that fails leaves its facts empty (unknown), never an error:
// a sensor runs without them.
func Detect(src Sources) Detected {
	var d Detected
	if src.Interfaces != nil {
		if ifs, err := src.Interfaces(); err == nil {
			d.OnLink = onLink(ifs)
		}
	}
	d.Routes, d.RoutesKnown = readRoutes(src)
	for _, r := range d.Routes {
		if r.Prefix.Bits() != 0 {
			continue
		}
		if r.Prefix.Addr().Is4() {
			d.DefaultV4 = true
		} else {
			d.DefaultV6 = true
		}
		if r.Gateway.IsValid() && !containsAddr(d.Gateways, r.Gateway) {
			d.Gateways = append(d.Gateways, r.Gateway)
		}
	}
	sortAddrs(d.Gateways)
	if src.ResolvConf != nil {
		if raw, err := src.ResolvConf(); err == nil {
			d.ResolvConfRead = true
			d.SystemResolvers, d.SearchDomains = parseResolvConf(raw)
		}
	}
	d.Resolvers = d.SystemResolvers
	if src.Lookup != nil {
		if v, ok := src.Lookup(EnvDNSResolvers); ok && strings.TrimSpace(v) != "" {
			d.Resolvers, d.ResolversFromEnv = parseResolverList(v), true
		}
	}
	return d
}

func onLink(ifs []Iface) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, in := range ifs {
		if in.Flags&net.FlagLoopback != 0 || in.Flags&net.FlagUp == 0 || virtualIface(in.Name) {
			continue
		}
		for _, a := range in.Addrs {
			ad := a.Addr().Unmap()
			if !ad.IsGlobalUnicast() || ad.IsLinkLocalUnicast() {
				continue
			}
			p := netip.PrefixFrom(ad, a.Bits()).Masked()
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sortPrefixes(out)
	return out
}

// Linux route flags.
const (
	rtfUp     = 0x0001
	rtfGW     = 0x0002
	rtfReject = 0x0200
)

func readRoutes(src Sources) ([]Route, bool) {
	var out []Route
	known := false
	if src.RouteV4 != nil {
		if raw, err := src.RouteV4(); err == nil {
			if rs, err := parseRouteV4(raw); err == nil {
				out, known = append(out, rs...), true
			}
		}
	}
	if src.RouteV6 != nil {
		if raw, err := src.RouteV6(); err == nil {
			if rs, err := parseRouteV6(raw); err == nil {
				out, known = append(out, rs...), true
			}
		}
	}
	return out, known
}

var errRouteFormat = errors.New("unexpected routing table format")

// parseRouteV4 reads /proc/net/route: a header, then Iface Destination
// Gateway Flags RefCnt Use Metric Mask ..., addresses in little-endian
// hex.
func parseRouteV4(raw []byte) ([]Route, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	if !sc.Scan() || !strings.HasPrefix(strings.TrimSpace(sc.Text()), "Iface") {
		return nil, errRouteFormat
	}
	var out []Route
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 || f[0] == "lo" {
			continue
		}
		dst, ok1 := leHex4(f[1])
		gw, ok2 := leHex4(f[2])
		mask, ok3 := leHex4(f[7])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		bits := maskBits(mask)
		if bits < 0 {
			continue
		}
		r := Route{Prefix: netip.PrefixFrom(dst, bits).Masked(), Iface: f[0]}
		if flags&rtfGW != 0 && !gw.IsUnspecified() {
			r.Gateway = gw
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func leHex4(s string) (netip.Addr, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return netip.AddrFrom4(b), true
}

// maskBits is the length of a contiguous IPv4 mask, -1 when not contiguous.
func maskBits(m netip.Addr) int {
	b := m.As4()
	v := binary.BigEndian.Uint32(b[:])
	n := 0
	for v&0x80000000 != 0 {
		n++
		v <<= 1
	}
	if v != 0 {
		return -1
	}
	return n
}

// parseRouteV6 reads /proc/net/ipv6_route: dest dest_len src src_len
// next_hop metric refcnt use flags iface, in hex.
func parseRouteV6(raw []byte) ([]Route, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	var out []Route
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			if len(f) > 0 {
				return nil, errRouteFormat
			}
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 || f[9] == "lo" {
			continue
		}
		dst, ok1 := hex16(f[0])
		gw, ok2 := hex16(f[4])
		bits, err := strconv.ParseUint(f[1], 16, 8)
		if !ok1 || !ok2 || err != nil || bits > 128 {
			continue
		}
		// Local, multicast and link-local entries are not routes out.
		if dst.IsMulticast() || dst.IsLinkLocalUnicast() || (bits == 128 && dst.IsLoopback()) {
			continue
		}
		r := Route{Prefix: netip.PrefixFrom(dst, int(bits)).Masked(), Iface: f[9]}
		if flags&rtfGW != 0 && !gw.IsUnspecified() {
			r.Gateway = gw
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func hex16(s string) (netip.Addr, bool) {
	if len(s) != 32 {
		return netip.Addr{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16([16]byte(b)), true
}

// parseResolvConf returns the name servers and the search domains (the
// last search or domain line wins, as in the resolver), bounded.
func parseResolvConf(raw []byte) ([]netip.Addr, []string) {
	var servers []netip.Addr
	var search []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if a, err := netip.ParseAddr(f[1]); err == nil {
				a = a.WithZone("").Unmap()
				if !containsAddr(servers, a) {
					servers = append(servers, a)
				}
			}
		case "search", "domain":
			search = search[:0]
			for _, d := range f[1:] {
				d = strings.TrimSuffix(strings.ToLower(d), ".")
				if validDomain(d) && !containsString(search, d) {
					search = append(search, d)
				}
			}
		}
	}
	if len(servers) > MaxResolvers {
		servers = servers[:MaxResolvers]
	}
	if len(search) > MaxSearchDomains {
		search = search[:MaxSearchDomains]
	}
	return servers, append([]string(nil), search...)
}

// parseResolverList reads SENSOR_DNS_RESOLVERS ("10.0.0.2,[2001:db8::53]:53,
// 10.0.0.3:53"); entries it cannot read are left out (the sensor that owns
// the setting validates it).
func parseResolverList(s string) []netip.Addr {
	var out []netip.Addr
	for _, it := range splitList(s) {
		host := it
		if h, _, err := net.SplitHostPort(it); err == nil {
			host = h
		}
		a, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			continue
		}
		a = a.WithZone("").Unmap()
		if !containsAddr(out, a) {
			out = append(out, a)
		}
		if len(out) == MaxResolvers {
			break
		}
	}
	return out
}

func containsAddr(as []netip.Addr, a netip.Addr) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func sortAddrs(as []netip.Addr) {
	sort.Slice(as, func(i, j int) bool { return as[i].Less(as[j]) })
}

// isPrivate reports whether a is in private space: RFC 1918, IPv6 ULA
// (fc00::/7) or shared address space (100.64.0.0/10).
func isPrivate(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Routed reports whether p is covered by a route of d (a default route
// covers everything of its family). Unknown routes report true: nothing to
// warn about.
func (d Detected) Routed(p netip.Prefix) bool {
	if !d.RoutesKnown {
		return true
	}
	for _, r := range d.Routes {
		if r.Prefix.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if r.Prefix.Bits() <= p.Bits() && r.Prefix.Contains(p.Addr()) {
			return true
		}
	}
	for _, o := range d.OnLink {
		if o.Addr().Is4() == p.Addr().Is4() && o.Bits() <= p.Bits() && o.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func sortStrings(ss []string) { sort.Strings(ss) }
