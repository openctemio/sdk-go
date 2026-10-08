//go:build linux

package executor

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// runConfined is the confined launcher's first step: it starts itself again
// (the inner launcher) in new user, network and mount namespaces, passes
// its standard streams and signals through, and returns the inner
// launcher's exit status. It is a fresh process, so the kernel lets it
// write the new namespace's id maps; it makes itself non-dumpable once the
// inner launcher has started. rest is "--" and the tool's argv.
func runConfined(ls launchSpec, rest []string) int {
	ls.Inner = true
	enc, err := ls.encode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openctem sandbox: %v\n", err)
		return launcherExit
	}
	cmd := exec.Command("/proc/self/exe", append([]string{LauncherArg, enc}, rest...)...) //nolint:gosec // this program
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	confineAttrs(cmd)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGINT, unix.SIGHUP)
	if err := cmd.Start(); err != nil {
		if ls.Probe {
			st := Status{Backend: "process", Missing: []string{"network: user namespaces: " + err.Error()}}
			_ = json.NewEncoder(os.Stdout).Encode(st)
			return 0
		}
		fmt.Fprintf(os.Stderr, "openctem sandbox: network: user namespaces: %v\n", err)
		return launcherExit
	}
	makeUndumpable()
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	return exitStatus(cmd.Wait())
}

// exitStatus is a child's exit code, 128+signal when a signal ended it.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return launcherExit
}

// confineAttrs makes the launcher start in its own user, network and mount
// namespaces, as root of the user namespace mapped to this process's user
// (no other id is mapped, so it gains nothing outside).
func confineAttrs(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	a := cmd.SysProcAttr
	a.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS
	a.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	a.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	a.GidMappingsEnableSetgroups = false
}

// setupNetwork runs in the launcher, inside the new namespaces, before the
// sandbox is applied: it brings up loopback (the only interface), points
// the resolver at the relay, and starts the relays to the forwarder.
func setupNetwork(ls launchSpec) error {
	if err := loopbackUp(); err != nil {
		return fmt.Errorf("loopback: %w", err)
	}
	// The resolver: /etc/resolv.conf names the relay where this mount
	// namespace may be changed; where it may not (a container profile
	// that denies mount), the relay answers on every address the file
	// names, each added to loopback.
	dnsAddrs := []string{RelayDNSAddr}
	if err := bindResolvConf(ls.Workdir); err != nil {
		servers, rerr := nameservers("/etc/resolv.conf")
		if rerr != nil {
			return fmt.Errorf("resolver: %w (and %w)", err, rerr)
		}
		// 127.0.0.1:53 is always served too: a tool told to use it (a DNS
		// tool given -r 127.0.0.1) finds the relay there.
		for _, s := range servers {
			if !s.IsLoopback() {
				if err := addLoopbackAddr(s); err != nil {
					return fmt.Errorf("resolver %s: %w", s, err)
				}
			}
			if a := net.JoinHostPort(s.String(), "53"); !slices.Contains(dnsAddrs, a) {
				dnsAddrs = append(dnsAddrs, a)
			}
		}
	}
	if ls.EgressProxy != "" {
		ln, err := net.Listen("tcp", RelayProxyAddr)
		if err != nil {
			return fmt.Errorf("proxy relay: %w", err)
		}
		go relayStreams(ln, ls.EgressProxy)
	}
	if ls.EgressDNS != "" {
		for _, a := range dnsAddrs {
			pc, err := net.ListenPacket("udp", a)
			if err != nil {
				return fmt.Errorf("dns relay %s: %w", a, err)
			}
			go relayDNSPackets(pc, ls.EgressDNS)
			ln, err := net.Listen("tcp", a)
			if err != nil {
				return fmt.Errorf("dns relay %s: %w", a, err)
			}
			go relayStreams(ln, ls.EgressDNS)
		}
	}
	return nil
}

// nameservers are the resolver addresses of a resolv.conf (at most 8).
func nameservers(path string) ([]netip.Addr, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil && !slices.Contains(out, a.Unmap()) && len(out) < 8 {
				out = append(out, a.Unmap())
			}
		}
	}
	if len(out) == 0 {
		out = append(out, netip.MustParseAddr("127.0.0.1"))
	}
	return out, nil
}

// addLoopbackAddr adds a host address to the loopback interface of this
// network namespace (rtnetlink RTM_NEWADDR), so a resolver address the
// tool will use is served by the relay instead of being unreachable.
func addLoopbackAddr(a netip.Addr) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	family, bits := uint8(unix.AF_INET), uint8(32)
	raw := a.AsSlice()
	if a.Is6() {
		family, bits = unix.AF_INET6, 128
	}
	attr := func(typ uint16, data []byte) []byte {
		l := unix.SizeofRtAttr + len(data)
		b := make([]byte, (l+3)&^3)
		binary.NativeEndian.PutUint16(b[0:], uint16(l)) //nolint:gosec // a short attribute
		binary.NativeEndian.PutUint16(b[2:], typ)
		copy(b[unix.SizeofRtAttr:], data)
		return b
	}
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0], body[1], body[2], body[3] = family, bits, 0, unix.RT_SCOPE_HOST
	binary.NativeEndian.PutUint32(body[4:], uint32(lo.Index)) //nolint:gosec // an interface index
	body = append(body, attr(unix.IFA_LOCAL, raw)...)
	body = append(body, attr(unix.IFA_ADDRESS, raw)...)
	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.SizeofNlMsghdr+len(body))) //nolint:gosec // a short message
	binary.NativeEndian.PutUint16(msg[4:], unix.RTM_NEWADDR)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_ERROR && len(m.Data) >= 4 {
			if code := int32(binary.NativeEndian.Uint32(m.Data[:4])); code != 0 { //nolint:gosec // the kernel's errno
				return syscall.Errno(uint32(-code)) //nolint:gosec // a negative errno from the kernel
			}
		}
	}
	return nil
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// bindResolvConf makes /etc/resolv.conf, in this mount namespace only, name
// the relay. A system without the file resolves at 127.0.0.1:53 anyway.
func bindResolvConf(workdir string) error {
	if _, err := os.Stat("/etc/resolv.conf"); err != nil {
		return nil //nolint:nilerr // no file: resolvers default to 127.0.0.1:53
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	src := filepath.Join(workdir, ".resolv.conf")
	if err := os.WriteFile(src, []byte("nameserver 127.0.0.1\noptions ndots:1\n"), 0o400); err != nil {
		return err
	}
	return unix.Mount(src, "/etc/resolv.conf", "", unix.MS_BIND, "")
}

// relayStreams carries each connection on ln to the unix socket path.
func relayStreams(ln net.Listener, path string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			up, err := net.DialTimeout("unix", path, 10*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(up, c); halfClose(up); close(done) }()
			_, _ = io.Copy(c, up)
			halfClose(c)
			<-done
		}()
	}
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// relayDNSPackets sends each UDP query to the forwarder's DNS stream
// socket (RFC 1035 TCP framing) and returns the answer.
func relayDNSPackets(pc net.PacketConn, path string) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp, err := dnsOverStream(path, q); err == nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}

func dnsOverStream(path string, q []byte) ([]byte, error) {
	if len(q) > 65535 {
		return nil, errors.New("query too large")
	}
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame, uint16(len(q))) //nolint:gosec // bounded above
	copy(frame[2:], q)
	if _, err := c.Write(frame); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(c, resp)
	return resp, err
}

// superviseTool runs the tool as this process's child (the relays live
// here) and returns its exit status. It runs on the confined thread: the
// child inherits no_new_privs, Landlock and seccomp. The child gets no
// capabilities: root of the user namespace gains none at exec
// (SECBIT_NOROOT, locked) and the bounding set is emptied first.
func superviseTool(bin string, argv []string, env []string) int {
	if bin == "" || len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "openctem sandbox: no command")
		return launcherExit
	}
	if err := dropChildCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "openctem sandbox: capabilities: %v\n", err)
		return launcherExit
	}
	cmd := &exec.Cmd{Path: bin, Args: argv, Env: env, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGINT, unix.SIGHUP)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "openctem sandbox: run %s: %v\n", bin, err)
		return launcherExit
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	return exitStatus(cmd.Wait())
}

// Secure bits (linux/securebits.h).
const (
	secbitNoroot              = 1 << 0
	secbitNorootLocked        = 1 << 1
	secbitNoSetuidFixup       = 1 << 2
	secbitNoSetuidFixupLocked = 1 << 3
	secbitKeepCapsLocked      = 1 << 5
	secbitNoCapAmbientRaise   = 1 << 6
	secbitNoCapAmbientLocked  = 1 << 7
)

func dropChildCapabilities() error {
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("bounding set: %w", err)
		}
	}
	bits := secbitNoroot | secbitNorootLocked | secbitNoSetuidFixup | secbitNoSetuidFixupLocked |
		secbitKeepCapsLocked | secbitNoCapAmbientRaise | secbitNoCapAmbientLocked
	return unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(bits), 0, 0, 0)
}
