package executor

// taskResolvConf is the /etc/resolv.conf a confined task sees: the relay
// as its only resolver, and no "search" or "domain" line, so a target name
// is looked up exactly as written. The host's search domains (often "lan"
// from DHCP, copied into containers) would otherwise be appended to a
// target that does not resolve and sent as queries for names that are not
// targets.
const taskResolvConf = "nameserver 127.0.0.1\noptions ndots:1\n"
