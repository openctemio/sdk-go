// Package netctx is a sensor's network self-description: what the host
// owner declares (site, routes it reaches, DNS suffixes, internet mode),
// what the SDK detects on the host (interfaces, routes, resolvers, the
// egress path to the platform) and a fingerprint that changes when the
// sensor moves. The sensor manifest carries the report (member "network")
// to a platform that lists the "network" hello feature.
//
// Design: https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-089-reachability-aware-routing.md
//
// Security. The report is a hint the platform may use only to take work
// away from this sensor or to rank sensors that are already authorized; it
// never authorizes anything. It discloses internal topology, so:
//   - the default mode is summary (private prefixes listed, public ones
//     counted), and the host owner can choose off (only the fingerprint and
//     the internet mode leave the host);
//   - the report never names a prefix outside the local policy's
//     targets.allow when that is set (entries are narrowed or dropped and
//     counted in Trimmed);
//   - every list is bounded and sorted, so the report is deterministic;
//   - detection reads local tables only (interfaces, the routing table,
//     resolv.conf). The only network call is the Echo the caller supplies
//     (the platform's egress echo): no cloud metadata endpoint, no LAN
//     scanning, no DNS query.
//
// Detection never changes local enforcement: the local policy keeps the
// final say on what this sensor scans.
//
// Stability: Experimental (docs/STABILITY.md).
package netctx
