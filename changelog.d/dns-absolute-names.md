### Fixed: target names are never looked up with a search domain appended

- A host resolver with search domains (`search lan` from DHCP, copied into containers) made a tool's resolver also ask `<target>.lan` when a target did not resolve. The forwarder logged these lookups as refusals (`egress refused app.example.com.lan (dns)`), and under a public-internet scope they could be resolved upstream.
- A confined task's `/etc/resolv.conf` names only the relay and has no search list (unchanged, now tested). The SDK's own target lookups (the forwarder, the tool host, the local policy and scan-target checks) use absolute names, with a trailing dot.
- The forwarder answers a search-domain variant of a name that is not a target NXDOMAIN, never resolves it, and does not record it as a refusal (`egress.Forwarder.SearchDomains`, `egress.SearchDomains`).
- The doctor reports `network.dns_search` (information only) when the host resolver has search domains.
