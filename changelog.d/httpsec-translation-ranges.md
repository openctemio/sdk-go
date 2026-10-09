### Security: the SSRF guard refuses IPv6 ranges that translate to IPv4

- `pkg/httpsec` also hard-blocks four IPv6 ranges that carry an IPv4 address:
  - NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`;
  - 6to4 `2002::/16`;
  - Teredo `2001::/32`.
- On a network with NAT64/DNS64, a name that resolved to `64:ff9b::a9fe:a9fe` reached the cloud metadata address `169.254.169.254` through the translator.
- `192.0.0.0/24` and `198.18.0.0/15` are refused too.
- The table matches the platform's copy (api `pkg/httpsec`), which the platform's security lint compares line by line.
