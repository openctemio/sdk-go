### Security: one deny list with the platform (ctis addrscope)

- `httpsec.IsIPBlockedWith` (and with it the scan target policy, the local policy's built-in deny list and the shared-sensor zone rule), and the egress forwarder's public-only check now use `github.com/openctemio/ctis/addrscope`. The platform checks job targets with the same package.
- An IPv6 address that carries an IPv4 address (NAT64, 6to4, Teredo, IPv4-compatible) is judged by that IPv4 address. `64:ff9b::a00:1`, `2002:a00:1::1` and a Teredo address whose client is 10.0.0.1 are refused, even where private targets are allowed. The same forms of a public address are no longer refused for their range alone.
- Newly refused: `fec0::/10` (deprecated site-local). Vendor hosts and egress-proxy destinations that resolve to CGNAT, benchmarking or reserved space are refused too. Ranges that hold `192.0.0.0/24`, `198.18.0.0/15` or an IPv6 range that carries IPv4 are refused as range targets.
