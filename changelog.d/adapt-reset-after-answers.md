### Behaviour change: a reset from a host that answered no longer cuts the host off

- `adapt.HostRate`: a connection reset from a host that already answered in the task halves its rate instead of counting toward the breaker; only 20 resets in a row with no answer between them make it a `blocked` coverage gap. Hosts behind a CDN or an intrusion-prevention device that resets the requests it dislikes keep being scanned (on production nuclei runs, resets opened ten times more breakers than timeouts). A host that resets before it ever answered still trips the breaker.
