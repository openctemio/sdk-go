### Added: `targets.allow: ["*"]` in local policy schema v2

- A single `"*"` entry (schema v2 and later) means every target the platform signs, still inside the built-in deny list, `targets.deny` and the private-range rules. Mixed with other entries it is refused; schema v1 stays frozen and refuses it. The reported policy summary gains `mode` (`allow_all`, `allow_list`, `platform_scope`) and `policy validate` says "everything the platform signs".
