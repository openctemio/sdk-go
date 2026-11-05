### Fixed: A registry lookup (lookup.rdap) runs on names that do not resolve
- A job for `lookup.rdap` asks the domain's registry and never the target, so the sensor no longer refuses its names as `unresolvable`: a plain domain name is checked by name only (the domain deny list, and the allowed domains when `targets.allow` is set) and handed to the tool whether or not it resolves. Capabilities that connect to their targets keep refusing a name whose addresses cannot be checked. Addresses, ranges and URLs are checked as before.
- New `core.RegistryOnlyCapability`.
