### Security: a confined task never dials an address no check has seen

- `LocalPolicy.AdmittedAddrs` without a policy file applies the built-in deny list to the addresses it returns, as `CheckTarget` does. A name that passed the target check with a public address and resolves to a private, loopback, CGNAT, link-local or metadata address when the task starts is refused, not pinned for the task's forwarder (DNS rebinding).
- The tool host, when its policy has no `AdmittedAddrs`, checks every address of its own lookup with the policy's target check before pinning it (a CI run without any policy, whose admission checks no target either, is unchanged). Before, it pinned whatever the name resolved to when the task started.
