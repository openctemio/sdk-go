### Security: per-organization keys for queued results, with crypto-erasure (`outbox.Config.Store`)

- With a `localstore.Store` (`outbox.Config.Store`, `client.OutboxConfig.Store`), every new outbox item and its state are sealed under the data key of the item's organization (file format 2, which names the tenant in the header). Before, one key covered every organization.
- A shared sensor can now remove an organization's queued results with `Outbox.DropTenant` and then crypto-erase them with `Store.EraseTenant`; a copy left on a snapshot can no longer be read. An item copied over another organization's, or relabelled in its header, does not open. A tenant name read from a file never creates a key.
- Upgrade: items written before (format 1) are still read with the outbox key, which the store adopts as the organization sensor's data key, so nothing is re-encrypted. Without the outbox key, format-2-only outboxes open and format 1 items still refuse to open, as before.
