### Fixed: signed jobs are no longer refused after platform aging reorders a batch

- The command poller re-sorted a claimed batch by priority before verifying job signatures, while the signer numbers jobs in the platform's order and a sensor accepts only strictly increasing sequence numbers. When aging put a lower-priority job first, valid jobs were refused as replays. The poller now handles a batch in the order the platform returned it (the platform owns ordering); replay protection is unchanged.
