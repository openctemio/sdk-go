### Security: a scanner run that was stopped is never reported as a clean scan

- A legacy in-process scanner that the job's time budget, the platform's stop or a signal ended
  part-way was delivered with coverage `full` and every target `done`, because the runtime read
  only the scanner's own error text. A scanner that accepts any exit code up to 1 (code scanners,
  several recon tools) then reported a killed run as "scanned, nothing found". A code scan stopped
  this way also declared full coverage of its branch, so the platform's branch sweep could close
  occurrences the run never looked at.
- Now `core.ExecuteScanner` / `core.StreamScanner` mark a run their context or the executor ended
  with `ErrScannerStopped` and a non-zero exit, and the command poller treats a run that returned
  after its job budget ended, or whose tool died by a signal, as stopped: the report is `partial`,
  the command result's exit code is not 0, and every target its report does not settle is
  `unfinished` (the platform re-queues it). A code scan declares full coverage of its branch only
  when the run ended by itself. What the tool wrote before it stopped is still delivered.
