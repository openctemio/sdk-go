### Fixed: a report leaves the outbox only once the platform processed it

- The outbox deleted a report as soon as the platform answered 202, before the platform processed it. If
  processing then failed, or the platform dropped the report, the findings existed nowhere and could not be
  sent again. Now the 202 marks the report accepted. The outbox keeps it and reads its status
  (`GET /results/{report_id}`) until it is final:
  - `completed`: deleted;
  - `failed`, or unknown to the platform: sent again under the same id with the same bytes, at most 5 times;
  - `expired`, or failed past the cap: kept as a dead letter.
- A report that is only accepted no longer holds back its command's result.
- Dead letters of reports are no longer deleted by the byte cap, the age cap or the janitor; only an
  operator removes them. They count towards the claim gate, so a disk full of them stops claiming instead
  of losing results.
- New `OutboxConfig.ReportStatusPoll` (default 5 s) and `outbox.Accepted`, `Outbox.DiscardDead`.
