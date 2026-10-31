### Changed: ctis v1.6.6 (more edge protection signatures)

- Sensors recognise block and challenge pages of three more bot-management and WAF edges, including challenges answered with status 200, so a scan they stop is reported as a coverage gap with the edge and its vendor, never as no findings. Weak signs count only on a small page.
