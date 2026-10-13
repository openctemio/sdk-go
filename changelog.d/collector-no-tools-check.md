### Fixed: a collector no longer reports "No scanner is available"

- A sensor that adds no scanner and runs its collectors on its own schedule (platform commands off), or one with collectors only, no longer reports the failing `tools.available` check (`none`, blocks scans). A collector needs no scanner. A sensor that takes platform commands with no collector, or that added scanners, still reports it.
