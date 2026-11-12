### Fixed: a sensor on a large volume no longer stops claiming with plenty of disk free

- The storage high watermark (claiming stops) was reached whenever less than 15 % of the volume was free, whatever the absolute amount: a sensor with 29 GiB free on a 194 GiB volume, or 200 GiB free on 2 TiB, held every job while the sensor itself may write at most its store quota and budgets.
- The high watermark now needs free space below both 15 % of the volume and an absolute ceiling, new `localstore.Policy.HighFreeBytes` (1 GiB to 1 TiB; default: store quota + workspace budget + pack budget + 2 GiB, 16 GiB with the defaults). Small volumes keep the share. The reason in the heartbeat's `local_store` now names the free MiB and both thresholds.
