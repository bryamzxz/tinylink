# `tinylink` core component

This is the protocol-side core of tinylink, separated from the `main/`
application so that protocol code can be unit-tested independently of WiFi /
NVS / GPIO concerns.

## Status by milestone

| API surface           | Milestone | State         |
|-----------------------|-----------|---------------|
| `tinylink_version_*`  | M1        | implemented   |
| ts2021 Noise IK       | M2        | stub / TODO   |
| MapResponse parser    | M3        | stub / TODO   |
| DISCO box (NaCl)      | M4        | stub / TODO   |
| DERP client           | M5        | stub / TODO   |
| Hardening hooks       | M6        | stub / TODO   |

The public header is [`include/tinylink.h`](include/tinylink.h). Every TODO
function returns `ESP_ERR_NOT_SUPPORTED` until its milestone lands.
