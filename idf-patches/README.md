# IDF patches required for `feat/wg-netif-without-is-ppp`

These two patches must be applied to ESP-IDF v5.5.4 (and current master at time of writing) for the firmware on this branch to boot without panicking.

| Patch | Target file | Why |
|---|---|---|
| `0001-fix-esp_netif-restore-DHCP_CLIENT-whitelist-in-dhcpc.patch` | `components/esp_netif/lwip/esp_netif_lwip.c` | `esp_netif_internal_dhcpc_cb` calls `dhcp_ip_addr_store()` for any non-PPP netif. That dereferences `netif_dhcp_data(netif)` which is NULL on a netif that never ran DHCP. With the WG netif using `ESP_NETIF_FLAG_AUTOUP` instead of `ESP_NETIF_FLAG_IS_PPP` and a static IP, the cb fires on `netif_set_addr()` and panics from the lwIP task. The patch restores the `ESP_NETIF_DHCP_CLIENT` whitelist that existed in the original 2018 implementation (`VALID_NETIF_ID` in `dhcp_state.c`) and was silently removed in commit `356bc603c4` (2022). The PPP-specific gate added in `c8c10214f8` (2025, closes [esp-protocols#800](https://github.com/espressif/esp-protocols/issues/800)) covered only PPP; this whitelist covers all non-DHCP netif types. |
| `0002-fix-lwip-dhcp_state-null-guard-dhcp_ip_addr_-store-r.patch` | `components/lwip/port/esp32xx/netif/dhcp_state.c` | Defense-in-depth NULL guard on `dhcp_ip_addr_store()` and `dhcp_ip_addr_restore()` against the same regression class that introduced the bug in 2022. Cheap, callee-side. |

## Applying

```sh
cd "$IDF_PATH"            # your ESP-IDF v5.5.4 checkout
git apply --check /path/to/tinylink/idf-patches/0001-*.patch /path/to/tinylink/idf-patches/0002-*.patch
git am /path/to/tinylink/idf-patches/0001-*.patch /path/to/tinylink/idf-patches/0002-*.patch
```

If `git am` complains about whitespace, `git apply` followed by a manual commit is fine.

## Reverting (to test against stock IDF)

```sh
cd "$IDF_PATH"
git reset --hard v5.5.4
```

The firmware on this branch will **panic at boot** with stock IDF — the symptom is `LoadProhibited` at `dhcp_state.c:52` from the lwIP-task, fired by the `netif_add()` → `netif_set_addr()` → ext-callback path during WG netif bring-up. That is not a regression in the firmware; it is the IDF bug these patches fix.

## Upstream status

These patches have not been submitted upstream yet. Recommended PR strategy: file as a single PR against `espressif/esp-idf` master with two commits, citing `c8c10214f8` and `esp-protocols#800` as prior partial fix history. The diff is 24+/4- across two files.
