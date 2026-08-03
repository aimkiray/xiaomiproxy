# Repository Guidelines

`homeproxy` is a sing-box front-end for **LuCI-less, nftables-less routers** (e.g. stock Xiaomi/MiWiFi). The original `luci-app-homeproxy` depended on LuCI (JavaScript view), ucode, and fw4/nftables. This port replaces all three: backend logic is **Lua** (using the on-device `uci` binding + `luci.json`), and traffic steering uses **iptables + ipset**. A shell CLI replaces the web UI.

Target environment verified on a Xiaomi router (OpenWrt 18.06 base, kernel 5.4, busybox/ash, `lua 5.1` + `luci.json` + `uci` binding, `iptables`/`ip6tables`, `ipset`, `xt_TPROXY`; **no** `ucode`, `nft`, `fw4`, or `jq`).

## Project Structure & Module Organization

- `Makefile` — OpenWrt package definition (`Package/homeproxy`, deps: `+sing-box +lua +iptables +iptables-mod-tproxy +kmod-ipt-tproxy +iptables-mod-ipset +kmod-ipt-ipset +ipset`).
- `root/usr/lib/homeproxy/` — Lua backend:
  - `homeproxy.lua` — shared helpers (URL/base64/md5, `uci` wrapper, JSON via `luci.json`, `clean()`/`encode_json`).
  - `generate_client.lua`, `generate_server.lua` — build `sing-box` JSON from UCI.
  - `migrate_config.lua` — idempotent defaults/deprecated-option cleanup.
  - `update_subscriptions.lua` — fetch/parse share-links (`ss/vmess/vless/trojan/hysteria2/http/socks/tuic/anytls` + SIP008), write nodes.
  - `firewall.sh` — iptables+ipset rules (TCP redirect, UDP tproxy, DNS hijack, CN bypass).
- `root/usr/bin/homeproxy` — CLI (`start/stop/generate/subscribe/nodes/add/set/...`).
- `root/etc/init.d/homeproxy` — procd service: runs lua generators, sets tproxy routing table, starts sing-box, applies firewall.
- `root/etc/config/homeproxy` — UCI default config.
- `root/etc/homeproxy/resources/` — geodata/lists (`china_ip4/6.txt`, `china_list.txt`, `gfw_list.txt`).
- `root/etc/homeproxy/scripts/` — `clean_log.sh`, `update_crond.sh`, `update_resources.sh` (uses `lua+luci.json` instead of `jsonfilter`).

## Build & Run

- Build an ipk/apk: `.github/build-ipk.sh apk|ipk` (no longer needs `htdocs`/`po`/`po2lmo`).
- Deploy to a MiWiFi device: copy `root/*` to the router (note `/` is read-only on MiWiFi; place scripts/resources on a writable layer such as `/data` or `/etc` ramfs, or rebuild the firmware).
- Validate a generated config on-device: `sing-box check --config /var/run/homeproxy/sing-box-c.json`.
- Common commands: `homeproxy generate`, `homeproxy subscribe`, `homeproxy nodes`, `homeproxy main-node <name>`, `homeproxy restart`, `homeproxy log -f`.

## Coding Style & Conventions

- Lua 5.1 only (no 5.3 bitops/goto); indent with tabs; reuse `hp.*` helpers; never shell out to `jq`/`ucode`/`nft`.
- Shell scripts are POSIX/ash (LF line endings), `set -u`; quote variables; best-effort iptables calls.
- Keep JSON output clean: `hp.encode_json` drops `nil`/`""`/empty containers (keeps `false`/numbers).
- All files keep the `SPDX-License-Identifier: GPL-2.0-only` header.

## Validation

No unit-test framework. Generators/firewall/CLI were validated live on the target router via SSH: JSON generation, subscription parsing (5 schemes), iptables/ipset rule apply+teardown, and CLI ops. Re-run `homeproxy generate` after config edits.

## Commits

Follow Conventional Commits with a scope, e.g. `fix(generator/client):`, `feat(firewall):`, `chore(resources):`.