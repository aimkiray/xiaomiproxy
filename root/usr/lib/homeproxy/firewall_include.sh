#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# fw3 include entry point: re-applies homeproxy iptables rules on firewall
# reload/restart so they survive fw3 flushing the base chains. Registered as a
# `config include` in /etc/config/firewall (type=script, reload=1). Only acts
# while the service is active (flag set by the init script) so a stopped
# service is not resurrected by a firewall reload.
[ -f /var/run/homeproxy/firewall.active ] || exit 0
HP_LIB_DIR=/usr/lib/homeproxy
[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh || true
"$HP_LIB_DIR/firewall.sh" start