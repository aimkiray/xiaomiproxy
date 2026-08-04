#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy cron job: refresh resource lists and subscriptions.

SCRIPTS_DIR="/etc/homeproxy/scripts"
[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh || true
LUA_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"
export HP_LUAPATH="$LUA_DIR"

for i in "china_ip4" "china_ip6" "gfw_list" "china_list"; do
    "$SCRIPTS_DIR"/update_resources.sh "$i"
done

lua "$LUA_DIR/update_subscriptions.lua"