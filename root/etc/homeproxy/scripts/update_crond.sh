#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy cron job: refresh resource lists and subscriptions.

SCRIPTS_DIR="/etc/homeproxy/scripts"
LUA_DIR="/usr/lib/homeproxy"

for i in "china_ip4" "china_ip6" "gfw_list" "china_list"; do
    "$SCRIPTS_DIR"/update_resources.sh "$i"
done

lua "$LUA_DIR/update_subscriptions.lua"