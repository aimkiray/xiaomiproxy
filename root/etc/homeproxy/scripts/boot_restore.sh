#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Idempotent post-boot restorer for homeproxy on LuCI-less MiWiFi routers.
#
# Why this exists: '/' is squashfs (ro) and '/etc' is ramfs (volatile) -- every
# reboot wipes /etc/init.d/*, the /etc/homeproxy symlink, and /etc/profile.d.
# The backend (lib/scripts/web/resources), sing-box, and the patched init
# scripts all live on persistent /data/other_vol; and MiWiFi mirrors
# /etc/config + /etc/crontabs to /data/etc/ and restores them on boot, so the
# UCI config (lan_proxy_mode, subscription, main_node, firewall include) and
# the crontab already survive a reboot. The ONLY thing missing for auto-start
# is recreating the volatile /etc bits and starting the services -- which is
# exactly what this script does.
#
# Triggered from /data/auto_start.sh (MiWiFi's boot hook) and a low-frequency
# cron watchdog (defense-in-depth). Safe to run repeatedly: it only (re)starts
# the services in the same invocation that recreated the init scripts, so an
# intentional user stop (init scripts still present) is never overridden.

set -u
# Ensure cron/auto_start (minimal env) can find core utils + flock.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
HP=/data/other_vol/homeproxy
INITD=/etc/init.d
RUN=/var/run/homeproxy
LOG=$RUN/homeproxy.log
mkdir -p "$RUN" 2>/dev/null
log() { echo "$(date '+%H:%M:%S') [hp-restore] $*" >>"$LOG" 2>/dev/null; }

# Concurrency guard: auto_start + the cron tick can race on the same boot.
exec 9>/var/run/hp_restore.lock 2>/dev/null || exit 0
flock -n 9 2>/dev/null || { log "another restore in progress, exiting."; exit 0; }

# 1. /etc/homeproxy symlink (resources + scripts resolve through it)
if [ ! -e /etc/homeproxy ]; then
	ln -sfn "$HP" /etc/homeproxy 2>/dev/null
	log "created /etc/homeproxy -> $HP"
fi

# 2. init.d scripts -> persistent patched copies on /data/other_vol
need_start=0
for s in homeproxy homeproxy-web; do
	if [ ! -e "$INITD/$s" ]; then
		[ -f "$HP/init.d/$s" ] || { log "missing $HP/init.d/$s -- skip."; continue; }
		ln -sfn "$HP/init.d/$s" "$INITD/$s" 2>/dev/null
		[ -x "$HP/init.d/$s" ] || chmod +x "$HP/init.d/$s" 2>/dev/null
		need_start=1
		log "recreated $INITD/$s"
	fi
done

# 3. PATH helper for interactive shells
if [ ! -e /etc/profile.d/homeproxy.sh ]; then
	mkdir -p /etc/profile.d 2>/dev/null
	printf 'export PATH="$PATH:/data/other_vol/bin:/data/other_vol/homeproxy/bin"\n' \
		> /etc/profile.d/homeproxy.sh 2>/dev/null
	log "created /etc/profile.d/homeproxy.sh"
fi

# 4. Start services ONLY when we just recreated the init scripts (post-reboot).
#    If the scripts already existed (normal runtime), do nothing -- respecting
#    any intentional stop the user made via the web UI / CLI.
if [ "$need_start" = 1 ]; then
	log "starting homeproxy + homeproxy-web."
	"$INITD/homeproxy" start >/dev/null 2>&1 || log "homeproxy start returned $?"
	"$INITD/homeproxy-web" start >/dev/null 2>&1 || log "homeproxy-web start returned $?"
fi
