#!/usr/bin/env python3
"""Auto-deploy homeproxy_mi to a LuCI-less MiWiFi router with 30s auto-rollback.

The router root filesystem is squashfs (read-only); /etc is ramfs (volatile);
/data/other_vol is ubifs (persistent).  This script deploys all homeproxy
files to /data/other_vol/homeproxy (persistent), patches hardcoded paths in
init.d / CLI / helper scripts, symlinks /etc/homeproxy -> the persistent dir,
and installs the init.d service.

A rollback watchdog is launched ON the router *before* the service restart.
If you do not confirm within --timeout seconds (default 30) the watchdog
restores the pre-deploy backup automatically -- even if SSH is lost.

Usage:
    python deploy.py                         # deploy with defaults
    python deploy.py --timeout 45            # 45s confirmation window
    python deploy.py --force                 # overwrite existing config too
    python deploy.py --rollback              # manually rollback last deploy
    python deploy.py --dry-run               # show what would happen

Requirements: Windows OpenSSH (ssh.exe, scp.exe) or any OpenSSH client.
No pip packages needed -- pure stdlib + subprocess.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

# ─── defaults ───────────────────────────────────────────────────────────────
DEFAULT_HOST     = "192.168.31.1"
DEFAULT_USER     = "root"
DEFAULT_PASSWORD = "akari"
DEFAULT_TIMEOUT  = 30

HP_BASE   = "/data/other_vol/homeproxy"           # persistent ubifs
SINGBOX   = "/data/other_vol/bin/sing-box"
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# ─── file manifest ──────────────────────────────────────────────────────────
# (local_rel, remote, patches, chmod, policy)
#   patches: list of (old_substr, new_str)
#   policy:  "always" | "if_missing"
LIB = f"{HP_BASE}/lib"
RES = f"{HP_BASE}/resources"
SCR = f"{HP_BASE}/scripts"
BIN = f"{HP_BASE}/bin"

MANIFEST = [
    # ── Lua backend (no patches — they use /etc/homeproxy which is symlinked) ──
    ("root/usr/lib/homeproxy/homeproxy.lua",          f"{LIB}/homeproxy.lua",          [], "644", "always"),
    ("root/usr/lib/homeproxy/generate_client.lua",    f"{LIB}/generate_client.lua",    [], "644", "always"),
    ("root/usr/lib/homeproxy/generate_server.lua",    f"{LIB}/generate_server.lua",    [], "644", "always"),
    ("root/usr/lib/homeproxy/migrate_config.lua",     f"{LIB}/migrate_config.lua",     [], "644", "always"),
    ("root/usr/lib/homeproxy/update_subscriptions.lua",f"{LIB}/update_subscriptions.lua",[], "644", "always"),
    # ── firewall glue ──
    ("root/usr/lib/homeproxy/firewall.sh",            f"{LIB}/firewall.sh",            [], "755", "always"),
    ("root/usr/lib/homeproxy/firewall_include.sh",    f"{LIB}/firewall_include.sh",
        [("/usr/lib/homeproxy/firewall.sh start", f"{LIB}/firewall.sh start")], "755", "always"),
    # ── CLI (patch Lua/HP dirs) ──
    ("root/usr/bin/homeproxy",                        f"{BIN}/homeproxy",
        [("LUA_DIR=/usr/lib/homeproxy", f"LUA_DIR={LIB}")], "755", "always"),
    # ── helper scripts ──
    ("root/etc/homeproxy/scripts/clean_log.sh",       f"{SCR}/clean_log.sh",           [], "755", "always"),
    ("root/etc/homeproxy/scripts/update_crond.sh",    f"{SCR}/update_crond.sh",
        [('LUA_DIR="/usr/lib/homeproxy"', f'LUA_DIR="{LIB}"')], "755", "always"),
    ("root/etc/homeproxy/scripts/update_resources.sh",f"{SCR}/update_resources.sh",    [], "755", "always"),
    # ── init.d (patch HP_LUA_DIR + sing-box fallback) ──
    ("root/etc/init.d/homeproxy",                     "/etc/init.d/homeproxy",
        [('HP_LUA_DIR="/usr/lib/homeproxy"', f'HP_LUA_DIR="{LIB}"'),
         ('PROG="/usr/bin/sing-box"',       f'PROG="{SINGBOX}"')], "755", "always"),
    # ── default UCI config (never overwrite user config unless --force) ──
    ("root/etc/config/homeproxy",                     "/etc/config/homeproxy",         [], "644", "if_missing"),
]

# resources: upload everything under root/etc/homeproxy/resources/
RES_LOCAL = "root/etc/homeproxy/resources"

# ─── SSH wrapper ────────────────────────────────────────────────────────────
class Router:
    """Thin SSH/SCP wrapper using the system OpenSSH client."""

    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self._askpass = self._write_askpass()

    # -- askpass helper for non-interactive password auth --
    def _write_askpass(self):
        p = os.path.join(tempfile.gettempdir(), "hp_sshask.cmd")
        with open(p, "w", newline="\r\n") as f:
            f.write(f"@echo {self.password}\r\n")
        return p

    def _env(self):
        env = dict(os.environ)
        env["SSH_ASKPASS"]        = self._askpass
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"]            = ":0"
        return env

    def _opts(self):
        return [
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=NUL",
            "-o", "ConnectTimeout=10",
        ]

    def run(self, cmd, timeout=30):
        """Execute *cmd* on the router; return (rc, stdout, stderr)."""
        args = ["ssh"] + self._opts() + [f"{self.user}@{self.host}", cmd]
        try:
            p = subprocess.run(args, capture_output=True, text=True,
                               timeout=timeout, env=self._env(),
                               stdin=subprocess.DEVNULL)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "TIMEOUT"

    def run_ok(self, cmd, timeout=30):
        rc, out, err = self.run(cmd, timeout)
        if rc != 0:
            raise RuntimeError(f"remote cmd failed (rc={rc}): {cmd}\n  stderr: {err}")
        return out

    def upload(self, local, remote):
        """Upload a single file via scp -O (legacy SCP protocol)."""
        remote_dir = remote.rsplit("/", 1)[0]
        self.run(f"mkdir -p '{remote_dir}'")
        args = ["scp", "-O"] + self._opts() + [local, f"{self.user}@{self.host}:{remote}"]
        try:
            p = subprocess.run(args, capture_output=True, text=True,
                               timeout=120, env=self._env(),
                               stdin=subprocess.DEVNULL)
            if p.returncode != 0:
                raise RuntimeError(f"scp failed (rc={p.returncode}): {p.stderr.strip()}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"scp timeout uploading {local}")

    def upload_text(self, text, remote, mode=None):
        """Upload *text* (str) to *remote*, optionally chmod."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp",
                                         delete=False, encoding="utf-8",
                                         newline="\n") as f:
            f.write(text)
            local = f.name
        try:
            self.upload(local, remote)
            if mode:
                self.run(f"chmod {mode} '{remote}'")
        finally:
            os.unlink(local)

    def test(self):
        """Quick connectivity check; returns True/False."""
        rc, out, _ = self.run("echo OK", timeout=10)
        return rc == 0 and "OK" in out

# ─── helpers ────────────────────────────────────────────────────────────────
def patch_text(text, patches):
    for old, new in patches:
        if old not in text:
            print(f"  WARN: patch target not found: {old[:60]!r}")
        text = text.replace(old, new)
    return text

def confirm_prompt(timeout):
    """Block for up to *timeout* seconds waiting for Enter.
    Returns: 'confirm' | 'rollback' | 'timeout'"""
    result = [None]
    def _reader():
        try:
            line = input()
            result[0] = line.strip().lower() if line else ""
        except EOFError:
            result[0] = ""
    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = int(deadline - time.monotonic()) + 1
        sys.stdout.write(f"\r\033[K  Confirm deploy? [Enter]=keep  r=rollback  ({remaining}s) ")
        sys.stdout.flush()
        t.join(0.5)
        if not t.is_alive():
            break
    sys.stdout.write("\r\033[K")
    if result[0] is None:
        return "timeout"
    if result[0] in ("r", "rollback", "n", "no"):
        return "rollback"
    return "confirm"

# ─── device probe ───────────────────────────────────────────────────────────
def probe(rt: Router):
    print("\n[1/8] Probing device...")
    checks = {
        "lua":       "lua -v 2>&1 | head -1",
        "sing-box":  f"ls -la {SINGBOX} 2>/dev/null || echo MISSING",
        "iptables":  "iptables -V 2>&1",
        "ipset":     "ipset -V 2>&1 | head -1",
        "disk_free": f"df -m {HP_BASE.rsplit('/',1)[0]} 2>/dev/null | tail -1",
    }
    results = {}
    for name, cmd in checks.items():
        rc, out, _ = rt.run(cmd)
        results[name] = out
        status = "✓" if ("MISSING" not in out and out) else "✗"
        print(f"  {status} {name:12s} {out}")

    if "MISSING" in results.get("sing-box", ""):
        raise RuntimeError(f"sing-box not found at {SINGBOX}")
    if "Lua 5.1" not in results.get("lua", ""):
        print("  ⚠ lua 5.1 not detected — service may fail")

    # disk space check (need ~5 MB for resources)
    try:
        avail = int(results["disk_free"].split()[3])
        if avail < 5:
            raise RuntimeError(f"insufficient disk space on {HP_BASE}: {avail} MB free")
        print(f"  ✓ disk space: {avail} MB free")
    except (IndexError, ValueError):
        print("  ⚠ could not parse disk space — continuing")

    return results

# ─── backup ─────────────────────────────────────────────────────────────────
BACKUP_TAR  = "/tmp/hp_deploy_backup.tar.gz"
BACKUP_META = "/tmp/hp_deploy_meta.sh"
CONFIRM_FILE = "/tmp/hp_deploy_confirmed"

def backup(rt: Router):
    print("\n[2/8] Backing up existing install...")
    # Gather paths that exist
    paths = []
    for p in ["/etc/init.d/homeproxy", "/etc/config/homeproxy",
              "/etc/homeproxy", HP_BASE, "/etc/profile.d/homeproxy.sh"]:
        rc, _, _ = rt.run(f"test -e {p} && echo yes || echo no")
        if rc == 0:
            rc2, out, _ = rt.run(f"test -e {p} 2>/dev/null && echo yes")
            if "yes" in out:
                paths.append(p)

    # Save firewall UCI include state
    rc, fw_inc, _ = rt.run("uci -q get firewall.homeproxy 2>/dev/null")
    fw_path = ""
    if fw_inc and "include" in fw_inc:
        _, fw_path, _ = rt.run("uci -q get firewall.homeproxy.path 2>/dev/null")

    # Save service running state
    _, running, _ = rt.run("ps w 2>/dev/null | grep -q '[s]ing-box run --config' && echo yes || echo no")

    meta = f"""#!/bin/sh
# Backup metadata generated by deploy.py
HP_FW_INC="{fw_inc}"
HP_FW_PATH="{fw_path}"
HP_WAS_RUNNING="{running}"
"""
    rt.upload_text(meta, BACKUP_META, "644")

    if paths:
        tar_list = " ".join(paths)
        rt.run_ok(f"tar -C / -czf {BACKUP_TAR} {tar_list} 2>/dev/null")
        _, sz, _ = rt.run(f"wc -c < {BACKUP_TAR}")
        print(f"  ✓ backup: {BACKUP_TAR} ({sz.strip()} bytes, {len(paths)} paths)")
    else:
        # Create an empty marker tar so watchdog knows it's a first deploy
        rt.run_ok(f"tar -C / -czf {BACKUP_TAR} --no-recursion /dev/null 2>/dev/null || true")
        print("  ✓ no existing install found (first deploy)")

# ─── upload files ───────────────────────────────────────────────────────────
def upload_files(rt: Router, force_config=False):
    print("\n[3/8] Uploading files...")

    # 3a. manifest files (with patching)
    for local_rel, remote, patches, mode, policy in MANIFEST:
        local = os.path.join(REPO_ROOT, local_rel.replace("/", os.sep))
        if not os.path.isfile(local):
            print(f"  ✗ MISSING local file: {local_rel}")
            raise RuntimeError(f"missing {local_rel}")

        if policy == "if_missing" and not force_config:
            rc, out, _ = rt.run(f"test -e {remote} && echo yes || echo no")
            if "yes" in out:
                print(f"  ⊝ {remote}  (exists, skipped)")
                continue

        with open(local, "r", encoding="utf-8", newline="") as f:
            text = f.read()
        if local_rel.endswith('.lua'):
            text = text.replace('or "/usr/lib/homeproxy"', 'or "' + LIB + '"')
        if patches:
            text = patch_text(text, patches)

        tmp = os.path.join(tempfile.gettempdir(), os.path.basename(remote) + ".patched")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        try:
            rt.upload(tmp, remote)
            rt.run(f"chmod {mode} '{remote}'")
            tag = "✓" if patches else "✓"
            pnote = " (patched)" if patches else ""
            print(f"  {tag} {remote}{pnote}")
        finally:
            os.unlink(tmp)

    # 3b. resources (all files, no patching)
    res_local = os.path.join(REPO_ROOT, RES_LOCAL.replace("/", os.sep))
    if os.path.isdir(res_local):
        rt.run(f"mkdir -p {RES}")
        for fname in sorted(os.listdir(res_local)):
            local = os.path.join(res_local, fname)
            if not os.path.isfile(local):
                continue
            remote = f"{RES}/{fname}"
            rt.upload(local, remote)
            print(f"  ✓ {remote}")

    print(f"  → persistent base: {HP_BASE}")

# ─── watchdog ───────────────────────────────────────────────────────────────
WATCHDOG = "/tmp/hp_watchdog.sh"

def make_watchdog(timeout):
    return f"""#!/bin/sh
# Auto-rollback watchdog — generated by deploy.py
# Sleeps {timeout}s, then restores backup unless /tmp/hp_deploy_confirmed exists.
set -u
SLEEP={timeout}
CONFIRM={CONFIRM_FILE}
BACKUP={BACKUP_TAR}
META={BACKUP_META}

if [ "${{1:-}}" = "now" ]; then SLEEP=0; fi
logger -t hp-deploy "watchdog started, sleeping $SLEEP s"
sleep "$SLEEP"

if [ -f "$CONFIRM" ]; then
    rm -f "$CONFIRM" "$META"
    # keep backup for one more boot cycle? no — clean up
    rm -f "$BACKUP"
    logger -t hp-deploy "deploy confirmed, cleanup done"
    exit 0
fi

logger -t hp-deploy "NO confirmation — rolling back"

# ── stop everything ──
/etc/init.d/homeproxy stop 2>/dev/null
sleep 1

# ── remove new deploy ──
rm -rf {HP_BASE}
rm -f /etc/homeproxy              # symlink or real dir
rm -f /etc/init.d/homeproxy
rm -f /etc/profile.d/homeproxy.sh

# ── restore backup ──
if [ -f "$BACKUP" ] && [ -s "$BACKUP" ]; then
    tar -C / -xzf "$BACKUP" 2>/dev/null
    logger -t hp-deploy "backup restored from $BACKUP"
else
    logger -t hp-deploy "no backup (first deploy) — clean removal done"
fi

# ── restore firewall UCI include ──
if [ -f "$META" ]; then
    . "$META"
    if [ "$HP_FW_INC" = "include" ]; then
        uci -q set firewall.homeproxy=include
        uci -q set firewall.homeproxy.type='script'
        uci -q set firewall.homeproxy.path="$HP_FW_PATH"
        uci -q set firewall.homeproxy.reload='1'
        uci -q set firewall.homeproxy.enabled='1'
        uci -q commit firewall
    else
        uci -q delete firewall.homeproxy 2>/dev/null
        uci -q commit firewall
    fi
fi

# ── restart services ──
/etc/init.d/dnsmasq restart 2>/dev/null
/etc/init.d/firewall reload 2>/dev/null

# ── restart homeproxy if it was running before ──
if [ -f "$META" ] && . "$META" 2>/dev/null && [ "$HP_WAS_RUNNING" = "yes" ]; then
    /etc/init.d/homeproxy start 2>/dev/null
    logger -t hp-deploy "rollback complete, service restarted"
else
    logger -t hp-deploy "rollback complete (service was not running before)"
fi

# cleanup
rm -f "$CONFIRM" "$META" "$BACKUP" {WATCHDOG} /tmp/hp_watchdog.pid
"""

def launch_watchdog(rt: Router, timeout):
    print(f"\n[4/8] Launching rollback watchdog ({timeout}s)...")
    rt.upload_text(make_watchdog(timeout), WATCHDOG, "755")
    # Launch in background, detached from SSH session
    rt.run_ok(f"sh {WATCHDOG} </dev/null >/tmp/hp_watchdog.log 2>&1 & echo $! > /tmp/hp_watchdog.pid")
    time.sleep(1)
    _, pid_out, _ = rt.run("ps w 2>/dev/null | grep ''[h]p_watchdog'' | head -1")
    if pid_out:
        print(f"  ✓ watchdog running: {pid_out.strip()}")
    else:
        print("  ⚠ watchdog may not have started")

# ─── apply deployment ───────────────────────────────────────────────────────
def apply_deploy(rt: Router, force_config=False):
    print("\n[5/8] Applying deployment (stop → swap → start)...")

    # stop old service
    print("  → stopping homeproxy service...")
    rt.run("/etc/init.d/homeproxy stop 2>/dev/null; true")

    # symlink /etc/homeproxy -> HP_BASE
    print("  → linking /etc/homeproxy -> " + HP_BASE)
    rt.run("rm -rf /etc/homeproxy 2>/dev/null; true")
    rt.run_ok(f"ln -s {HP_BASE} /etc/homeproxy")

    # profile.d for PATH (sing-box + CLI)
    print("  → installing /etc/profile.d/homeproxy.sh")
    rt.run(f"mkdir -p /etc/profile.d")
    profile = f'export PATH="$PATH:{SINGBOX.rsplit("/",1)[0]}:{BIN}"\n'
    rt.upload_text(profile, "/etc/profile.d/homeproxy.sh", "644")

    # run migration
    print("  → running config migration...")
    rc, out, err = rt.run(f"lua {LIB}/migrate_config.lua 2>&1")
    if rc != 0:
        print(f"  ⚠ migration returned rc={rc}: {err}")
    else:
        print("  ✓ migration done")

    # register fw3 include (idempotent)
    print("  → registering fw3 include...")
    rt.run(f"""uci -q set firewall.homeproxy=include
uci -q set firewall.homeproxy.type='script'
uci -q set firewall.homeproxy.path='{LIB}/firewall_include.sh'
uci -q set firewall.homeproxy.reload='1'
uci -q set firewall.homeproxy.enabled='1'
uci -q commit firewall""")

    # start service
    print("  → starting homeproxy service...")
    rc, out, err = rt.run("/etc/init.d/homeproxy start 2>&1", timeout=30)
    if rc != 0:
        print(f"  ⚠ service start returned rc={rc}")
        print(f"    stderr: {err}")
    else:
        print("  ✓ service started")

    # verify sing-box is running
    time.sleep(2)
    rc, out, _ = rt.run("ps w 2>/dev/null | grep -q '[s]ing-box run --config' && echo running || echo stopped")
    status = out.strip()
    print(f"  → sing-box status: {status}")
    if status != "running":
        print("  ⚠ sing-box not running! Check with: ssh root@host 'cat /var/run/homeproxy/homeproxy.log'")
        print("  ⚠ The watchdog will auto-rollback if you do not confirm.")
    return status

# ─── confirm / rollback ─────────────────────────────────────────────────────
def confirm_deploy(rt: Router, timeout):
    print(f"\n[6/8] Confirmation window ({timeout}s).")
    print("  The deploy is LIVE on the router.")
    print("  Test your connection. If anything is broken, just wait —")
    print(f"  the watchdog will auto-rollback in {timeout}s.\n")

    action = confirm_prompt(timeout)

    if action == "confirm":
        print("\n  → Confirming deploy...")
        rc, _, err = rt.run(f"touch {CONFIRM_FILE}")
        if rc == 0:
            print("  ✓ Deploy confirmed! Watchdog will clean up backup.")
        else:
            print(f"  ⚠ Could not confirm via SSH: {err}")
            print("  ⚠ Watchdog may roll back. Check router manually.")

        # verify watchdog saw the confirm
        time.sleep(3)
        rc, out, _ = rt.run(f"test -f {CONFIRM_FILE} && echo pending || echo confirmed")
        if "confirmed" in out:
            print("  ✓ Watchdog acknowledged confirmation.")
        else:
            print("  ℹ Watchdog still running — it will see the confirm file shortly.")
        return True

    elif action == "rollback":
        print("\n  → Manual rollback requested.")
        print("  → Not sending confirm — watchdog will restore backup...")
        # optionally trigger immediate rollback
        rc, _, _ = rt.run(f"kill $(cat /tmp/hp_watchdog.pid 2>/dev/null) 2>/dev/null; sh {WATCHDOG} now", timeout=30)
        return False

    else:  # timeout
        print(f"\n  ⏱ No confirmation within {timeout}s.")
        print("  → Watchdog is rolling back on the router...")
        return False

def verify_rollback(rt: Router):
    print("\n[7/8] Verifying rollback...")
    for attempt in range(12):
        time.sleep(3)
        if not rt.test():
            print(f"  ... router unreachable, retrying ({attempt+1}/12)")
            continue
        rc, out, _ = rt.run("ps w 2>/dev/null | grep -q '[s]ing-box run --config' && echo running || echo stopped")
        rc2, conf, _ = rt.run(f"test -f {BACKUP_TAR} && echo backup_exists || echo no_backup")
        print(f"  → sing-box: {out.strip()}, backup: {conf.strip()}")
        if "no_backup" in conf:
            print("  ✓ Rollback complete (backup cleaned up).")
            return True
    print("  ⚠ Could not verify rollback — check router manually.")
    return False

# ─── manual rollback command ────────────────────────────────────────────────
def manual_rollback(rt: Router):
    print("Manual rollback requested...")
    if not rt.test():
        print("  ✗ Cannot reach router!")
        return False
    rc, out, _ = rt.run(f"test -f {BACKUP_TAR} && echo yes || echo no")
    if "yes" not in out:
        print("  ✗ No backup found — nothing to rollback.")
        return False
    print("  → Triggering watchdog rollback...")
    rt.run("kill $(cat /tmp/hp_watchdog.pid 2>/dev/null) 2>/dev/null")
    rt.run_ok(f"sh {WATCHDOG} now", timeout=30)
    print("  ✓ Rollback executed.")
    return True

# ─── main ───────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Deploy homeproxy_mi to a MiWiFi router with auto-rollback.")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument("--password", default=DEFAULT_PASSWORD)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="confirmation window in seconds (default 30)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing UCI config too")
    ap.add_argument("--dry-run", action="store_true",
                    help="probe + show plan, do not deploy")
    ap.add_argument("--rollback", action="store_true",
                    help="manually rollback the last deploy")
    args = ap.parse_args()

    rt = Router(args.host, args.user, args.password)

    # connectivity
    print(f"[0/8] Connecting to {args.user}@{args.host} ...")
    if not rt.test():
        print("  ✗ Cannot connect to router!")
        print("  Check: host IP, password, SSH service, network.")
        return 1
    print("  ✓ Connected.")

    if args.rollback:
        return 0 if manual_rollback(rt) else 1

    # 1. probe
    probe(rt)

    if args.dry_run:
        print("\n[dry-run] Would deploy:")
        for local_rel, remote, patches, mode, policy in MANIFEST:
            pnote = f" (+{len(patches)} patches)" if patches else ""
            print(f"  {remote}{pnote}")
        print(f"  {RES}/*  (all resources)")
        print(f"  symlink /etc/homeproxy -> {HP_BASE}")
        print(f"  /etc/profile.d/homeproxy.sh")
        print(f"  fw3 include -> {LIB}/firewall_include.sh")
        print(f"  watchdog: {args.timeout}s auto-rollback")
        return 0

    # 2. backup
    backup(rt)

    # 3. upload
    upload_files(rt, force_config=args.force)

    # 4. watchdog (BEFORE applying, so it survives SSH loss)
    launch_watchdog(rt, args.timeout + 5)  # +5s buffer for deploy time

    # 5. apply
    try:
        status = apply_deploy(rt, force_config=args.force)
    except Exception as e:
        print(f"\n  ✗ Deploy failed: {e}")
        print("  → Triggering immediate rollback...")
        rt.run(f"sh {WATCHDOG} now 2>/dev/null; true")
        verify_rollback(rt)
        return 1

    # 6. confirm
    ok = confirm_deploy(rt, args.timeout)

    # 7. verify
    if ok:
        print("\n[7/8] Final verification...")
        time.sleep(2)
        rc, out, _ = rt.run("ps w 2>/dev/null | grep -q '[s]ing-box run --config' && echo running || echo stopped")
        print(f"  sing-box: {out.strip()}")
        rc, out, _ = rt.run("cat /var/run/homeproxy/homeproxy.log 2>/dev/null | tail -3")
        if out:
            print(f"  log tail: {out}")
        print("\n[8/8] ✓ Deploy complete!")
        print(f"  CLI:  /data/other_vol/homeproxy/bin/homeproxy")
        print(f"  Log:  ssh {args.user}@{args.host} 'tail -f /var/run/homeproxy/homeproxy.log'")
        print(f"  Hint: add to PATH via /etc/profile.d/homeproxy.sh (re-login or source it)")
    else:
        verify_rollback(rt)
        print("\n[8/8] Deploy rolled back.")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())