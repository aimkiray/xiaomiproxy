#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# HomeProxy firewall glue for legacy iptables (fw3) routers without nftables/fw4.
# Usage: firewall.sh {start|stop|restart}
# Builds ipsets + iptables/ip6tables rules to steer LAN traffic into sing-box
# (TCP redirect, UDP tproxy, DNS hijack) honoring routing_mode and LAN control.

set -u

CFG=homeproxy
HP_DIR=/etc/homeproxy
RES_DIR="$HP_DIR/resources"
RUN_DIR=/var/run/homeproxy

uci_get() { uci -q get "$CFG.$1" 2>/dev/null; }

# --- config ---------------------------------------------------------------
routing_mode=$(uci_get "config.routing_mode"); routing_mode=${routing_mode:-bypass_mainland_china}
proxy_mode=$(uci_get "config.proxy_mode");      proxy_mode=${proxy_mode:-redirect_tproxy}
ipv6=$(uci_get "config.ipv6_support");          ipv6=${ipv6:-0}
routing_port=$(uci_get "config.routing_port")

mixed_port=$(uci_get "infra.mixed_port");       mixed_port=${mixed_port:-5330}
redirect_port=$(uci_get "infra.redirect_port"); redirect_port=${redirect_port:-5331}
tproxy_port=$(uci_get "infra.tproxy_port");     tproxy_port=${tproxy_port:-5332}
dns_port=$(uci_get "infra.dns_port");           dns_port=${dns_port:-5333}
tproxy_mark=$(uci_get "infra.tproxy_mark");     tproxy_mark=${tproxy_mark:-101}
common_port=$(uci_get "infra.common_port");     common_port=${common_port:-22,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418}

lan_proxy_mode=$(uci_get "control.lan_proxy_mode"); lan_proxy_mode=${lan_proxy_mode:-disabled}

# LAN interface + subnet
lan_if=$(uci -q get network.lan.device 2>/dev/null); [ -z "$lan_if" ] && lan_if=$(uci -q get network.lan.ifname 2>/dev/null)
# MiWiFi exposes bridge member lists (space separated) here; use the bridge.
case "$lan_if" in
    *" "*|*"	"*) lan_if=br-lan ;;
esac
[ -z "$lan_if" ] && lan_if=br-lan
# If the chosen iface does not exist, omit the ingress filter (apply to all).
[ -n "$lan_if" ] && ! ip link show "$lan_if" >/dev/null 2>&1 && lan_if=""
lan_ip=$(uci -q get network.lan.ipaddr 2>/dev/null)
lan_mask=$(uci -q get network.lan.netmask 2>/dev/null)
lan_net=""
if [ -n "$lan_ip" ] && [ -n "$lan_mask" ]; then
    lan_net=$(ipcalc.sh "$lan_ip" "$lan_mask" 2>/dev/null | awk -F= '/^NETWORK=/{n=$2}/^PREFIX=/{p=$2}END{if(n!=""&&p!="")print n"/"p}')
fi
[ -z "$lan_net" ] && lan_net="192.168.31.0/24"

# LAN IPv6 prefix (best-effort) for v6 skip rules; empty when ipv6 disabled.
lan_net6=""
if [ "$ipv6" = "1" ] && [ -n "$lan_if" ]; then
    lan_net6=$(ip -6 addr show "$lan_if" 2>/dev/null | awk '/inet6/ && $0 ~ /scope global/ {print $2; exit}')
fi

list_ipv4() { uci_get "control.lan_proxy_ipv4_ips"; }
list_ipv6() { uci_get "control.lan_proxy_ipv6_ips"; }
list_mac()  { uci_get "control.lan_proxy_mac_addrs"; }
direct_ipv4() { uci_get "control.lan_direct_ipv4_ips"; }
direct_ipv6() { uci_get "control.lan_direct_ipv6_ips"; }

IP4=iptables
IP6=ip6tables

# --- teardown -------------------------------------------------------------
stop_fw() {
    for ip in $IP4 $IP6; do
        [ "$ip" = "$IP6" ] && [ "$ipv6" != "1" ] && continue
        $ip -t nat    -D PREROUTING -i "$lan_if" -p tcp -j homeproxy_redir 2>/dev/null
        $ip -t nat    -D PREROUTING -i "$lan_if" -p udp --dport 53 -j homeproxy_dns 2>/dev/null
        $ip -t mangle -D PREROUTING -i "$lan_if" -p udp -j homeproxy_mangle 2>/dev/null
        $ip -t nat    -F homeproxy_dns 2>/dev/null;     $ip -t nat -X homeproxy_dns 2>/dev/null
        $ip -t nat    -F homeproxy_redir 2>/dev/null;   $ip -t nat -X homeproxy_redir 2>/dev/null
        $ip -t mangle -F homeproxy_mangle 2>/dev/null;  $ip -t mangle -X homeproxy_mangle 2>/dev/null
    done
    ipset destroy homeproxy_cn4 2>/dev/null
    [ "$ipv6" = "1" ] && ipset destroy homeproxy_cn6 2>/dev/null
}

[ "$1" = "stop" ] && { stop_fw; exit 0; }
[ "$1" = "restart" ] && stop_fw

if [ "$lan_proxy_mode" = "disabled" ]; then
    echo "homeproxy: LAN proxy disabled; no firewall rules applied." >&2
    exit 0
fi

mkdir -p "$RUN_DIR"

# --- ipsets for CN (bypass/proxy_mainland_china) --------------------------
build_ipset() {
    local name="$1" file="$2" fam="$3"
    ipset destroy "$name" 2>/dev/null
    ipset create "$name" hash:net family "$fam" maxelem 65536 2>/dev/null || return 1
    if [ -f "$file" ]; then
        awk -v n="$name" 'NF && !/^#/ {print "add "n" "$0}' "$file" 2>/dev/null | ipset restore -exist 2>/dev/null
    fi
}
if [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "proxy_mainland_china" ]; then
    build_ipset homeproxy_cn4 "$RES_DIR/china_ip4.txt" inet
    [ "$ipv6" = "1" ] && build_ipset homeproxy_cn6 "$RES_DIR/china_ip6.txt" inet6
fi

cnset4=homeproxy_cn4
cnset6=homeproxy_cn6

# --- skip rules shared by v4/v6 (nat and mangle) --------------------------
# $1=iptables cmd  $2=table(nat|mangle)  $3=chain
emit_skip() {
    local ip="$1" tbl="$2" ch="$3"
    $ip -t "$tbl" -A "$ch" -m conntrack --ctdir REPLY -j RETURN
    $ip -t "$tbl" -A "$ch" -m addrtype --dst-type LOCAL -j RETURN
    if [ "$ip" = "$IP6" ]; then
        [ -n "$lan_net6" ] && $ip -t "$tbl" -A "$ch" -d "$lan_net6" -j RETURN
        $ip -t "$tbl" -A "$ch" -d fc00::/7 -j RETURN
        $ip -t "$tbl" -A "$ch" -d fe80::/10 -j RETURN
        $ip -t "$tbl" -A "$ch" -d ::1/128 -j RETURN
        $ip -t "$tbl" -A "$ch" -d ff00::/8 -j RETURN
        for d in $(direct_ipv6); do $ip -t "$tbl" -A "$ch" -d "$d" -j RETURN; done 2>/dev/null
    else
        $ip -t "$tbl" -A "$ch" -d "$lan_net" -j RETURN
        $ip -t "$tbl" -A "$ch" -d 10.0.0.0/8 -j RETURN
        $ip -t "$tbl" -A "$ch" -d 172.16.0.0/12 -j RETURN
        $ip -t "$tbl" -A "$ch" -d 192.168.0.0/16 -j RETURN
        $ip -t "$tbl" -A "$ch" -d 100.64.0.0/10 -j RETURN
        $ip -t "$tbl" -A "$ch" -d 127.0.0.0/8 -j RETURN
        $ip -t "$tbl" -A "$ch" -d 169.254.0.0/16 -j RETURN
        $ip -t "$tbl" -A "$ch" -d 224.0.0.0/3 -j RETURN
        for d in $(direct_ipv4); do $ip -t "$tbl" -A "$ch" -d "$d" -j RETURN; done 2>/dev/null
    fi
}

# routing-mode rule(s): which destinations are direct (RETURN) before proxy
# $1=iptables  $2=table  $3=chain  $4=cnset (empty if none)
emit_routing() {
    local ip="$1" tbl="$2" ch="$3" cnset="$4"
    case "$routing_mode" in
        bypass_mainland_china)
            [ -n "$cnset" ] && $ip -t "$tbl" -A "$ch" -m set --match-set "$cnset" dst -j RETURN ;;
        proxy_mainland_china)
            [ -n "$cnset" ] && $ip -t "$tbl" -A "$ch" -m set ! --match-set "$cnset" dst -j RETURN ;;
    esac
}

# LAN client control. $1=iptables $2=table $3=chain $4=final action args
# Appends per-client rules and the catch-all action.
emit_control() {
    local ip="$1" tbl="$2" ch="$3" action="$4"
    # v4 chains match ipv4 clients; v6 chains match ipv6 clients; mac applies to both.
    local src_list
    if [ "$ip" = "$IP6" ]; then src_list=$(list_ipv6); else src_list=$(list_ipv4); fi
    if [ "$lan_proxy_mode" = "except_listed" ]; then
        local d
        for d in $src_list; do $ip -t "$tbl" -A "$ch" -s "$d" -j RETURN; done 2>/dev/null
        for d in $(list_mac);  do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j RETURN; done 2>/dev/null
        $ip -t "$tbl" -A "$ch" $action          # proxy everyone else
    elif [ "$lan_proxy_mode" = "listed_only" ]; then
        local d
        for d in $src_list; do $ip -t "$tbl" -A "$ch" -s "$d" $action; done 2>/dev/null
        for d in $(list_mac);  do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" $action; done 2>/dev/null
        $ip -t "$tbl" -A "$ch" -j RETURN          # not listed -> direct
    else   # global / only_proxy
        $ip -t "$tbl" -A "$ch" $action
    fi
}

# --- TCP redirect (nat) ---------------------------------------------------
apply_tcp() {
    local ip="$1" cnset="$2"
    $ip -t nat -N homeproxy_redir 2>/dev/null || $ip -t nat -F homeproxy_redir
    $ip -t nat -A PREROUTING -i "$lan_if" -p tcp -j homeproxy_redir
    emit_skip "$ip" nat homeproxy_redir
    emit_routing "$ip" nat homeproxy_redir "$cnset"
    emit_control "$ip" nat homeproxy_redir "-p tcp -j REDIRECT --to-ports $redirect_port"
}

# --- UDP tproxy (mangle) --------------------------------------------------
apply_udp() {
    local ip="$1" cnset="$2"
    $ip -t mangle -N homeproxy_mangle 2>/dev/null || $ip -t mangle -F homeproxy_mangle
    $ip -t mangle -A PREROUTING -i "$lan_if" -p udp -j homeproxy_mangle
    emit_skip "$ip" mangle homeproxy_mangle
    emit_routing "$ip" mangle homeproxy_mangle "$cnset"
    # do not proxy QUIC over UDP (let clients fall back to TCP)
    $ip -t mangle -A homeproxy_mangle -p udp --dport 443 -j RETURN
    local tproxy_act="-p udp -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_mark/$tproxy_mark"
    if [ "$routing_port" = "common" ]; then
        tproxy_act="-p udp -m multiport --dports $common_port -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_mark/$tproxy_mark"
    fi
    emit_control "$ip" mangle homeproxy_mangle "$tproxy_act"
}

# --- DNS hijack (nat) -----------------------------------------------------
apply_dns() {
    local ip="$1"
    $ip -t nat -N homeproxy_dns 2>/dev/null || $ip -t nat -F homeproxy_dns
    $ip -t nat -A PREROUTING -i "$lan_if" -p udp --dport 53 -j homeproxy_dns
    $ip -t nat -A homeproxy_dns -p udp --dport 53 -j REDIRECT --to-ports "$dns_port"
}

# --- apply per family -----------------------------------------------------
# UDP tproxy is only meaningful when sing-box actually opens a tproxy inbound,
# i.e. a dedicated UDP node is configured or routing_mode is custom. This
# mirrors the tproxy_port gating in generate_client.lua so we never steer UDP
# at a port nothing is listening on.
main_udp_node=$(uci_get "config.main_udp_node"); main_udp_node=${main_udp_node:-nil}
udp_tproxy=0
if [ "$main_udp_node" != "nil" ] || [ "$routing_mode" = "custom" ]; then
    udp_tproxy=1
fi

if echo "$proxy_mode" | grep -q redirect; then
    apply_tcp "$IP4" "$cnset4"
    if [ "$ipv6" = "1" ]; then apply_tcp "$IP6" "$cnset6"; fi
fi
if echo "$proxy_mode" | grep -q tproxy && [ "$udp_tproxy" = "1" ]; then
    apply_udp "$IP4" "$cnset4"
    if [ "$ipv6" = "1" ]; then apply_udp "$IP6" "$cnset6"; fi
fi
apply_dns "$IP4"
[ "$ipv6" = "1" ] && apply_dns "$IP6"

echo "homeproxy: firewall rules applied (mode=$proxy_mode routing=$routing_mode lan=$lan_proxy_mode)." >&2
exit 0
