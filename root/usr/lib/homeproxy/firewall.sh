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
tun_mark=$(uci_get "infra.tun_mark");           tun_mark=${tun_mark:-102}
tun_name=$(uci_get "infra.tun_name");           tun_name=${tun_name:-singtun0}
self_mark=$(uci_get "infra.self_mark");         self_mark=${self_mark:-100}
common_port=$(uci_get "infra.common_port");     common_port=${common_port:-22,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418}

lan_proxy_mode=$(uci_get "control.lan_proxy_mode"); lan_proxy_mode=${lan_proxy_mode:-disabled}
dns_redirect=$(uci_get "infra.dns_redirect"); dns_redirect=${dns_redirect:-1}

# LAN interface + subnet
# Interfaces to steer: control.listen_interfaces (UCI list) takes priority,
# otherwise auto-detect the LAN bridge. Only existing interfaces are used.
LAN_IFS=$(uci_get "control.listen_interfaces")
if [ -z "$LAN_IFS" ]; then
	lan_if=$(uci -q get network.lan.device 2>/dev/null); [ -z "$lan_if" ] && lan_if=$(uci -q get network.lan.ifname 2>/dev/null)
	# MiWiFi exposes bridge member lists (space separated) here; use the bridge.
	case "$lan_if" in
		*" "*|*"	"*) lan_if=br-lan ;;
	esac
	[ -z "$lan_if" ] && lan_if=br-lan
	[ -n "$lan_if" ] && ! ip link show "$lan_if" >/dev/null 2>&1 && lan_if=""
	LAN_IFS="$lan_if"
fi
# Keep only interfaces that actually exist.
LAN_IFS_EXIST=""
for _li in $LAN_IFS; do
	ip link show "$_li" >/dev/null 2>&1 && LAN_IFS_EXIST="$LAN_IFS_EXIST $_li"
done
LAN_IFS=$(echo $LAN_IFS_EXIST)

lan_ip=$(uci -q get network.lan.ipaddr 2>/dev/null)
lan_mask=$(uci -q get network.lan.netmask 2>/dev/null)
lan_net=""
if [ -n "$lan_ip" ] && [ -n "$lan_mask" ]; then
	lan_net=$(ipcalc.sh "$lan_ip" "$lan_mask" 2>/dev/null | awk -F= '/^NETWORK=/{n=$2}/^PREFIX=/{p=$2}END{if(n!=""&&p!="")print n"/"p}')
fi
[ -z "$lan_net" ] && lan_net="192.168.31.0/24"

# LAN IPv6 prefix (best-effort) for v6 skip rules; empty when ipv6 disabled.
lan_net6=""
if [ "$ipv6" = "1" ]; then
	for _li in $LAN_IFS; do
		lan_net6=$(ip -6 addr show "$_li" 2>/dev/null | awk '/inet6/ && $0 ~ /scope global/ {print $2; exit}')
		[ -n "$lan_net6" ] && break
	done
fi

list_ipv4() { uci_get "control.lan_proxy_ipv4_ips"; }
list_ipv6() { uci_get "control.lan_proxy_ipv6_ips"; }
list_mac()  { uci_get "control.lan_proxy_mac_addrs"; }
direct_ipv4() { uci_get "control.lan_direct_ipv4_ips"; }
direct_ipv6() { uci_get "control.lan_direct_ipv6_ips"; }
direct_mac()  { uci_get "control.lan_direct_mac_addrs"; }
wan_proxy_ipv4() { uci_get "control.wan_proxy_ipv4_ips"; }
wan_proxy_ipv6() { uci_get "control.wan_proxy_ipv6_ips"; }
wan_direct_ipv4() { uci_get "control.wan_direct_ipv4_ips"; }
wan_direct_ipv6() { uci_get "control.wan_direct_ipv6_ips"; }
lan_global_ipv4() { uci_get "control.lan_global_proxy_ipv4_ips"; }
lan_global_ipv6() { uci_get "control.lan_global_proxy_ipv6_ips"; }
lan_global_mac()  { uci_get "control.lan_global_proxy_mac_addrs"; }
lan_gaming_ipv4() { uci_get "control.lan_gaming_mode_ipv4_ips"; }
lan_gaming_ipv6() { uci_get "control.lan_gaming_mode_ipv6_ips"; }
lan_gaming_mac()  { uci_get "control.lan_gaming_mode_mac_addrs"; }

# dnsmasq listen port: the iptables DNS redirect forces clients using a custom
# DNS server back to local dnsmasq, which then applies the conf-dir steering
# rules (written by init.d). dnsmasq itself decides which domains go to
# sing-box; we never redirect DNS straight to sing-box here.
dnsmasq_port=$(uci -q get dhcp.@dnsmasq[0].port 2>/dev/null); dnsmasq_port=${dnsmasq_port:-53}

IP4=iptables
IP6=ip6tables

# All chains we may create, so stop_fw can flush+delete them unconditionally.
ALL_CHAINS_NAT="homeproxy_dns homeproxy_redir homeproxy_redir_port homeproxy_redir_act homeproxy_redir_lanac"
ALL_CHAINS_MANGLE="homeproxy_mangle homeproxy_mangle_port homeproxy_mangle_act homeproxy_mangle_lanac homeproxy_mangle_mark homeproxy_mangle_out homeproxy_tun homeproxy_tun_mark homeproxy_tun_lanac"
ALL_IPSETS="homeproxy_cn4 homeproxy_cn6 homeproxy_gfw4 homeproxy_gfw6 homeproxy_wan_proxy4 homeproxy_wan_proxy6 homeproxy_wan_direct4 homeproxy_wan_direct6"

# --- teardown -------------------------------------------------------------
# Remove every PREROUTING/OUTPUT jump we might have added (per LAN iface, plus
# the iface-agnostic OUTPUT and lo re-entry jumps), then flush+delete chains
# and destroy ipsets. Best-effort; missing rules/chains are ignored.
stop_fw() {
	for ip in $IP4 $IP6; do
		# per-interface PREROUTING jumps
		for _li in $LAN_IFS lo; do
			$ip -t nat    -D PREROUTING -i "$_li" -p tcp -j homeproxy_redir_lanac 2>/dev/null
			$ip -t nat    -D PREROUTING -i "$_li" -p udp --dport 53 -j homeproxy_dns 2>/dev/null
			$ip -t mangle -D PREROUTING -i "$_li" -p udp -j homeproxy_mangle_lanac 2>/dev/null
			$ip -t mangle -D PREROUTING -i "$_li" -j homeproxy_tun_lanac 2>/dev/null
			# fall back to the old single-IFARG hook names for compatibility
			$ip -t nat    -D PREROUTING -i "$_li" -p tcp -j homeproxy_redir 2>/dev/null
			$ip -t mangle -D PREROUTING -i "$_li" -p udp -j homeproxy_mangle 2>/dev/null
			$ip -t mangle -D PREROUTING -i "$_li" -j homeproxy_tun_lanac 2>/dev/null
		done
		# iface-agnostic OUTPUT hooks (router self-traffic)
		$ip -t nat    -D OUTPUT -p tcp -j homeproxy_redir 2>/dev/null
		$ip -t mangle -D OUTPUT -p udp -j homeproxy_mangle_out 2>/dev/null
		$ip -t mangle -D OUTPUT -p udp -j homeproxy_mangle_mark 2>/dev/null
		$ip -t mangle -D OUTPUT -j homeproxy_tun 2>/dev/null
		# also remove any unfiltered OUTPUT hooks from earlier revisions
		$ip -t mangle -D OUTPUT -p udp -j homeproxy_mangle 2>/dev/null
		# Two passes: flush every chain (drops cross-chain jumps), then delete.
		# A single pass leaves referenced chains (e.g. homeproxy_mangle_mark,
		# jumped to by homeproxy_mangle_out) non-empty and undeletable.
		for _ch in $ALL_CHAINS_NAT; do $ip -t nat -F "$_ch" 2>/dev/null; done
		for _ch in $ALL_CHAINS_NAT; do $ip -t nat -X "$_ch" 2>/dev/null; done
		for _ch in $ALL_CHAINS_MANGLE; do $ip -t mangle -F "$_ch" 2>/dev/null; done
		for _ch in $ALL_CHAINS_MANGLE; do $ip -t mangle -X "$_ch" 2>/dev/null; done
		# filter-table accepts (firewall_pre equivalent)
		$ip -D INPUT -j homeproxy_in 2>/dev/null
		$ip -D FORWARD -j homeproxy_fwd 2>/dev/null
		$ip -F homeproxy_in 2>/dev/null;  $ip -X homeproxy_in 2>/dev/null
		$ip -F homeproxy_fwd 2>/dev/null; $ip -X homeproxy_fwd 2>/dev/null
	done
	for _s in $ALL_IPSETS; do ipset destroy "$_s" 2>/dev/null; done
}

[ "$1" = "stop" ] && { stop_fw; exit 0; }
[ "$1" = "restart" ] && stop_fw

if [ "$lan_proxy_mode" = "disabled" ]; then
	echo "homeproxy: LAN proxy disabled; no firewall rules applied." >&2
	exit 0
fi

mkdir -p "$RUN_DIR"

# --- ipsets ---------------------------------------------------------------
build_ipset() {
	local name="$1" file="$2" fam="$3"
	ipset destroy "$name" 2>/dev/null
	ipset create "$name" hash:net family "$fam" maxelem 65536 2>/dev/null || return 1
	if [ -n "$file" ] && [ -f "$file" ]; then
		awk -v n="$name" 'NF && !/^#/ {print "add "n" "$0}' "$file" 2>/dev/null | ipset restore -exist 2>/dev/null
	fi
}
# empty ipset (no file) -- used for dynamic sets dnsmasq populates.
build_ipset_empty() {
	local name="$1" fam="$2" type="${3:-hash:net}"
	ipset destroy "$name" 2>/dev/null
	ipset create "$name" "$type" family "$fam" maxelem 65536 2>/dev/null || return 1
}
load_list_ipset() {
	# $1=ipset-name $2=family $3=space-separated-cidr-list
	local name="$1" fam="$2" list="$3"
	build_ipset_empty "$name" "$fam" || return 1
	[ -n "$list" ] || return 0
	local cidr
	for cidr in $list; do ipset add -exist "$name" "$cidr" 2>/dev/null; done
}

if [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "proxy_mainland_china" ]; then
	build_ipset homeproxy_cn4 "$RES_DIR/china_ip4.txt" inet
	[ "$ipv6" = "1" ] && build_ipset homeproxy_cn6 "$RES_DIR/china_ip6.txt" inet6
	cn_cnt=$(ipset list homeproxy_cn4 2>/dev/null | awk '/Number of entries/{print $4}')
	[ -z "$cn_cnt" ] && cn_cnt=0
	[ "$cn_cnt" -le 0 ] && echo "homeproxy: WARNING: CN ipset empty/missing ($RES_DIR/china_ip4.txt) -- $routing_mode will proxy all traffic." >&2
	if [ "$ipv6" = "1" ]; then
		cn6_cnt=$(ipset list homeproxy_cn6 2>/dev/null | awk '/Number of entries/{print $4}')
		[ -z "$cn6_cnt" ] && cn6_cnt=0
		[ "$cn6_cnt" -le 0 ] && echo "homeproxy: WARNING: CN ipset empty/missing ($RES_DIR/china_ip6.txt) -- v6 $routing_mode will proxy all traffic." >&2
	fi
fi

if [ "$routing_mode" = "gfwlist" ]; then
	build_ipset_empty homeproxy_gfw4 inet hash:ip
	[ "$ipv6" = "1" ] && build_ipset_empty homeproxy_gfw6 inet6 hash:ip
	[ -s "$RES_DIR/gfw_list.txt" ] || \
		echo "homeproxy: WARNING: gfw_list.txt missing/empty -- gfwlist will proxy nothing (all direct)." >&2
fi

# wan_proxy / wan_direct: always created (even empty) so dnsmasq ipset= can
# populate wan_proxy dynamically from proxy_list.txt.
load_list_ipset homeproxy_wan_proxy4 inet "$(wan_proxy_ipv4)"
[ "$ipv6" = "1" ] && load_list_ipset homeproxy_wan_proxy6 inet6 "$(wan_proxy_ipv6)"
load_list_ipset homeproxy_wan_direct4 inet "$(wan_direct_ipv4)"
[ "$ipv6" = "1" ] && load_list_ipset homeproxy_wan_direct6 inet6 "$(wan_direct_ipv6)"

cnset4=homeproxy_cn4
cnset6=homeproxy_cn6
route_set4=""
route_set6=""
if [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "proxy_mainland_china" ]; then
	route_set4="$cnset4"; route_set6="$cnset6"
elif [ "$routing_mode" = "gfwlist" ]; then
	route_set4=homeproxy_gfw4; route_set6=homeproxy_gfw6
fi

# --- shared rule emitters -------------------------------------------------
# local/private destinations -> RETURN (mirrors upstream @homeproxy_local_addr).
# $1=ip $2=table $3=chain
emit_local() {
	local ip="$1" tbl="$2" ch="$3"
	$ip -t "$tbl" -A "$ch" -m conntrack --ctdir REPLY -j RETURN 2>/dev/null
	$ip -t "$tbl" -A "$ch" -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null
	if [ "$ip" = "$IP6" ]; then
		[ -n "$lan_net6" ] && $ip -t "$tbl" -A "$ch" -d "$lan_net6" -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d fc00::/7 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d fe80::/10 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d ::1/128 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d ff00::/8 -j RETURN 2>/dev/null
	else
		$ip -t "$tbl" -A "$ch" -d "$lan_net" -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 10.0.0.0/8 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 172.16.0.0/12 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 192.168.0.0/16 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 100.64.0.0/10 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 127.0.0.0/8 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 169.254.0.0/16 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 224.0.0.0/3 -j RETURN 2>/dev/null
	fi
}

# routing-mode dst split: which destinations are direct (RETURN) before proxy.
# $1=ip $2=table $3=chain $4=rset (empty if none)
emit_routing() {
	local ip="$1" tbl="$2" ch="$3" rset="$4"
	case "$routing_mode" in
		bypass_mainland_china)
			[ -n "$rset" ] && $ip -t "$tbl" -A "$ch" -m set --match-set "$rset" dst -j RETURN 2>/dev/null ;;
		proxy_mainland_china)
			[ -n "$rset" ] && $ip -t "$tbl" -A "$ch" -m set ! --match-set "$rset" dst -j RETURN 2>/dev/null ;;
		gfwlist)
			[ -n "$rset" ] && $ip -t "$tbl" -A "$ch" -m set ! --match-set "$rset" dst -j RETURN 2>/dev/null ;;
	esac
}

# destination ipset match -> target. $1=ip $2=table $3=chain $4=kind(wan_proxy|wan_direct) $5=target
emit_dst_ipset() {
	local ip="$1" tbl="$2" ch="$3" kind="$4" tgt="$5" set4 set6
	if [ "$kind" = "wan_proxy" ]; then set4=homeproxy_wan_proxy4; set6=homeproxy_wan_proxy6
	elif [ "$kind" = "wan_direct" ]; then set4=homeproxy_wan_direct4; set6=homeproxy_wan_direct6; fi
	$ip -t "$tbl" -A "$ch" -m set --match-set "$set4" dst -j "$tgt" 2>/dev/null
	if [ "$ipv6" = "1" ]; then $ip -t "$tbl" -A "$ch" -m set --match-set "$set6" dst -j "$tgt" 2>/dev/null; fi
}

# source-list match (ipv4 list + ipv6 list + mac) -> target.
# $1=ip $2=table $3=chain $4=kind(lan_global|lan_gaming) $5=target
emit_src_list() {
	local ip="$1" tbl="$2" ch="$3" kind="$4" tgt="$5" v4 v6 mac
	if [ "$kind" = "lan_global" ]; then v4=$(lan_global_ipv4); v6=$(lan_global_ipv6); mac=$(lan_global_mac)
	else v4=$(lan_gaming_ipv4); v6=$(lan_gaming_ipv6); mac=$(lan_gaming_mac); fi
	if [ "$ip" = "$IP6" ]; then
		local d; for d in $v6; do $ip -t "$tbl" -A "$ch" -s "$d" -j "$tgt" 2>/dev/null; done
	else
		local d; for d in $v4; do $ip -t "$tbl" -A "$ch" -s "$d" -j "$tgt" 2>/dev/null; done
	fi
	local d; for d in $mac; do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j "$tgt" 2>/dev/null; done
}

# Build the steering chain (homeproxy_redir / homeproxy_mangle / homeproxy_tun).
# Used by the PREROUTING gate and by the OUTPUT hook directly. Order mirrors
# upstream homeproxy_redirect / mangle_prerouting / mangle_tun:
#   self_mark -> wan_proxy -> local -> lan_global -> wan_direct -> routing
#   -> gaming -> catch-all(port-filtered)
# $1=ip $2=table $3=chain $4=rset $5=port_target $6=act_target
emit_steering() {
	local ip="$1" tbl="$2" ch="$3" rset="$4" port_tgt="$5" act_tgt="$6"
	$ip -t "$tbl" -N "$ch" 2>/dev/null || $ip -t "$tbl" -F "$ch"
	# loop prevention: sing-box's own egress carries self_mark (routing_mark).
	$ip -t "$tbl" -A "$ch" -m mark --mark "$self_mark/$self_mark" -j RETURN 2>/dev/null
	emit_dst_ipset "$ip" "$tbl" "$ch" wan_proxy "$port_tgt"
	emit_local "$ip" "$tbl" "$ch"
	if [ "$routing_mode" != "custom" ]; then
		emit_src_list "$ip" "$tbl" "$ch" lan_global "$port_tgt"
	fi
	emit_dst_ipset "$ip" "$tbl" "$ch" wan_direct RETURN
	emit_routing "$ip" "$tbl" "$ch" "$rset"
	# Block QUIC over UDP/80,443 so clients fall back to TCP (steered above).
	# mangle has no REJECT, so DROP. Only bypass/gfwlist; upstream lets QUIC
	# reach the proxy in proxy_mainland_china & custom. Harmless in the nat
	# chain (which only sees tcp).
	if [ "$tbl" = "mangle" ] && { [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "gfwlist" ]; }; then
		$ip -t "$tbl" -A "$ch" -p udp -m multiport --dports 80,443 -j DROP 2>/dev/null
	fi
	emit_src_list "$ip" "$tbl" "$ch" lan_gaming "$act_tgt"
	$ip -t "$tbl" -A "$ch" -j "$port_tgt"
}

# Build the per-client gate (lanac). PREROUTING jumps here; OUTPUT bypasses it.
# $1=ip $2=table $3=chain(gate) $4=steering_target
emit_gate() {
	local ip="$1" tbl="$2" ch="$3" tgt="$4"
	$ip -t "$tbl" -N "$ch" 2>/dev/null || $ip -t "$tbl" -F "$ch"
	# loop prevention (router-self packets re-entering via lo carry self_mark).
	$ip -t "$tbl" -A "$ch" -m mark --mark "$self_mark/$self_mark" -j RETURN 2>/dev/null
	# do not steer DNS over UDP here -- the nat-table homeproxy_dns handles it.
	[ "$tbl" = "mangle" ] && $ip -t "$tbl" -A "$ch" -p udp --dport 53 -j RETURN 2>/dev/null
	if [ "$lan_proxy_mode" = "listed_only" ]; then
		local src_list d
		if [ "$ip" = "$IP6" ]; then src_list=$(list_ipv6); else src_list=$(list_ipv4); fi
		for d in $src_list; do $ip -t "$tbl" -A "$ch" -s "$d" -j "$tgt" 2>/dev/null; done
		for d in $(list_mac); do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j "$tgt" 2>/dev/null; done
		# not listed -> direct (chain ends, implicit RETURN)
	elif [ "$lan_proxy_mode" = "except_listed" ]; then
		local dlist d
		if [ "$ip" = "$IP6" ]; then dlist=$(direct_ipv6); else dlist=$(direct_ipv4); fi
		for d in $dlist; do $ip -t "$tbl" -A "$ch" -s "$d" -j RETURN 2>/dev/null; done
		for d in $(direct_mac); do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j RETURN 2>/dev/null; done
		$ip -t "$tbl" -A "$ch" -j "$tgt"            # proxy everyone else
	else   # global / only_proxy
		$ip -t "$tbl" -A "$ch" -j "$tgt"
	fi
}

# Hook a PREROUTING jump for every LAN interface. $1=ip $2=table $3=proto-args $4=chain
hook_prerouting() {
	local ip="$1" tbl="$2" proto="$3" ch="$4" li
	for li in $LAN_IFS; do
		$ip -t "$tbl" -D PREROUTING -i "$li" $proto -j "$ch" 2>/dev/null
		$ip -t "$tbl" -A PREROUTING -i "$li" $proto -j "$ch" 2>/dev/null
	done
}

# --- TCP redirect (nat) ----------------------------------------------------
apply_tcp() {
	local ip="$1" rset="$2"
	# action (no port filter) -- used by gaming src rule
	$ip -t nat -N homeproxy_redir_act 2>/dev/null || $ip -t nat -F homeproxy_redir_act
	$ip -t nat -A homeproxy_redir_act -p tcp -j REDIRECT --to-ports "$redirect_port"
	# port-filtered action -- used by catch-all / wan_proxy / lan_global
	$ip -t nat -N homeproxy_redir_port 2>/dev/null || $ip -t nat -F homeproxy_redir_port
	if [ "$routing_port" = "common" ]; then
		$ip -t nat -A homeproxy_redir_port -p tcp -m multiport --dports "$common_port" -j homeproxy_redir_act 2>/dev/null
	else
		$ip -t nat -A homeproxy_redir_port -p tcp -j homeproxy_redir_act
	fi
	# steering chain
	emit_steering "$ip" nat homeproxy_redir "$rset" homeproxy_redir_port homeproxy_redir_act
	# gate + PREROUTING hook
	emit_gate "$ip" nat homeproxy_redir_lanac homeproxy_redir
	hook_prerouting "$ip" nat "-p tcp" homeproxy_redir_lanac
	# router-self TCP -> steering (bypasses the gate; covers update_via_proxy).
	$ip -t nat -D OUTPUT -p tcp -j homeproxy_redir 2>/dev/null
	$ip -t nat -A OUTPUT -p tcp -j homeproxy_redir
}

# --- UDP tproxy (mangle) ---------------------------------------------------
apply_udp() {
	local ip="$1" rset="$2"
	$ip -t mangle -N homeproxy_mangle_act 2>/dev/null || $ip -t mangle -F homeproxy_mangle_act
	$ip -t mangle -A homeproxy_mangle_act -p udp -j TPROXY --on-port "$tproxy_port" --tproxy-mark "$tproxy_mark/$tproxy_mark"
	$ip -t mangle -N homeproxy_mangle_port 2>/dev/null || $ip -t mangle -F homeproxy_mangle_port
	if [ "$routing_port" = "common" ]; then
		$ip -t mangle -A homeproxy_mangle_port -p udp -m multiport --dports "$common_port" -j homeproxy_mangle_act 2>/dev/null
	else
		$ip -t mangle -A homeproxy_mangle_port -p udp -j homeproxy_mangle_act
	fi
	emit_steering "$ip" mangle homeproxy_mangle "$rset" homeproxy_mangle_port homeproxy_mangle_act
	emit_gate "$ip" mangle homeproxy_mangle_lanac homeproxy_mangle
	hook_prerouting "$ip" mangle "-p udp" homeproxy_mangle_lanac
	# Router-self UDP steering (mirrors upstream homeproxy_mangle_output -> _mark).
	# A dedicated steering chain exempts sing-box's own egress (self_mark), then
	# applies wan_proxy/local/wan_direct/routing split, ending in MARK tproxy_mark.
	# ip rule (fwmark tproxy_mark -> table -> local dev lo) then re-delivers the
	# packet on lo, where the PREROUTING hook re-enters homeproxy_mangle -> TPROXY.
	$ip -t mangle -N homeproxy_mangle_mark 2>/dev/null || $ip -t mangle -F homeproxy_mangle_mark
	if [ "$routing_port" = "common" ]; then
		$ip -t mangle -A homeproxy_mangle_mark -p udp -m multiport ! --dports "$common_port" -j RETURN 2>/dev/null
	fi
	$ip -t mangle -A homeproxy_mangle_mark -p udp -j MARK --set-mark "$tproxy_mark"
	emit_steering "$ip" mangle homeproxy_mangle_out "$rset" homeproxy_mangle_mark homeproxy_mangle_mark
	$ip -t mangle -D OUTPUT -p udp -j homeproxy_mangle_out 2>/dev/null
	$ip -t mangle -A OUTPUT -p udp -j homeproxy_mangle_out
	# legacy hook cleanup (older revisions jumped straight to the mark chain)
	$ip -t mangle -D OUTPUT -p udp -j homeproxy_mangle_mark 2>/dev/null
	# re-entry: lo packets (already tproxy-marked) run through steering -> TPROXY.
	$ip -t mangle -D PREROUTING -i lo -p udp -j homeproxy_mangle 2>/dev/null
	$ip -t mangle -A PREROUTING -i lo -p udp -j homeproxy_mangle 2>/dev/null
}

# --- TUN steering (mangle MARK) ------------------------------------------
apply_tun() {
	local ip="$1" rset="$2"
	# mark chain: port filter (tcp only in pure tun) + MARK tun_mark
	$ip -t mangle -N homeproxy_tun_mark 2>/dev/null || $ip -t mangle -F homeproxy_tun_mark
	if [ "$routing_port" = "common" ]; then
		if [ "$proxy_mode" = "tun" ]; then
			$ip -t mangle -A homeproxy_tun_mark -p tcp -m multiport ! --dports "$common_port" -j RETURN 2>/dev/null
		fi
		$ip -t mangle -A homeproxy_tun_mark -p udp -m multiport ! --dports "$common_port" -j RETURN 2>/dev/null
	fi
	[ "$proxy_mode" = "tun" ] && $ip -t mangle -A homeproxy_tun_mark -p tcp -j MARK --set-mark "$tun_mark" 2>/dev/null
	$ip -t mangle -A homeproxy_tun_mark -p udp -j MARK --set-mark "$tun_mark" 2>/dev/null
	# steering chain: tun egress + loop prevention at top, then standard order.
	$ip -t mangle -N homeproxy_tun 2>/dev/null || $ip -t mangle -F homeproxy_tun
	$ip -t mangle -A homeproxy_tun -i "$tun_name" -j RETURN 2>/dev/null
	$ip -t mangle -A homeproxy_tun -m mark --mark "$self_mark/$self_mark" -j RETURN 2>/dev/null
	emit_dst_ipset "$ip" mangle homeproxy_tun wan_proxy homeproxy_tun_mark
	emit_local "$ip" mangle homeproxy_tun
	if [ "$routing_mode" != "custom" ]; then
		emit_src_list "$ip" mangle homeproxy_tun lan_global homeproxy_tun_mark
	fi
	emit_dst_ipset "$ip" mangle homeproxy_tun wan_direct RETURN
	emit_routing "$ip" mangle homeproxy_tun "$rset"
	if [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "gfwlist" ]; then
		$ip -t mangle -A homeproxy_tun -p udp -m multiport --dports 80,443 -j DROP 2>/dev/null
	fi
	# gaming: direct mark, no port filter (like upstream meta mark set tun_mark)
	emit_src_list "$ip" mangle homeproxy_tun lan_gaming homeproxy_tun_mark
	$ip -t mangle -A homeproxy_tun -j homeproxy_tun_mark
	# gate + PREROUTING hook (tcp+udp in pure tun; udp only in redirect_tun)
	emit_gate "$ip" mangle homeproxy_tun_lanac homeproxy_tun
	hook_prerouting "$ip" mangle "" homeproxy_tun_lanac
	# router-self -> tun steering (bypasses the gate). lo re-entry not needed:
	# marked packets go to the tun device via ip rule, not back through lo.
	$ip -t mangle -D OUTPUT -j homeproxy_tun 2>/dev/null
	$ip -t mangle -A OUTPUT -j homeproxy_tun
}

# --- DNS redirect (nat) ----------------------------------------------------
# Force clients using a custom DNS server back to local dnsmasq (port 53),
# which applies the per-routing_mode conf-dir rules written by init.d. We do
# NOT redirect straight to sing-box: dnsmasq owns the domain split + ipset
# population. Skipped when the user disables it or dnsmasq already hijacks.
apply_dns() {
	local ip="$1" target="$2"
	$ip -t nat -N homeproxy_dns 2>/dev/null || $ip -t nat -F homeproxy_dns
	emit_local "$ip" nat homeproxy_dns
	$ip -t nat -A homeproxy_dns -p udp --dport 53 -j REDIRECT --to-ports "$target"
	hook_prerouting "$ip" nat "-p udp --dport 53" homeproxy_dns
}

# --- filter-table accepts (mirror upstream firewall_pre.uc) -------------
apply_fw_pre() {
	local ip="$1" need_in=0 need_fwd=0 sect
	for sect in $(uci -q show "$CFG" 2>/dev/null | sed -n "s/^homeproxy\.\([^.]*\)=server/\1/p"); do
		[ "$(uci -q get "$CFG.$sect.enabled")" = "1" ] && [ "$(uci -q get "$CFG.$sect.firewall")" = "1" ] && need_in=1
	done
	if echo "$proxy_mode" | grep -q tun && [ -n "$tun_name" ]; then
		need_in=1; need_fwd=1
	fi
	[ "$need_in" = "1" ] || return 0
	$ip -N homeproxy_in 2>/dev/null || $ip -F homeproxy_in
	for sect in $(uci -q show "$CFG" 2>/dev/null | sed -n "s/^homeproxy\.\([^.]*\)=server/\1/p"); do
		[ "$(uci -q get "$CFG.$sect.enabled")" = "1" ] || continue
		[ "$(uci -q get "$CFG.$sect.firewall")" = "1" ] || continue
		local port; port=$(uci -q get "$CFG.$sect.port"); [ -n "$port" ] || continue
		$ip -A homeproxy_in -p tcp --dport "$port" -j ACCEPT 2>/dev/null
		$ip -A homeproxy_in -p udp --dport "$port" -j ACCEPT 2>/dev/null
	done
	if echo "$proxy_mode" | grep -q tun && [ -n "$tun_name" ]; then
		$ip -A homeproxy_in -i "$tun_name" -j ACCEPT 2>/dev/null
	fi
	$ip -C INPUT -j homeproxy_in 2>/dev/null || $ip -A INPUT -j homeproxy_in
	if [ "$need_fwd" = "1" ]; then
		$ip -N homeproxy_fwd 2>/dev/null || $ip -F homeproxy_fwd
		$ip -A homeproxy_fwd -o "$tun_name" -j ACCEPT 2>/dev/null
		$ip -C FORWARD -j homeproxy_fwd 2>/dev/null || $ip -A FORWARD -j homeproxy_fwd
	fi
}

# --- apply per family -----------------------------------------------------
# UDP tproxy is only meaningful when sing-box actually opens a tproxy inbound
# (a dedicated UDP node or custom routing). Mirrors generate_client.lua gating.
main_udp_node=$(uci_get "config.main_udp_node"); main_udp_node=${main_udp_node:-nil}
# A tproxy inbound exists whenever main_udp_node != nil (incl. "same") or
# routing_mode is custom -- mirrors generate_client.lua's tproxy_port gating.
udp_tproxy=0
if [ "$main_udp_node" != "nil" ] || [ "$routing_mode" = "custom" ]; then
	udp_tproxy=1
fi

if echo "$proxy_mode" | grep -q redirect; then
	apply_tcp "$IP4" "$route_set4"
	if [ "$ipv6" = "1" ]; then apply_tcp "$IP6" "$route_set6"; fi
fi
if echo "$proxy_mode" | grep -q tproxy && [ "$udp_tproxy" = "1" ]; then
	apply_udp "$IP4" "$route_set4"
	if [ "$ipv6" = "1" ]; then apply_udp "$IP6" "$route_set6"; fi
fi
if echo "$proxy_mode" | grep -q tun; then
	apply_tun "$IP4" "$route_set4"
	if [ "$ipv6" = "1" ]; then apply_tun "$IP6" "$route_set6"; fi
fi
# filter-table accepts (server inbound + tun forward/input)
apply_fw_pre "$IP4"
if [ "$ipv6" = "1" ]; then apply_fw_pre "$IP6"; fi

# DNS redirect to dnsmasq (which steers via conf-dir). Skipped when the user
# disables it or dnsmasq already hijacks DNS, to avoid a double redirect.
dns_hijacked=0
[ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect 2>/dev/null)" = "1" ] && dns_hijacked=1
if [ "$dns_redirect" = "1" ] && [ "$dns_hijacked" != "1" ]; then
	apply_dns "$IP4" "$dnsmasq_port"
	[ "$ipv6" = "1" ] && apply_dns "$IP6" "$dnsmasq_port"
else
	echo "homeproxy: DNS redirect skipped (dns_redirect=$dns_redirect dnsmasq_hijacked=$dns_hijacked)." >&2
fi

echo "homeproxy: firewall rules applied (mode=$proxy_mode routing=$routing_mode lan=$lan_proxy_mode ifaces=$LAN_IFS)." >&2
exit 0
