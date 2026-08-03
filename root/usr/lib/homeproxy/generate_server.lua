#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy server config generator (Lua port of generate_server.uc).
-- Emits the sing-box server JSON to /var/run/homeproxy/sing-box-s.json.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp  = require("homeproxy")
local uci = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local UCICONFIG = "homeproxy"
uci:load(UCICONFIG)

local UCISERVER = "server"
local log_level = uci:get(UCICONFIG, UCISERVER, "log_level") or "warn"

local function strToBool(v) return hp.strToBool(v) end
local function strToInt(v) return hp.strToInt(v) end
local function strToTime(v) return hp.strToTime(v) end
local function isEmpty(v) return hp.isEmpty(v) end
local function push(t, v) t[#t + 1] = v end

local config = {}
config.log = {
    disabled = false,
    level = log_level,
    output = hp.RUN_DIR .. "/sing-box-s.log",
    timestamp = true,
}
config.inbounds = {}

uci:foreach(UCICONFIG, UCISERVER, function(cfg)
    if cfg.enabled ~= "1" then return end
    push(config.inbounds, {
        type = cfg.type,
        tag = "cfg-" .. cfg[".name"] .. "-in",
        listen = cfg.address or "::",
        listen_port = strToInt(cfg.port),
        bind_interface = cfg.bind_interface,
        reuse_addr = strToBool(cfg.reuse_addr),
        tcp_fast_open = strToBool(cfg.tcp_fast_open),
        tcp_multi_path = strToBool(cfg.tcp_multi_path),
        udp_fragment = strToBool(cfg.udp_fragment),
        udp_timeout = strToTime(cfg.udp_timeout),
        network = cfg.network,
        padding_scheme = cfg.anytls_padding_scheme,
        up_mbps = strToInt(cfg.hysteria_up_mbps),
        down_mbps = strToInt(cfg.hysteria_down_mbps),
        obfs = cfg.hysteria_obfs_type and { type = cfg.hysteria_obfs_type, password = cfg.hysteria_obfs_password }
            or cfg.hysteria_obfs_password,
        recv_window_conn = strToInt(cfg.hysteria_recv_window_conn),
        recv_window_client = strToInt(cfg.hysteria_revc_window_client),
        max_conn_client = strToInt(cfg.hysteria_max_conn_client),
        disable_mtu_discovery = strToBool(cfg.hysteria_disable_mtu_discovery),
        ignore_client_bandwidth = strToBool(cfg.hysteria_ignore_client_bandwidth),
        masquerade = cfg.hysteria_masquerade,
        method = (cfg.type == "shadowsocks") and cfg.shadowsocks_encrypt_method or nil,
        password = (cfg.type == "shadowsocks" or cfg.type == "shadowtls") and cfg.password or nil,
        congestion_control = cfg.tuic_congestion_control,
        auth_timeout = strToTime(cfg.tuic_auth_timeout),
        zero_rtt_handshake = strToBool(cfg.tuic_enable_zero_rtt),
        heartbeat = strToTime(cfg.tuic_heartbeat),
        users = (cfg.type ~= "shadowsocks") and {
            {
                name = (cfg.type ~= "http" and cfg.type ~= "mixed" and cfg.type ~= "naive"
                    and cfg.type ~= "socks") and ("cfg-" .. cfg[".name"] .. "-server") or nil,
                username = cfg.username,
                password = cfg.password,
                auth = (cfg.hysteria_auth_type == "base64") and cfg.hysteria_auth_payload or nil,
                auth_str = (cfg.hysteria_auth_type == "string") and cfg.hysteria_auth_payload or nil,
                uuid = cfg.uuid,
                flow = cfg.vless_flow,
                alterId = strToInt(cfg.vmess_alterid),
            },
        } or nil,
        multiplex = (cfg.multiplex == "1") and {
            enabled = true,
            padding = strToBool(cfg.multiplex_padding),
            brutal = (cfg.multiplex_brutal == "1") and {
                enabled = true,
                up_mbps = strToInt(cfg.multiplex_brutal_up),
                down_mbps = strToInt(cfg.multiplex_brutal_down),
            } or nil,
        } or nil,
        tls = (cfg.tls == "1") and {
            enabled = true,
            server_name = cfg.tls_sni,
            alpn = cfg.tls_alpn,
            min_version = cfg.tls_min_version,
            max_version = cfg.tls_max_version,
            cipher_suites = cfg.tls_cipher_suites,
            certificate_path = cfg.tls_cert_path,
            key_path = cfg.tls_key_path,
            acme = (cfg.tls_acme == "1") and {
                domain = cfg.tls_acme_domain,
                data_directory = hp.HP_DIR .. "/certs",
                default_server_name = cfg.tls_acme_dsn,
                email = cfg.tls_acme_email,
                provider = cfg.tls_acme_provider,
                disable_http_challenge = strToBool(cfg.tls_acme_dhc),
                disable_tls_alpn_challenge = cfg.tls_acme_dtac,
                alternative_http_port = strToInt(cfg.tls_acme_ahp),
                alternative_tls_port = strToInt(cfg.tls_acme_atp),
                external_account = (cfg.tls_acme_external_account == "1") and {
                    key_id = cfg.tls_acme_ea_keyid,
                    mac_key = cfg.tls_acme_ea_mackey,
                } or nil,
                dns01_challenge = (cfg.tls_dns01_challenge == "1") and {
                    provider = cfg.tls_dns01_provider,
                    access_key_id = cfg.tls_dns01_ali_akid,
                    access_key_secret = cfg.tls_dns01_ali_aksec,
                    region_id = cfg.tls_dns01_ali_rid,
                    api_token = cfg.tls_dns01_cf_api_token,
                } or nil,
            } or nil,
            ech = cfg.tls_ech_key and { enabled = true, key = hp.split(cfg.tls_ech_key, "\n") } or nil,
            reality = (cfg.tls_reality == "1") and {
                enabled = true,
                private_key = cfg.tls_reality_private_key,
                short_id = cfg.tls_reality_short_id,
                max_time_difference = strToTime(cfg.tls_reality_max_time_difference),
                handshake = {
                    server = cfg.tls_reality_server_addr,
                    server_port = strToInt(cfg.tls_reality_server_port),
                },
            } or nil,
        } or nil,
        transport = not isEmpty(cfg.transport) and {
            type = cfg.transport,
            host = cfg.http_host or cfg.httpupgrade_host,
            path = cfg.http_path or cfg.ws_path,
            headers = cfg.ws_host and { Host = cfg.ws_host } or nil,
            method = cfg.http_method,
            max_early_data = strToInt(cfg.websocket_early_data),
            early_data_header_name = cfg.websocket_early_data_header,
            service_name = cfg.grpc_servicename,
            idle_timeout = strToTime(cfg.http_idle_timeout),
            ping_timeout = strToTime(cfg.http_ping_timeout),
        } or nil,
    })
end)

if #config.inbounds == 0 then os.exit(1) end

hp.mkdir_p(hp.RUN_DIR)
hp.writefile(hp.RUN_DIR .. "/sing-box-s.json", hp.encode_json(config))
