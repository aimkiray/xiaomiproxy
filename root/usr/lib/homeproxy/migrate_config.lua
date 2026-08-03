#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy config migration / defaults (Lua port, simplified for MiWiFi).
-- Idempotent: ensures sane defaults and removes deprecated options. Safe to
-- run repeatedly. Expects the shipped default /etc/config/homeproxy baseline.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp  = require("homeproxy")
local uci = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"
uci:load(CFG)

local function isEmpty(v) return hp.isEmpty(v) end
local function changed() return uci:changes(CFG) ~= nil and next(uci:changes(CFG)) ~= nil end

-- ensure a scalar default on an existing named section
local function ensure(sec, opt, default)
    if isEmpty(uci:get(CFG, sec, opt)) then
        uci:set(CFG, sec, opt, default)
    end
end

-- ensure infra defaults
if uci:get_all(CFG, "infra") then
    ensure("infra", "mixed_port", "5330")
    ensure("infra", "redirect_port", "5331")
    ensure("infra", "tproxy_port", "5332")
    ensure("infra", "dns_port", "5333")
    ensure("infra", "self_mark", "100")
    ensure("infra", "tproxy_mark", "101")
    ensure("infra", "tun_mark", "102")
    ensure("infra", "tun_name", "singtun0")
    ensure("infra", "sniff_override", "1")
    ensure("infra", "ntp_server", "nil")
    -- deprecated
    if not isEmpty(uci:get(CFG, "infra", "tun_gso")) then uci:delete(CFG, "infra", "tun_gso") end
    if not isEmpty(uci:get(CFG, "infra", "china_dns_port")) then uci:delete(CFG, "infra", "china_dns_port") end
end

-- ensure main config defaults
if uci:get_all(CFG, "config") then
    ensure("config", "routing_mode", "bypass_mainland_china")
    ensure("config", "proxy_mode", "redirect_tproxy")
    ensure("config", "ipv6_support", "0")
    ensure("config", "log_level", "warn")
    if uci:get(CFG, "config", "routing_port") == "all" then
        uci:delete(CFG, "config", "routing_port")
    end
    -- china_dns_server must be a single server
    local cds = uci:get(CFG, "config", "china_dns_server")
    if type(cds) == "table" then
        uci:set(CFG, "config", "china_dns_server", cds[1])
    elseif type(cds) == "string" and cds:find(",") then
        uci:set(CFG, "config", "china_dns_server", cds:match("^([^,]+)"))
    elseif cds == "wan_114" then
        uci:set(CFG, "config", "china_dns_server", "114.114.114.114")
    end
end

-- server defaults
uci:foreach(CFG, "server", function(s)
    if isEmpty(uci:get(CFG, s[".name"], "log_level")) then
        uci:set(CFG, s[".name"], "log_level", "warn")
    end
    if not isEmpty(s.sniff_override) then uci:delete(CFG, s[".name"], "sniff_override") end
    if not isEmpty(s.domain_strategy) then uci:delete(CFG, s[".name"], "domain_strategy") end
end)

-- node deprecated options
uci:foreach(CFG, "node", function(s)
    if not isEmpty(s.tls_ech_tls_disable_drs) then uci:delete(CFG, s[".name"], "tls_ech_tls_disable_drs") end
    if not isEmpty(s.tls_ech_enable_pqss) then uci:delete(CFG, s[".name"], "tls_ech_enable_pqss") end
    if not isEmpty(s.wireguard_gso) then uci:delete(CFG, s[".name"], "wireguard_gso") end
end)

-- experimental section was removed
if uci:get_all(CFG, "experimental") then
    uci:delete(CFG, "experimental")
end

if changed() then uci:commit(CFG) end
