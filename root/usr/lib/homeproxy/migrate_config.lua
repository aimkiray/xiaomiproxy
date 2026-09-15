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
    ensure("infra", "ntp_server", "nil")
    -- deprecated
    if not isEmpty(uci:get(CFG, "infra", "tun_gso")) then uci:delete(CFG, "infra", "tun_gso") end
    if not isEmpty(uci:get(CFG, "infra", "china_dns_port")) then uci:delete(CFG, "infra", "china_dns_port") end
    -- sniff_override never had an effect in this port (no consumer).
    if not isEmpty(uci:get(CFG, "infra", "sniff_override")) then uci:delete(CFG, "infra", "sniff_override") end
end
if not isEmpty(uci:get(CFG, "routing", "sniff_override")) then
    uci:delete(CFG, "routing", "sniff_override")
end

-- ensure main config defaults
if uci:get_all(CFG, "config") then
    ensure("config", "routing_mode", "bypass_mainland_china")
    ensure("config", "proxy_mode", "redirect_tproxy")
    ensure("config", "ipv6_support", "1")
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

-- Normalize subscription node section names to md5(grouphash|label) (F6).
-- Older builds hashed the bare label, which collides across subscriptions;
-- an even older scheme embedded a NUL that the md5 pipeline truncated.
-- Rename sections in place and repoint every reference so the user's chosen
-- main node survives the upgrade.
do
    local renames = {}
    uci:foreach(CFG, "node", function(s)
        local gh, lbl = s.grouphash, s.label
        if isEmpty(gh) or isEmpty(lbl) then return end
        local want = hp.md5(tostring(gh) .. "|" .. tostring(lbl))
        if not want or s[".name"] == want then return end
        if uci:get_all(CFG, want) then return end  -- target exists; leave it
        renames[s[".name"]] = want
    end)
    if next(renames) ~= nil then
        for old, new in pairs(renames) do
            local sec = uci:get_all(CFG, old)
            if sec then
                uci:set(CFG, new, "node")
                for k, v in pairs(sec) do
                    if k:sub(1, 1) ~= "." then uci:set(CFG, new, k, v) end
                end
                uci:delete(CFG, old)
            end
        end
        for _, opt in ipairs({ "main_node", "main_udp_node" }) do
            local v = uci:get(CFG, "config", opt)
            if v and renames[v] then uci:set(CFG, "config", opt, renames[v]) end
        end
        for _, opt in ipairs({ "main_urltest_nodes", "main_udp_urltest_nodes" }) do
            local l = uci:get(CFG, "config", opt)
            if type(l) == "table" then
                local ch = false
                for i, v in ipairs(l) do
                    if renames[v] then l[i] = renames[v]; ch = true end
                end
                if ch then uci:set(CFG, "config", opt, l) end
            end
        end
        uci:foreach(CFG, "routing_node", function(s)
            if s.node and renames[s.node] then
                uci:set(CFG, s[".name"], "node", renames[s.node])
            end
            local l = s.urltest_nodes
            if type(l) == "table" then
                local ch = false
                for i, v in ipairs(l) do
                    if renames[v] then l[i] = renames[v]; ch = true end
                end
                if ch then uci:set(CFG, s[".name"], "urltest_nodes", l) end
            end
        end)
    end
end

-- experimental section was removed
if uci:get_all(CFG, "experimental") then
    uci:delete(CFG, "experimental")
end

if changed() then uci:commit(CFG) end
