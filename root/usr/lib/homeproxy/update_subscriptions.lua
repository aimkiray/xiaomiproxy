#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy subscription updater (Lua port of update_subscriptions.uc).
-- Fetches subscription URLs, parses common share-link schemes (ss, vmess,
-- vless, trojan, hysteria2, http(s), socks, tuic, anytls) and SIP008, then
-- writes nodes to /etc/config/homeproxy. Requires: lua, uci binding, luci.json,
-- busybox base64, md5sum, wget.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp  = require("homeproxy")
local uci = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"
uci:load(CFG)

local UCIMAIN = "config"
local UCINODE = "node"
local UCISUB  = "subscription"

local function isEmpty(v) return hp.isEmpty(v) end
local function push(t, v) t[#t + 1] = v end
local function log(msg) hp.log(msg, "SUBSCRIBE") end

local allow_insecure   = uci:get(CFG, UCISUB, "allow_insecure") or "0"
local filter_mode       = uci:get(CFG, UCISUB, "filter_nodes") or "disabled"
local filter_keywords  = uci:get(CFG, UCISUB, "filter_keywords") or {}
local packet_encoding  = uci:get(CFG, UCISUB, "packet_encoding") or "xudp"
local subscription_urls = uci:get(CFG, UCISUB, "subscription_url") or {}
local user_agent        = uci:get(CFG, UCISUB, "user_agent")
local via_proxy         = uci:get(CFG, UCISUB, "update_via_proxy") or "0"

local routing_mode = uci:get(CFG, UCIMAIN, "routing_mode") or "bypass_mainland_china"
local main_node, main_udp_node
if routing_mode ~= "custom" then
    main_node = uci:get(CFG, UCIMAIN, "main_node") or "nil"
    main_udp_node = uci:get(CFG, UCIMAIN, "main_udp_node") or "nil"
end

if type(subscription_urls) ~= "table" then subscription_urls = { subscription_urls } end
if type(filter_keywords) ~= "table" then filter_keywords = { filter_keywords } end

local function filter_check(name)
    if isEmpty(name) or filter_mode == "disabled" or #filter_keywords == 0 then
        return false
    end
    local matched = false
    for _, kw in ipairs(filter_keywords) do
        if name:find(kw) then matched = true end
    end
    return (filter_mode == "whitelist") and not matched or matched
end

-- convert "a,b,c" or table into a uci list-friendly table
local function aslist(v)
    if isEmpty(v) then return nil end
    if type(v) == "table" then return v end
    local t = {}
    for part in tostring(v):gmatch("[^,]+") do t[#t + 1] = part end
    return #t > 0 and t or nil
end

-- parse a single share link / SIP008 entry into a node config table
local function parse_uri(uri)
    if type(uri) == "table" then -- SIP008
        if uri.nodetype == "sip008" then
            return {
                label = uri.remarks,
                type = "shadowsocks",
                address = uri.server,
                port = uri.server_port and tostring(uri.server_port),
                shadowsocks_encrypt_method = uri.method,
                password = uri.password,
                shadowsocks_plugin = uri.plugin,
                shadowsocks_plugin_opts = uri.plugin_opts,
            }
        end
        return nil
    end
    if type(uri) ~= "string" then return nil end
    uri = uri:gsub("^%s+", ""):gsub("%s+$", "")
    local scheme, rest = uri:match("^(%w[%w+.-]*)://(.*)$")
    if not scheme then return nil end
    scheme = scheme:lower()
    -- vmess payload is base64-encoded JSON, not a host:port URL, so it must be
    -- handled before the parseURL guard (parseURL rejects it as an invalid host).
    if scheme == "vmess" then
        local raw = hp.decodeBase64Str(rest)
        if isEmpty(raw) then return nil end
        local ok, j = pcall(hp.decode_json, raw)
        if not ok or type(j) ~= "table" then return nil end
        local net = j.net or "tcp"
        return { label = j.ps, type = "vmess", address = j.add, port = tostring(j.port),
            uuid = j.id, vmess_alterid = tostring(j.aid or 0), vmess_encrypt = j.scy or "auto",
            vmess_global_padding = (j.padding == "1") and "1" or "0",
            tls = (j.tls == "tls") and "1" or "0", tls_sni = j.sni,
            tls_insecure = (j.verify_cert == "0" or j.allowInsecure == "1") and "1" or "0",
            tls_alpn = aslist(j.alpn), tls_utls = j.fp,
            transport = (net ~= "tcp") and net or nil,
            ws_path = (net == "ws") and (j.path or "/") or nil,
            ws_host = (net == "ws") and j.host or nil,
            grpc_servicename = (net == "grpc") and j.path or nil,
            http_path = (net == "http") and (j.path or "/") or nil,
            http_host = (net == "http") and j.host or nil,
            packet_encoding = packet_encoding }
    end
    local url = hp.parseURL("http://" .. rest)
    if not url then return nil end
    local p = url.searchParams or {}
    local label = url.hash and hp.urldecode(url.hash) or nil
    local function has(k) return p[k] ~= nil end

    if scheme == "anytls" then
        return { label = label, type = "anytls", address = url.hostname,
            port = url.port, password = hp.urldecode(url.username), tls = "1",
            tls_sni = p.sni, tls_alpn = aslist(p.alpn),
            tls_insecure = (p.insecure == "1") and "1" or "0",
            tls_reality = (p.security == "reality") and "1" or "0",
            tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
            tls_utls = (p.fp and p.fp ~= "") and p.fp or nil }

    elseif scheme == "http" or scheme == "https" then
        return { label = label, type = "http", address = url.hostname, port = url.port,
            username = url.username and hp.urldecode(url.username) or nil,
            password = url.password and hp.urldecode(url.password) or nil,
            tls = (scheme == "https") and "1" or "0" }

    elseif scheme == "socks" then
        return { label = label, type = "socks", socks_version = "5",
            address = url.hostname, port = url.port,
            username = url.username and hp.urldecode(url.username) or nil,
            password = url.password and hp.urldecode(url.password) or nil }

    elseif scheme == "trojan" then
        return { label = label, type = "trojan", address = url.hostname, port = url.port,
            password = hp.urldecode(url.username), tls = "1", tls_sni = p.sni,
            tls_insecure = (p.allowInsecure == "1" or p.insecure == "1") and "1" or "0",
            tls_alpn = aslist(p.alpn), transport = (p.type and p.type ~= "tcp") and p.type or nil,
            ws_path = (p.type == "ws") and (p.path or "/") or nil,
            ws_host = (p.type == "ws") and p.host or nil,
            grpc_servicename = (p.type == "grpc") and p.serviceName or nil,
            http_path = (p.type == "http") and (p.path or "/") or nil,
            http_host = (p.type == "http") and p.host or nil }

    elseif scheme == "hysteria2" or scheme == "hy2" then
        return { label = label, type = "hysteria2", address = url.hostname, port = url.port,
            password = (url.username and hp.urldecode(url.username)) or hp.urldecode(url.password),
            tls = "1", tls_sni = p.sni,
            tls_insecure = (p.insecure == "1") and "1" or "0",
            tls_alpn = aslist(p.alpn),
            hysteria_obfs_type = p.obfs and "salamander" or nil,
            hysteria_obfs_password = p.obfs,
            hysteria_up_mbps = p.up, hysteria_down_mbps = p.down,
            hysteria_hopping_port = p.mport }

    elseif scheme == "tuic" then
        return { label = label, type = "tuic", address = url.hostname, port = url.port,
            uuid = hp.urldecode(url.username), password = hp.urldecode(url.password),
            tls = "1", tls_sni = p.sni, tls_alpn = aslist(p.alpn),
            tls_insecure = (p.allowInsecure == "1" or p.insecure == "1") and "1" or "0",
            tuic_congestion_control = p.congestion_control,
            tuic_udp_relay_mode = p.udp_relay_mode,
            tuic_enable_zero_rtt = (p.zero_rtt_handshake == "1") and "1" or "0" }

    elseif scheme == "vless" then
        local node = { label = label, type = "vless", address = url.hostname, port = url.port,
            uuid = hp.urldecode(url.username),
            flow = p.flow,
            tls = (p.security == "tls" or p.security == "reality") and "1" or "0",
            tls_sni = p.sni, tls_insecure = (p.allowInsecure == "1" or p.insecure == "1") and "1" or "0",
            tls_alpn = aslist(p.alpn),
            tls_reality = (p.security == "reality") and "1" or "0",
            tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
            tls_utls = (p.fp and p.fp ~= "") and p.fp or nil,
            transport = (p.type and p.type ~= "tcp") and p.type or nil,
            ws_path = (p.type == "ws") and (p.path or "/") or nil,
            ws_host = (p.type == "ws") and p.host or nil,
            grpc_servicename = (p.type == "grpc") and p.serviceName or nil,
            http_path = (p.type == "http") and (p.path or "/") or nil,
            http_host = (p.type == "http") and p.host or nil,
            packet_encoding = packet_encoding }
        return node

    elseif scheme == "ss" then
        -- SIP002: ss://base64(method:pass)@host:port#tag  or legacy base64(method:pass@host:port)
        local body, frag = rest, nil
        if rest:find("#") then body, frag = rest:match("^([^#]*)#(.*)$") end
        local sslabel = frag and frag ~= "" and hp.urldecode(frag) or label
        local method, pass, host, port
        local at = body:find("@", 1, true)
        if at then
            local userinfo = body:sub(1, at - 1)
            local hostport = body:sub(at + 1):gsub("%?.*$", "")
            method, pass = userinfo:match("^([^:]+):(.*)$")
            if not method then
                local dec = hp.decodeBase64Str(userinfo)
                if dec then method, pass = dec:match("^([^:]+):(.*)$") end
            end
            host, port = hostport:match("^([^:]+):(%d+)$")
        else
            local dec = hp.decodeBase64Str(body)
            if dec then method, pass, host, port = dec:match("^([^:]+):([^@]+)@([^:]+):(%d+)$") end
        end
        if method and host and port then
            return { label = sslabel, type = "shadowsocks", address = host, port = port,
                shadowsocks_encrypt_method = method, password = pass,
                shadowsocks_plugin = p.plugin, shadowsocks_plugin_opts = p["plugin-opts"] }
        end
        return nil
    end
    return nil
end

local node_cache, node_result = {}, {}

local function main()
    hp.mkdir_p(hp.RUN_DIR)
    if #subscription_urls == 0 then
        log("No subscription URL configured.")
        return
    end

    if via_proxy ~= "1" then
        log("Stopping service before subscription update.")
        os.execute("/etc/init.d/homeproxy stop >/dev/null 2>&1")
    end

    for _, url in ipairs(subscription_urls) do
        if isEmpty(url) then
        elseif not url:match("^https?://") and not url:match("^sip008://") then
            log("Skipping invalid URL: " .. url)
        else
            local groupHash = hp.md5(url)
            node_cache[groupHash] = {}
            push(node_result, {})

            local fetch_url = url
            if fetch_url:match("^sip008://") then
                fetch_url = fetch_url:gsub("^sip008://", "https://")
            end

            local res = hp.wGET(fetch_url, user_agent)
            if isEmpty(res) then
                log("Failed to fetch: " .. url)
            else
                -- try JSON (SIP008) first, else base64 node list
                local nodes
                local ok, j = pcall(hp.decode_json, res)
                if ok and type(j) == "table" and j.servers and type(j.servers) == "table" then
                    nodes = {}
                    for _, s in ipairs(j.servers) do
                        push(nodes, { nodetype = "sip008", remarks = s.remarks, server = s.server,
                            server_port = s.server_port, method = s.method, password = s.password,
                            plugin = s.plugin, plugin_opts = s.plugin_opts })
                    end
                else
                    local dec = hp.decodeBase64Str(res)
                    if not isEmpty(dec) then res = dec end
                    nodes = hp.split(res, "[\r\n]+")
                end

                local count = 0
                for _, n in ipairs(nodes) do
                    if not isEmpty(n) then
                        local cfg = parse_uri(n)
                        if not isEmpty(cfg) then
                            local label = cfg.label
                            cfg.label = nil
                            local confHash = hp.md5(hp.encode_json(cfg))
                            local nameHash = hp.md5(label)
                            cfg.label = label
                            if filter_check(label) then
                                log("Skipping blacklisted node: " .. tostring(label))
                            elseif node_cache[groupHash][confHash] or node_cache[groupHash][nameHash] then
                                log("Skipping duplicate node: " .. tostring(label))
                            else
                                if cfg.tls == "1" and allow_insecure == "1" then
                                    cfg.tls_insecure = "1"
                                end
                                if cfg.type == "vless" or cfg.type == "vmess" then
                                    cfg.packet_encoding = packet_encoding
                                end
                                cfg.grouphash = groupHash
                                push(node_result[#node_result], cfg)
                                node_cache[groupHash][confHash] = cfg
                                node_cache[groupHash][nameHash] = cfg
                                count = count + 1
                            end
                        end
                    end
                end
                if count == 0 then
                    log("No valid node found in " .. url)
                else
                    log(string.format("Fetched %s of %s nodes from %s.", count, #nodes, url))
                end
            end
        end
    end

    if isEmpty(node_result) or #node_result == 0 then
        log("Failed to update subscriptions: no valid node found.")
        if via_proxy ~= "1" then
            log("Starting service...")
            os.execute("/etc/init.d/homeproxy start >/dev/null 2>&1")
        end
        return
    end

    -- remove stale nodes + update existing
    local added, removed = 0, 0
    uci:foreach(CFG, UCINODE, function(cfg)
        if not cfg.grouphash then return end -- user-created node
        local gh = cfg.grouphash
        if not node_cache[gh] or not node_cache[gh][cfg[".name"]] then
            uci:delete(CFG, cfg[".name"])
            removed = removed + 1
            log("Removing node: " .. tostring(cfg.label))
        else
            for k in pairs(cfg) do
                if k:sub(1, 1) ~= "." then
                    local new = node_cache[gh][cfg[".name"]][k]
                    if new ~= nil then
                        uci:set(CFG, cfg[".name"], k, new)
                    else
                        uci:delete(CFG, cfg[".name"], k)
                    end
                end
            end
            node_cache[gh][cfg[".name"]].isExisting = true
        end
    end)

    -- add new nodes
    for _, nodes in ipairs(node_result) do
        for _, node in ipairs(nodes) do
            if not node.isExisting then
                local nameHash = hp.md5(node.label)
                uci:set(CFG, nameHash, "node")
                for k, v in pairs(node) do
                    if k ~= "isExisting" then uci:set(CFG, nameHash, k, v) end
                end
                added = added + 1
                log("Adding node: " .. tostring(node.label))
            end
        end
    end
    uci:commit(CFG)

    local need_restart = (via_proxy ~= "1")
    if not isEmpty(main_node) then
        local first
        uci:foreach(CFG, UCINODE, function(s) first = s[".name"]; return false end)
        if first then
            if main_node == "urltest" then
                -- leave as-is if still valid
            elseif not uci:get_all(CFG, main_node) then
                uci:set(CFG, UCIMAIN, "main_node", first)
                uci:commit(CFG)
                need_restart = true
                log("Main node is gone, switching to the first node.")
            end
            if not isEmpty(main_udp_node) and main_udp_node ~= "same"
                and main_udp_node ~= "urltest" and not uci:get_all(CFG, main_udp_node) then
                uci:set(CFG, UCIMAIN, "main_udp_node", first)
                uci:commit(CFG)
                need_restart = true
                log("Main UDP node is gone, switching to the first node.")
            end
        else
            uci:set(CFG, UCIMAIN, "main_node", "nil")
            uci:set(CFG, UCIMAIN, "main_udp_node", "nil")
            uci:commit(CFG)
            need_restart = true
            log("No available node, disable tproxy.")
        end
    end

    if need_restart then
        log("Restarting service...")
        os.execute("/etc/init.d/homeproxy restart >/dev/null 2>&1")
    end
    log(string.format("%s nodes added, %s removed. Successfully updated subscriptions.", added, removed))
end

local ok, err = pcall(main)
if not ok then
    log("[FATAL ERROR] " .. tostring(err))
    if via_proxy ~= "1" then
        os.execute("/etc/init.d/homeproxy start >/dev/null 2>&1")
    end
    os.exit(1)
end
