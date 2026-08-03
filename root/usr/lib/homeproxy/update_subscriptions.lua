#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy subscription updater (Lua port of update_subscriptions.uc).
-- Fetches subscription URLs, parses common share-link schemes (ss, vmess,
-- vless, trojan, hysteria, hysteria2, http(s), socks, tuic, anytls) and
-- SIP008, then writes nodes to /etc/config/homeproxy. Requires: lua, uci
-- binding, luci.json, busybox base64, md5sum, wget.

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

local allow_insecure    = uci:get(CFG, UCISUB, "allow_insecure") or "0"
local filter_mode        = uci:get(CFG, UCISUB, "filter_nodes") or "disabled"
local filter_keywords    = uci:get(CFG, UCISUB, "filter_keywords") or {}
local packet_encoding    = uci:get(CFG, UCISUB, "packet_encoding") or "xudp"
local subscription_urls  = uci:get(CFG, UCISUB, "subscription_url") or {}
local user_agent         = uci:get(CFG, UCISUB, "user_agent")
local via_proxy          = uci:get(CFG, UCISUB, "update_via_proxy") or "0"

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
	-- Lua patterns stand in for the upstream JS regex; plain keywords match as-is.
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

---------------------------------------------------------------------------
-- sing-box feature detection. Upstream used ubus("luci.homeproxy",
-- "singbox_get_features"), unavailable on LuCI-less routers. We probe the
-- binary with minimal configs: `sing-box check` rejects outbounds whose
-- features were not compiled in.
---------------------------------------------------------------------------
local function singbox_bin()
	local p = os.getenv("HP_SINGBOX")
	if p and p ~= "" then local f = io.open(p, "rb"); if f then f:close(); return p end end
	local f = io.popen("command -v sing-box 2>/dev/null")
	if f then local v = hp.trim(f:read("*a") or ""); f:close(); if v ~= "" then return v end end
	for _, cand in ipairs({ "/usr/bin/sing-box", "/data/other_vol/bin/sing-box" }) do
		local g = io.open(cand, "rb")
		if g then g:close(); return cand end
	end
	return "/usr/bin/sing-box"
end

local function exec_ok(code) return code == 0 or code == true end

local function detect_features()
	local feat = { with_quic = false, with_utls = false, with_hysteria = false }
	local bin = singbox_bin()
	local tmp = "/tmp/.hp_feat.json"
	-- QUIC: a minimal hysteria2 outbound requires QUIC support.
	hp.writefile(tmp, '{"outbounds":[{"type":"hysteria2","tag":"q","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"n"}}]}\n')
	if exec_ok(os.execute(hp.shellQuote(bin) .. " check --config " .. hp.shellQuote(tmp) .. " >/dev/null 2>&1")) then
		feat.with_quic = true
	end
	-- uTLS: a minimal vless outbound with a utls fingerprint.
	hp.writefile(tmp, '{"outbounds":[{"type":"vless","tag":"u","server":"127.0.0.1","server_port":443,"uuid":"00000000-0000-0000-0000-000000000000","tls":{"enabled":true,"server_name":"n","utls":{"enabled":true,"fingerprint":"chrome"}}}]}\n')
	if exec_ok(os.execute(hp.shellQuote(bin) .. " check --config " .. hp.shellQuote(tmp) .. " >/dev/null 2>&1")) then
		feat.with_utls = true
	end
	-- hysteria v1 outbound type (removed from sing-box 1.12+).
	hp.writefile(tmp, '{"outbounds":[{"type":"hysteria","tag":"h","server":"127.0.0.1","server_port":443,"up_mbps":10,"down_mbps":50,"tls":{"enabled":true,"server_name":"n"}}]}\n')
	if exec_ok(os.execute(hp.shellQuote(bin) .. " check --config " .. hp.shellQuote(tmp) .. " >/dev/null 2>&1")) then
		feat.with_hysteria = true
	end
	os.remove(tmp)
	log(string.format("sing-box features: quic=%s utls=%s hysteria=%s",
		tostring(feat.with_quic), tostring(feat.with_utls), tostring(feat.with_hysteria)))
	return feat
end

local sf_ok, sf = pcall(detect_features)
local sing_features = (sf_ok and sf) or { with_quic = true, with_utls = true, with_hysteria = false }

local function skip_no_quic(scheme, label, host)
	log(string.format("Skipping unsupported %s node: %s.", scheme, tostring(label) or host))
	log("Please rebuild sing-box with QUIC support!")
	return nil
end

-- Extract v2ray-style "?ed=N" early-data suffix from a websocket path.
local function apply_ws_early_data(cfg)
	if not cfg.ws_path then return end
	local path, ed = cfg.ws_path:match("^(.-)%?ed=(.+)$")
	if path and ed then
		cfg.ws_path = path
		cfg.websocket_early_data = ed
		cfg.websocket_early_data_header = "Sec-WebSocket-Protocol"
	end
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
		-- "Lovely" shadowrocket format uses "&" instead of JSON.
		if rest:find("&", 1, true) then
			log("Skipping unsupported vmess format.")
			return nil
		end
		local raw = hp.decodeBase64Str(rest)
		if isEmpty(raw) then return nil end
		local ok, j = pcall(hp.decode_json, raw)
		if not ok or type(j) ~= "table" then
			log("Skipping unsupported vmess format.")
			return nil
		end
		if j.v ~= "2" then
			log("Skipping unsupported vmess format.")
			return nil
		end
		local net = j.net or "tcp"
		local nm = j.ps or j.add
		-- Unsupported transports.
		if net == "kcp" then
			log(string.format("Skipping unsupported vmess node: %s.", tostring(nm)))
			return nil
		elseif net == "quic" and ((j.type and j.type ~= "none") or j.path or not sing_features.with_quic) then
			log(string.format("Skipping unsupported vmess node: %s.", tostring(nm)))
			if not sing_features.with_quic then log("Please rebuild sing-box with QUIC support!") end
			return nil
		end
		local cfg = {
			label = j.ps and hp.urldecode(j.ps) or nil,
			type = "vmess",
			address = j.add,
			port = tostring(j.port),
			uuid = j.id,
			vmess_alterid = tostring(j.aid or 0),
			vmess_encrypt = j.scy or "auto",
			vmess_global_padding = "1",
			transport = (net ~= "tcp") and net or nil,
			tls = (j.tls == "tls") and "1" or "0",
			tls_sni = j.sni or j.host,
			tls_alpn = aslist(j.alpn),
			tls_utls = (sing_features.with_utls and not isEmpty(j.fp)) and j.fp or nil,
			packet_encoding = packet_encoding,
		}
		if net == "h2" or (net == "tcp" and j.type == "http") then
			cfg.transport = "http"
			cfg.http_host = aslist(j.host)
			cfg.http_path = j.path
		elseif net == "grpc" then
			cfg.grpc_servicename = j.path
		elseif net == "httpupgrade" then
			cfg.httpupgrade_host = j.host
			cfg.http_path = j.path
		elseif net == "ws" then
			cfg.ws_host = j.host
			cfg.ws_path = j.path or "/"
			apply_ws_early_data(cfg)
		end
		return cfg
	end

	local url = hp.parseURL("http://" .. rest)
	if not url then return nil end
	local p = url.searchParams or {}
	local label = url.hash and hp.urldecode(url.hash) or nil

	if scheme == "anytls" then
		return { label = label, type = "anytls", address = url.hostname,
			port = url.port, password = hp.urldecode(url.username), tls = "1",
			tls_sni = p.sni, tls_alpn = aslist(p.alpn),
			tls_insecure = (p.insecure == "1") and "1" or "0",
			tls_reality = (p.security == "reality") and "1" or "0",
			tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
			tls_utls = (sing_features.with_utls and not isEmpty(p.fp)) and p.fp or nil }

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
		local cfg = { label = label, type = "trojan", address = url.hostname, port = url.port,
			password = hp.urldecode(url.username), tls = "1", tls_sni = p.sni,
			tls_insecure = (p.allowInsecure == "1" or p.insecure == "1") and "1" or "0",
			tls_alpn = aslist(p.alpn),
			transport = (p.type and p.type ~= "tcp") and p.type or nil }
		if p.type == "grpc" then
			cfg.grpc_servicename = p.serviceName
		elseif p.type == "ws" then
			cfg.ws_host = p.host
			cfg.ws_path = p.path or "/"
			apply_ws_early_data(cfg)
		elseif p.type == "http" then
			cfg.http_host = aslist(p.host)
			cfg.http_path = p.path
		end
		return cfg

	elseif scheme == "hysteria" then
		if not sing_features.with_hysteria then
			log(string.format("Skipping unsupported hysteria node: %s.", tostring(label) or url.hostname))
			log("hysteria (v1) outbound is not supported by this sing-box build.")
			return nil
		end
		return { label = label, type = "hysteria", address = url.hostname, port = url.port,
			hysteria_protocol = p.protocol or "udp",
			hysteria_auth_type = p.auth and "string" or nil,
			hysteria_auth_payload = p.auth,
			hysteria_obfs_password = p.obfsParam,
			hysteria_down_mbps = p.downmbps,
			hysteria_up_mbps = p.upmbps,
			tls = "1",
			tls_insecure = (p.insecure == "true" or p.insecure == "1") and "1" or "0",
			tls_sni = p.peer,
			tls_alpn = aslist(p.alpn) }

	elseif scheme == "hysteria2" or scheme == "hy2" then
		if not sing_features.with_quic then
			return skip_no_quic("hysteria2", label, url.hostname)
		end
		local password
		if url.username then
			password = hp.urldecode(url.username .. (url.password and (":" .. url.password) or ""))
		end
		return { label = label, type = "hysteria2", address = url.hostname, port = url.port,
			password = password,
			hysteria_obfs_type = p.obfs,
			hysteria_obfs_password = p["obfs-password"],
			tls = "1", tls_sni = p.sni,
			tls_insecure = (p.insecure == "1") and "1" or "0",
			tls_alpn = aslist(p.alpn) }

	elseif scheme == "tuic" then
		if not sing_features.with_quic then
			return skip_no_quic("tuic", label, url.hostname)
		end
		return { label = label, type = "tuic", address = url.hostname, port = url.port,
			uuid = hp.urldecode(url.username),
			password = url.password and hp.urldecode(url.password) or nil,
			tls = "1", tls_sni = p.sni, tls_alpn = aslist(p.alpn),
			tls_insecure = (p.allowInsecure == "1" or p.insecure == "1") and "1" or "0",
			tuic_congestion_control = p.congestion_control,
			tuic_udp_relay_mode = p.udp_relay_mode,
			tuic_enable_zero_rtt = (p.zero_rtt_handshake == "1") and "1" or "0" }

	elseif scheme == "vless" then
		-- https://github.com/XTLS/XTLS-core/discussions/716
		if p.type == "kcp" then
			log(string.format("Skipping unsupported vless node: %s.", tostring(label) or url.hostname))
			return nil
		elseif p.type == "quic" and ((p.quicSecurity and p.quicSecurity ~= "none") or not sing_features.with_quic) then
			log(string.format("Skipping unsupported vless node: %s.", tostring(label) or url.hostname))
			if not sing_features.with_quic then log("Please rebuild sing-box with QUIC support!") end
			return nil
		end
		local sec = p.security
		local has_tls = (sec == "tls" or sec == "xtls" or sec == "reality")
		local cfg = { label = label, type = "vless", address = url.hostname, port = url.port,
			uuid = hp.urldecode(url.username),
			transport = (p.type and p.type ~= "tcp") and p.type or nil,
			tls = has_tls and "1" or "0",
			tls_sni = p.sni, tls_alpn = aslist(p.alpn),
			tls_reality = (sec == "reality") and "1" or "0",
			tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
			tls_utls = (sing_features.with_utls and not isEmpty(p.fp)) and p.fp or nil,
			vless_flow = has_tls and p.flow or nil,
			packet_encoding = packet_encoding }
		if p.type == "grpc" then
			cfg.grpc_servicename = p.serviceName
		elseif p.type == "http" or (p.type == "tcp" and p.headerType == "http") then
			cfg.http_host = aslist(p.host)
			cfg.http_path = p.path
		elseif p.type == "httpupgrade" then
			cfg.httpupgrade_host = p.host
			cfg.http_path = p.path
		elseif p.type == "ws" then
			cfg.ws_host = p.host
			cfg.ws_path = p.path or "/"
			apply_ws_early_data(cfg)
		end
		return cfg

	elseif scheme == "ss" then
		-- SIP002 https://shadowsocks.org/guide/sip002.html
		-- Shadowrocket may base64-encode the whole "method:pass@host:port"
		-- portion before the fragment; decode it first (only when there is no
		-- "@" and the body is pure base64, to avoid corrupting plaintext URIs).
		local body, frag = rest, nil
		local hashpos = rest:find("#", 1, true)
		if hashpos then body, frag = rest:sub(1, hashpos - 1), rest:sub(hashpos + 1) end
		if body and not body:find("@", 1, true) and body:match("^[A-Za-z0-9%+%/_%=%-]+$") then
			local dec = hp.decodeBase64Str(body)
			if dec and dec:find("@", 1, true) then
				rest = dec .. (frag and ("#" .. frag) or "")
			end
		end
		local ssurl = hp.parseURL("http://" .. rest)
		if not ssurl then return nil end
		local ssp = ssurl.searchParams or {}
		local method, pass
		if ssurl.username and ssurl.password then
			-- User info encoded with URIComponent.
			method = ssurl.username
			pass = hp.urldecode(ssurl.password)
		elseif ssurl.username then
			-- User info encoded with base64.
			local d = hp.decodeBase64Str(hp.urldecode(ssurl.username))
			if d then method, pass = d:match("^([^:]+):(.*)$") end
		end
		local ssplugin, sspluginopts
		if ssp.plugin and ssp.plugin ~= "" then
			local pname, popts = ssp.plugin:match("^([^;]+);?(.*)$")
			if pname == "simple-obfs" then pname = "obfs-local" end
			ssplugin = pname
			sspluginopts = not isEmpty(popts) and popts or nil
		end
		if method and ssurl.hostname and ssurl.port then
			local sslabel = frag and hp.urldecode(frag) or label
			return { label = sslabel, type = "shadowsocks", address = ssurl.hostname,
				port = ssurl.port, shadowsocks_encrypt_method = method, password = pass,
				shadowsocks_plugin = ssplugin, shadowsocks_plugin_opts = sspluginopts }
		end
		return nil
	end

	return nil
end

local node_cache, node_result = {}, {}

-- Prune gone node names out of a urltest list UCI option; persists the cleaned
-- list and returns (kept count, whether anything was removed).
local function prune_urltest_list(opt)
	local list = uci:get(CFG, UCIMAIN, opt) or {}
	if type(list) ~= "table" then list = { list } end
	local kept, changed = {}, false
	for _, v in ipairs(list) do
		if uci:get_all(CFG, v) then
			kept[#kept + 1] = v
		else
			changed = true
			log("Node " .. tostring(v) .. " is gone, removing from urltest list.")
		end
	end
	if changed then
		if #kept > 0 then uci:set(CFG, UCIMAIN, opt, kept) else uci:delete(CFG, UCIMAIN, opt) end
		uci:commit(CFG)
	end
	return #kept, changed
end

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
				if ok and type(j) == "table" then
					-- SIP008: {"servers":[...]} or a bare array [...].
					local srvs = (type(j.servers) == "table") and j.servers
						or (j[1] ~= nil and j) or nil
					if srvs then
						nodes = {}
						for _, s in ipairs(srvs) do
							push(nodes, { nodetype = "sip008", remarks = s.remarks, server = s.server,
								server_port = s.server_port, method = s.method, password = s.password,
								plugin = s.plugin, plugin_opts = s.plugin_opts })
						end
					end
				end
				if not nodes then
					local dec = hp.decodeBase64Str(res)
					if not isEmpty(dec) then res = dec end
					nodes = hp.split(res, "[\r\n]+")
				end

				local count = 0
				for _, n in ipairs(nodes) do
					if not isEmpty(n) then
						local cfg = parse_uri(n)
						if not isEmpty(cfg) then
							local lbl = cfg.label
							cfg.label = nil
							local confHash = hp.md5(hp.encode_json(cfg))
							local nameHash = hp.md5(lbl)
							cfg.label = lbl
							if filter_check(lbl) then
								log("Skipping blacklisted node: " .. tostring(lbl))
							elseif node_cache[groupHash][confHash] or node_cache[groupHash][nameHash] then
								log("Skipping duplicate node: " .. tostring(lbl))
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
				local n, changed = prune_urltest_list("main_urltest_nodes")
				if changed then need_restart = true end
				if n == 0 then
					uci:set(CFG, UCIMAIN, "main_node", first)
					uci:commit(CFG)
					need_restart = true
					log("Main node is gone, switching to the first node.")
				end
			elseif not uci:get_all(CFG, main_node) then
				uci:set(CFG, UCIMAIN, "main_node", first)
				uci:commit(CFG)
				need_restart = true
				log("Main node is gone, switching to the first node.")
			end
			if not isEmpty(main_udp_node) and main_udp_node ~= "same" then
				if main_udp_node == "urltest" then
					local n, changed = prune_urltest_list("main_udp_urltest_nodes")
					if changed then need_restart = true end
					if n == 0 then
						uci:set(CFG, UCIMAIN, "main_udp_node", first)
						uci:commit(CFG)
						need_restart = true
						log("Main UDP node is gone, switching to the first node.")
					end
				elseif not uci:get_all(CFG, main_udp_node) then
					uci:set(CFG, UCIMAIN, "main_udp_node", first)
					uci:commit(CFG)
					need_restart = true
					log("Main UDP node is gone, switching to the first node.")
				end
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
