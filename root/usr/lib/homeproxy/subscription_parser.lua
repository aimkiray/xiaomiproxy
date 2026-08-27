-- SPDX-License-Identifier: GPL-2.0-only
-- Pure subscription parsing helpers for Lua 5.1.
-- The caller supplies runtime dependencies and feature flags so this module
-- remains independent from UCI, service control, and logging backends.

local M = {}

local function is_empty(hp, v) return hp.isEmpty(v) end

local function uridecode_component(s)
	if not s then return nil end
	return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

local function aslist(hp, v)
	if is_empty(hp, v) then return nil end
	if type(v) == "table" then return v end
	local t = {}
	for part in tostring(v):gmatch("[^,]+") do t[#t + 1] = part end
	return #t > 0 and t or nil
end

-- Consistent boolean flag parsing (M8): real-world links serialise booleans
-- as "1", "true", or true.  Use this everywhere instead of inconsistent per-
-- scheme checks.
local function flag(v) return v == "1" or v == "true" or v == true end

local function apply_ws_early_data(cfg)
	if not cfg.ws_path then return end
	local path, ed = cfg.ws_path:match("^(.-)%?ed=(.+)$")
	if path and ed then
		cfg.ws_path = path
		cfg.websocket_early_data = ed
		cfg.websocket_early_data_header = "Sec-WebSocket-Protocol"
	end
end

local function parse_share_url(hp, scheme, rest)
	local url = hp.parseURL("http://" .. rest)
	if not url then return nil end
	-- Stop at '/' so authority matches what parseURL sees (H6: URIs with a
	-- path before the query would otherwise fail port detection and fall back
	-- to the scheme default, connecting to the wrong port).
	local authority = rest:match("^([^?#/]*)") or ""
	local has_port = authority:match("%]:%d+$") or authority:match("[^:]:%d+$")
	if not has_port then
		local defaults = {
			http = "80", https = "443", socks = "1080", socks4 = "1080",
			socks4a = "1080", socks5 = "1080", socks5h = "1080",
			anytls = "443", hysteria = "443", hysteria2 = "443", hy2 = "443",
			trojan = "443", tuic = "443", vless = "443"
		}
		-- parseURL sees a synthetic http authority. SIP002 still requires an
		-- explicit port, so ss intentionally gets no implicit default here.
		url.port = defaults[scheme]
	end
	return url
end

local function normalize_node(hp, cfg)
	if type(cfg) ~= "table" or is_empty(hp, cfg.address) or is_empty(hp, cfg.port) then return nil end
	if cfg.type == "vmess" and is_empty(hp, cfg.uuid) then return nil end
	cfg.address = tostring(cfg.address):gsub("[%[%]]", "")
	local valid_host = hp.validation("ip4addr", cfg.address)
		or hp.validation("ip6addr", cfg.address)
		or hp.validation("hostname", cfg.address)
	if not valid_host or not hp.validation("port", tostring(cfg.port)) then return nil end
	if is_empty(hp, cfg.label) then
		local addr = hp.validation("ip6addr", cfg.address) and ("[" .. cfg.address .. "]") or cfg.address
		cfg.label = addr .. ":" .. tostring(cfg.port)
	end
	return cfg
end

local function parse_ss(hp, rest)
	local body, frag = rest, nil
	local hashpos = rest:find("#", 1, true)
	if hashpos then body, frag = rest:sub(1, hashpos - 1), rest:sub(hashpos + 1) end
	-- Shadowrocket whole-body form. Decode only an unambiguous Base64 body.
	if body and not body:find("@", 1, true) and body:match("^[A-Za-z0-9%+%/_%=%-]+$") then
		local dec = hp.decodeBase64Str(body)
		if dec and dec:find("@", 1, true) then
			local dh = dec:find("#", 1, true)
			if dh then
				body = dec:sub(1, dh - 1)
				if not frag then frag = dec:sub(dh + 1) end
			else
				body = dec
			end
		end
	end
	local ssuserinfo, hostpart = body:match("^(.*)@([^@]*)$")
	if not ssuserinfo then return nil end
	local ssurl = parse_share_url(hp, "ss", hostpart)
	if not ssurl then return nil end
	local ssp = ssurl.searchParams or {}
	local method, pass = ssuserinfo:match("^([^:]+):(.*)$")
	if method then
		pass = uridecode_component(pass)
	else
		local d = hp.decodeBase64Str(uridecode_component(ssuserinfo))
		if d then method, pass = d:match("^([^:]+):(.*)$") end
	end
	local ssplugin, sspluginopts
	if ssp.plugin and ssp.plugin ~= "" then
		local pname, popts = ssp.plugin:match("^([^;]+);?(.*)$")
		if pname == "simple-obfs" then pname = "obfs-local" end
		ssplugin = pname
		sspluginopts = not is_empty(hp, popts) and popts or nil
	end
	if not method or not ssurl.hostname or not ssurl.port then return nil end
	local sslabel = frag and hp.urldecode(frag) or nil
	return { label = sslabel, type = "shadowsocks", address = ssurl.hostname,
		port = ssurl.port, shadowsocks_encrypt_method = method, password = pass,
		shadowsocks_plugin = ssplugin, shadowsocks_plugin_opts = sspluginopts }
end

local function parse_uri_raw(hp, opts, uri)
	local log = opts.log or function() end
	local features = opts.features or {}
	local packet_encoding = opts.packet_encoding or "xudp"
	local function skip_quic(scheme, label, host)
		log(string.format("Skipping unsupported %s node: %s.", scheme, tostring(label or host)))
		log("Please rebuild sing-box with QUIC support!")
		return nil
	end
	if type(uri) == "table" then
		if uri.nodetype ~= "sip008" then return nil end
		return { label = uri.remarks, type = "shadowsocks", address = uri.server,
			port = uri.server_port and tostring(uri.server_port),
			shadowsocks_encrypt_method = uri.method, password = uri.password,
			shadowsocks_plugin = uri.plugin, shadowsocks_plugin_opts = uri.plugin_opts }
	end
	if type(uri) ~= "string" then return nil end
	uri = uri:gsub("^%s+", ""):gsub("%s+$", "")
	local scheme, rest = uri:match("^(%w[%w+.-]*)://(.*)$")
	if not scheme then return nil end
	scheme = scheme:lower()
	if scheme == "ss" then return parse_ss(hp, rest) end
	if scheme == "vmess" then
		if rest:find("&", 1, true) then log("Skipping unsupported vmess format."); return nil end
		-- Strip fragment/query before base64 decode (M7): characters in #tag
		-- that happen to be base64-valid would corrupt the trailing JSON.
		local b64 = rest:match("^([^?#]*)") or rest
		local raw = hp.decodeBase64Str(b64)
		if is_empty(hp, raw) then return nil end
		local ok, j = pcall(hp.decode_json, raw)
		if not ok or type(j) ~= "table" or j.v ~= "2" or is_empty(hp, j.add)
			or is_empty(hp, j.port) or is_empty(hp, j.id) then
			log("Skipping unsupported vmess format."); return nil
		end
		local net = j.net or "tcp"
		local nm = j.ps or j.add
		if net == "kcp" then
			log(string.format("Skipping unsupported vmess node: %s.", tostring(nm))); return nil
		elseif net == "quic" and ((j.type and j.type ~= "none") or j.path or not features.with_quic) then
			log(string.format("Skipping unsupported vmess node: %s.", tostring(nm)))
			if not features.with_quic then log("Please rebuild sing-box with QUIC support!") end
			return nil
		end
		local cfg = { label = j.ps and hp.urldecode(j.ps) or nil, type = "vmess", address = j.add,
			port = tostring(j.port), uuid = j.id, vmess_alterid = tostring(j.aid or 0),
			vmess_encrypt = j.scy or "auto", vmess_global_padding = "1",
			transport = (net ~= "tcp") and net or nil,
			tls = (flag(j.tls)) and "1" or "0",
			tls_sni = j.sni or j.host, tls_alpn = aslist(hp, j.alpn),
			tls_utls = (features.with_utls and not is_empty(hp, j.fp)) and j.fp or nil,
			packet_encoding = packet_encoding }
		if net == "h2" or (net == "tcp" and j.type == "http") then
			cfg.transport, cfg.http_host, cfg.http_path = "http", aslist(hp, j.host), j.path
		elseif net == "grpc" then cfg.grpc_servicename = j.path
		elseif net == "httpupgrade" then cfg.httpupgrade_host, cfg.http_path = j.host, j.path
		elseif net == "ws" then cfg.ws_host, cfg.ws_path = j.host, j.path or "/"; apply_ws_early_data(cfg) end
		return cfg
	end
	local url = parse_share_url(hp, scheme, rest)
	if not url then return nil end
	local p, label = url.searchParams or {}, url.hash and hp.urldecode(url.hash) or nil
	if scheme == "anytls" then
		return { label = label, type = "anytls", address = url.hostname, port = url.port,
			password = uridecode_component(url.username), tls = "1", tls_sni = p.sni,
			tls_alpn = aslist(hp, p.alpn), tls_insecure = flag(p.insecure) and "1" or "0",
			tls_reality = (p.security == "reality") and "1" or "0",
			tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
			tls_utls = (features.with_utls and not is_empty(hp, p.fp)) and p.fp or nil }
	elseif scheme == "http" or scheme == "https" then
		return { label = label, type = "http", address = url.hostname, port = url.port,
			username = url.username and uridecode_component(url.username) or nil,
			password = url.password and uridecode_component(url.password) or nil,
			tls = (scheme == "https") and "1" or "0" }
	elseif scheme == "socks" or scheme == "socks4" or scheme == "socks4a" or scheme == "socks5" or scheme == "socks5h" then
		return { label = label, type = "socks", socks_version = scheme:match("4") and "4" or "5",
			address = url.hostname, port = url.port, username = url.username and uridecode_component(url.username) or nil,
			password = url.password and uridecode_component(url.password) or nil }
	elseif scheme == "trojan" then
		local cfg = { label = label, type = "trojan", address = url.hostname, port = url.port,
			password = uridecode_component(url.username), tls = "1", tls_sni = p.sni,
			tls_insecure = (flag(p.allowInsecure) or flag(p.insecure)) and "1" or "0",
			tls_alpn = aslist(hp, p.alpn), transport = (p.type and p.type ~= "tcp") and p.type or nil }
		if p.type == "grpc" then cfg.grpc_servicename = p.serviceName
		elseif p.type == "ws" then cfg.ws_host, cfg.ws_path = p.host, p.path or "/"; apply_ws_early_data(cfg)
		elseif p.type == "http" then cfg.http_host, cfg.http_path = aslist(hp, p.host), p.path end
		return cfg
	elseif scheme == "hysteria" then
		if not features.with_hysteria or (p.protocol and p.protocol ~= "udp") then
			log(string.format("Skipping unsupported hysteria node: %s.", tostring(label or url.hostname)))
			if not features.with_hysteria then log("hysteria (v1) outbound is not supported by this sing-box build.")
			else log("hysteria protocols other than udp are not supported by this port.") end
			return nil
		end
		return { label = label, type = "hysteria", address = url.hostname, port = url.port,
			hysteria_protocol = p.protocol or "udp", hysteria_auth_type = p.auth and "string" or nil,
			hysteria_auth_payload = p.auth, hysteria_obfs_password = p.obfsParam,
			hysteria_down_mbps = p.downmbps, hysteria_up_mbps = p.upmbps, tls = "1",
			tls_insecure = flag(p.insecure) and "1" or "0",
			tls_sni = p.peer, tls_alpn = aslist(hp, p.alpn) }
	elseif scheme == "hysteria2" or scheme == "hy2" then
		if not features.with_quic then return skip_quic("hysteria2", label, url.hostname) end
		return { label = label, type = "hysteria2", address = url.hostname, port = url.port,
			password = url.username and uridecode_component(url.username .. (url.password and (":" .. url.password) or "")) or nil,
			hysteria_obfs_type = p.obfs, hysteria_obfs_password = p["obfs-password"], tls = "1",
			tls_sni = p.sni, tls_insecure = flag(p.insecure) and "1" or "0", tls_alpn = aslist(hp, p.alpn) }
	elseif scheme == "tuic" then
		if not features.with_quic then return skip_quic("tuic", label, url.hostname) end
		return { label = label, type = "tuic", address = url.hostname, port = url.port,
			uuid = uridecode_component(url.username), password = url.password and uridecode_component(url.password) or nil,
			tls = "1", tls_sni = p.sni, tls_alpn = aslist(hp, p.alpn),
			tls_insecure = (flag(p.allowInsecure) or flag(p.insecure)) and "1" or "0",
			tuic_congestion_control = p.congestion_control, tuic_udp_relay_mode = p.udp_relay_mode,
			tuic_enable_zero_rtt = flag(p.zero_rtt_handshake) and "1" or "0" }
	elseif scheme == "vless" then
		if p.type == "kcp" then log(string.format("Skipping unsupported vless node: %s.", tostring(label or url.hostname))); return nil end
		if p.type == "quic" and ((p.quicSecurity and p.quicSecurity ~= "none") or not features.with_quic) then
			log(string.format("Skipping unsupported vless node: %s.", tostring(label or url.hostname)))
			if not features.with_quic then log("Please rebuild sing-box with QUIC support!") end
			return nil
		end
		local sec, has_tls = p.security, (p.security == "tls" or p.security == "xtls" or p.security == "reality")
		local cfg = { label = label, type = "vless", address = url.hostname, port = url.port, uuid = uridecode_component(url.username),
			transport = (p.type and p.type ~= "tcp") and p.type or nil, tls = has_tls and "1" or "0", tls_sni = p.sni,
			tls_alpn = aslist(hp, p.alpn), tls_reality = (sec == "reality") and "1" or "0",
			tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
			tls_utls = (features.with_utls and not is_empty(hp, p.fp)) and p.fp or nil,
			vless_flow = (sec == "tls" or sec == "reality") and p.flow or nil, packet_encoding = packet_encoding }
		if p.type == "grpc" then cfg.grpc_servicename = p.serviceName
		elseif p.type == "http" or (p.type == "tcp" and p.headerType == "http") then cfg.http_host, cfg.http_path = aslist(hp, p.host), p.path
		elseif p.type == "httpupgrade" then cfg.httpupgrade_host, cfg.http_path = p.host, p.path
		elseif p.type == "ws" then cfg.ws_host, cfg.ws_path = p.host, p.path or "/"; apply_ws_early_data(cfg) end
		return cfg
	end
	return nil
end

function M.parse_uri(hp, opts, uri)
	return normalize_node(hp, parse_uri_raw(hp, opts or {}, uri))
end

function M.decode_subscription_body(hp, res)
	local function looks_like(s)
		if not s then return false end
		for line in s:gmatch("[^\r\n]+") do
			if line:match("^%s*[%a][%w+%.%-]*://") then return true end
		end
		return false
	end
	local plain = hp.trim(res)
	if is_empty(hp, plain) or looks_like(plain) then return plain end
	local decoded = hp.decodeBase64Str(plain)
	return looks_like(decoded) and decoded or plain
end

function M.filter_check(hp, name, mode, keywords)
	if is_empty(hp, name) or mode == "disabled" then return false end
	if type(keywords) ~= "table" or #keywords == 0 then return false end
	local matched = false
	for _, kw in ipairs(keywords) do
		for term in tostring(kw):gmatch("[^|]+") do
			if name:find(term, 1, true) then matched = true; break end
		end
		if matched then break end
	end
	if mode == "whitelist" then return not matched end
	return matched
end

return M
