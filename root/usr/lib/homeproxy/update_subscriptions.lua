#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy subscription updater (Lua port of update_subscriptions.uc).
-- Fetches subscription URLs, parses common share-link schemes (ss, vmess,
-- vless, trojan, hysteria, hysteria2, http(s), socks, tuic, anytls) and
-- SIP008, then writes nodes to /etc/config/homeproxy. Protocol parsing is
-- delegated to subscription_parser.lua. Requires: lua, uci binding, luci.json,
-- md5sum, wget/curl.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp        = require("homeproxy")
local sharelink = require("subscription_parser")
local uci       = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"
uci:load(CFG)

local UCIMAIN = "config"
local UCINODE = "node"
local UCISUB  = "subscription"

local function isEmpty(v) return hp.isEmpty(v) end
local function push(t, v) t[#t + 1] = v end
local function log(msg) hp.log(msg, "SUBSCRIBE") end

-- Concurrency lock: prevent cron + manual update from clobbering each other.
-- mkdir() is the only atomic check-and-create primitive available here --
-- the old timestamp file could be written simultaneously by two updaters
-- (check passes for both, both write, both proceed).  Stale detection uses
-- the directory's mtime: locks older than MAX_LOCK_AGE are presumed dead
-- (SIGKILL, power loss) and reclaimed.  RUN_DIR is tmpfs so a stale lock
-- can never survive a reboot.
-- Shared with add_nodes.lua: serializes all writers to the homeproxy UCI
-- package, not just subscription updates.
local lock_dir = hp.RUN_DIR .. "/uci-write.lock.d"
local MAX_LOCK_AGE = 120  -- seconds
hp.mkdir_p(hp.RUN_DIR)
local function acquire_lock()
	if os.execute("mkdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null") == 0 then
		return true
	end
	local h = io.popen("stat -c %Y " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
	local mt = h and tonumber(hp.trim(h:read("*a") or "")) or nil
	if h then h:close() end
	if mt == nil then
		-- Cannot age it; assume a live updater owns it.
		return false
	end
	local age = os.time() - mt
	if age >= 0 and age < MAX_LOCK_AGE then
		log("Another subscription update is running (started " .. age .. "s ago), aborting.")
		return false
	end
	-- Stale (or timestamp in the future after a clock step): reclaim once.
	os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
	return os.execute("mkdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null") == 0
end
local function release_lock()
	os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
end
if not acquire_lock() then
	-- Nonzero: a skipped update is NOT a success -- callers (web/CLI) must
	-- not treat it as "nodes refreshed" (e.g. by restarting the service).
	os.exit(3)
end

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
	return sharelink.filter_check(hp, name, filter_mode, filter_keywords)
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

local function singbox_signature(bin)
	-- The version output invalidates the cache after upgrades.  If the binary
	-- cannot answer `version`, the path still gives a deterministic fallback.
	local p = io.popen(hp.shellQuote(bin) .. " version 2>/dev/null")
	local version = p and hp.trim(p:read("*a") or "") or ""
	if p then p:close() end
	return bin .. "\n" .. (version ~= "" and version or "unknown")
end

local function read_feature_cache(signature)
	local raw = hp.readfile(hp.RUN_DIR .. "/singbox-features.json")
	if isEmpty(raw) then return nil end
	local ok, data = pcall(hp.decode_json, raw)
	if not ok or type(data) ~= "table" or data.signature ~= signature
		or type(data.features) ~= "table" then
		return nil
	end
	-- Reject corrupted cache entries: feature flags must be booleans.
	local f = data.features
	if type(f.with_quic) ~= "boolean" or type(f.with_utls) ~= "boolean"
		or type(f.with_hysteria) ~= "boolean" then
		return nil
	end
	return f
end

local function detect_features()
	local feat = { with_quic = false, with_utls = false, with_hysteria = false }
	local bin = singbox_bin()
	local signature = singbox_signature(bin)
	local cached = read_feature_cache(signature)
	if cached then
		log("Using cached sing-box feature detection.")
		return cached
	end
	local tmp = os.tmpname()
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
	-- Do not cache when the binary could not even report its version: an
	-- all-false probe caused by a missing/broken sing-box would otherwise be
	-- served from cache forever after the binary is fixed.
	if signature:match("\nunknown$") then
		log("sing-box binary unresponsive; feature cache skipped.")
		return feat
	end
	local cache = hp.RUN_DIR .. "/singbox-features.json"
	-- Keep the temporary cache beside the final file so rename stays atomic
	-- even when /tmp and RUN_DIR are different mounts.
	local temp_cache = cache .. ".tmp." .. tostring(os.time()) .. "." .. tostring(math.random(100000, 999999))
	if hp.writefile(temp_cache, hp.encode_json({ signature = signature, features = feat })) then
		if not os.rename(temp_cache, cache) then os.remove(temp_cache) end
	else
		os.remove(temp_cache)
	end
	log(string.format("sing-box features: quic=%s utls=%s hysteria=%s",
		tostring(feat.with_quic), tostring(feat.with_utls), tostring(feat.with_hysteria)))
	return feat
end

-- Feature detection writes a cache under RUN_DIR before main() starts.
hp.mkdir_p(hp.RUN_DIR)
local sf_ok, sf = pcall(detect_features)
-- Fail closed when feature probing itself fails.  Assuming QUIC/uTLS exists
-- can write nodes that the installed sing-box cannot load; an unavailable
-- optional feature should only skip those nodes, not break the service.
local sing_features = (sf_ok and sf) or { with_quic = false, with_utls = false, with_hysteria = false }

-- Bind the subscription_parser module with runtime dependencies.
local parser_opts = { log = log, features = sing_features, packet_encoding = packet_encoding }
local function parse_uri(uri)
	return sharelink.parse_uri(hp, parser_opts, uri)
end
local function decode_subscription_body(res)
	return sharelink.decode_subscription_body(hp, res)
end

local node_cache, node_result = {}, {}

-- Loopback/unspecified/link-local subscription hosts are never legitimate:
-- the router would fetch them blind (SSRF surface), and URLs can also be
-- written via UCI directly, bypassing the web API's validation.
local function is_local_url(url)
	local u = hp.parseURL(url)
	local h = u and u.hostname or nil
	if not h then return false end
	h = h:gsub("^%[(.*)%]$", "%1")
	return h == "localhost"
		or h:match("^127%.") or h:match("^169%.254%.")
		or h == "0.0.0.0" or h == "::" or h == "::1"
		or h:lower():match("^fe80:") or h:lower():match("^[fc][cd]%x*:")
end

-- Prune gone node names out of a urltest list UCI option; returns
-- (kept count, whether anything was removed).  Does NOT commit — the caller
-- folds the change into the final atomic commit.
local function prune_urltest_list(opt)
	local list = uci:get(CFG, UCIMAIN, opt) or {}
	if type(list) ~= "table" then list = { list } end
	local kept, changed = {}, false
	for _, v in ipairs(list) do
		local s = uci:get_all(CFG, v)
		if s and s[".type"] == UCINODE then
			kept[#kept + 1] = v
		else
			changed = true
			log("Node " .. tostring(v) .. " is gone, removing from urltest list.")
		end
	end
	if changed then
		if #kept > 0 then uci:set(CFG, UCIMAIN, opt, kept) else uci:delete(CFG, UCIMAIN, opt) end
	end
	return #kept, changed
end

-- Checked commit: aborts hard on persistence failure (H5) instead of silently
-- proceeding with a divergent in-memory/disk state.
local function commit_uci()
	if not uci:commit(CFG) then
		error("uci:commit failed — filesystem may be read-only or full")
	end
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

	for _, configured_url in ipairs(subscription_urls) do
			configured_url = hp.trim(configured_url)
			if isEmpty(configured_url) then
			elseif not configured_url:match("^https?://") and not configured_url:match("^sip008://") then
				log("Skipping invalid URL: " .. tostring(configured_url))
			elseif is_local_url(configured_url) then
				log("Skipping loopback/link-local URL (SSRF guard): " .. tostring(configured_url))
			else
				-- A fragment identifies a local subscription label, not the remote
				-- resource.  Do not let it create a separate group or reach curl.
				local url = configured_url:gsub("#.*$", "")
				local groupHash = hp.md5(url)
				node_cache[groupHash] = {}
				local group_nodes = {}

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
					-- Only recognize SIP008 when its first entry has the required
					-- server/method fields; unrelated JSON must fall through.
					local candidate = (type(j.servers) == "table") and j.servers
						or (j[1] ~= nil and j) or nil
					-- candidate[1] must be a table: indexing a string/number
					-- element (malformed JSON) would crash the whole update.
					local srvs = candidate and type(candidate[1]) == "table"
						and candidate[1].server and candidate[1].method and candidate or nil
					if srvs then
						nodes = {}
						for _, s in ipairs(srvs) do
							-- Elements past [1] are unguarded: a number/boolean
							-- entry would crash the whole update on s.remarks.
							if type(s) == "table" and s.server and s.method then
								push(nodes, { nodetype = "sip008",
									remarks = (type(s.remarks) == "string") and s.remarks or nil,
									server = s.server, server_port = s.server_port,
									method = s.method, password = s.password,
									plugin = s.plugin, plugin_opts = s.plugin_opts })
							end
						end
					end
				end
				if not nodes then
					res = decode_subscription_body(res)
					nodes = hp.split(res, "[\r\n]+")
				end

				local count = 0
				for _, n in ipairs(nodes) do
					if not isEmpty(n) then
						-- pcall per entry: one malformed link must not abort
						-- the entire subscription update.
						local pok, cfg = pcall(parse_uri, n)
						if not pok then
							log("Node parse error (skipped): " .. tostring(cfg))
							cfg = nil
						end
						if not isEmpty(cfg) then
							local lbl = cfg.label
							cfg.label = nil
							local confHash = hp.md5(hp.encode_json(cfg))
							-- Use namespaced hash to match the section name scheme (C1 fix).
							-- "|" separator: a NUL byte cannot survive the shell pipeline
							-- inside hp.md5 (arg lists are NUL-terminated).
							local nameHash = lbl and hp.md5(groupHash .. "|" .. lbl) or nil
							cfg.label = lbl
							if filter_check(lbl) then
								log("Skipping filtered node: " .. tostring(lbl))
							elseif node_cache[groupHash][confHash] or (nameHash and node_cache[groupHash][nameHash]) then
								log("Skipping duplicate node: " .. tostring(lbl))
							else
								if cfg.tls == "1" and allow_insecure == "1" then
									cfg.tls_insecure = "1"
								end
								if cfg.type == "vless" or cfg.type == "vmess" then
									cfg.packet_encoding = packet_encoding
								end
								cfg.grouphash = groupHash
								push(group_nodes, cfg)
								node_cache[groupHash][confHash] = cfg
								if nameHash then node_cache[groupHash][nameHash] = cfg end
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
				if count > 0 then push(node_result, group_nodes) end
			end
		end
	end

	if isEmpty(node_result) or #node_result == 0 then
		log("Failed to update subscriptions: no valid node found.")
		if via_proxy ~= "1" then
			log("Starting service...")
			os.execute("/etc/init.d/homeproxy start >/dev/null 2>&1")
		end
		-- Failure must reach the caller: previously this returned normally
		-- so the web API reported a successful update after every fetch died.
		return false
	end

	-- remove stale nodes + update existing.
	-- Collect deletions first: deleting a section inside uci:foreach mutates
	-- the very list being iterated.
	local added, removed, nodes_changed = 0, 0, false
	local to_delete = {}
	uci:foreach(CFG, UCINODE, function(cfg)
		if not cfg.grouphash then return end -- user-created node
		local gh = cfg.grouphash
		-- An empty cache means this subscription failed or returned no usable
		-- nodes.  Preserve its old nodes to avoid destructive transient updates.
		if node_cache[gh] and next(node_cache[gh]) == nil then
			return
		elseif not node_cache[gh] or not node_cache[gh][cfg[".name"]] then
			to_delete[#to_delete + 1] = cfg[".name"]
			log("Removing node: " .. tostring(cfg.label))
		else
			local newcfg = node_cache[gh][cfg[".name"]]
			-- Apply all fields from the new node (handles field additions).
			for k, v in pairs(newcfg) do
				if k:sub(1, 1) ~= "." and k ~= "isExisting" then
					local old = cfg[k]
					local same
					if type(old) == "table" and type(v) == "table" and #old == #v then
						same = true
						for i = 1, #v do if tostring(old[i]) ~= tostring(v[i]) then same = false; break end end
					else
						same = tostring(old) == tostring(v)
					end
					if not same then nodes_changed = true end
					uci:set(CFG, cfg[".name"], k, v)
				end
			end
			-- Delete fields present in the old node but absent from the new.
			for k in pairs(cfg) do
				if k:sub(1, 1) ~= "." and newcfg[k] == nil then
					nodes_changed = true
					uci:delete(CFG, cfg[".name"], k)
				end
			end
			newcfg.isExisting = true
		end
	end)
	for _, sname in ipairs(to_delete) do
		uci:delete(CFG, sname)
		removed = removed + 1
	end

	-- add new nodes
	for _, nodes in ipairs(node_result) do
		for _, node in ipairs(nodes) do
			if not node.isExisting then
				-- Namespace section name by groupHash to prevent cross-subscription
				-- label collisions (C1): two subs with "HK 01" would otherwise
				-- overwrite each other's UCI section every run.
				local nameHash = hp.md5(node.grouphash .. "|" .. tostring(node.label))
				uci:set(CFG, nameHash, "node")
				for k, v in pairs(node) do
					if k ~= "isExisting" then uci:set(CFG, nameHash, k, v) end
				end
				added = added + 1
				log("Adding node: " .. tostring(node.label))
			end
		end
	end

	-- Clean references to nodes just removed: custom-mode routing_node.node /
	-- urltest_nodes pointing at a deleted node would dangle (the generator
	-- used to re-wire the rule onto the previous outbound).
	uci:foreach(CFG, "routing_node", function(s)
		local n = s.node
		if not isEmpty(n) and n ~= "urltest" then
			local sec = uci:get_all(CFG, n)
			if not sec or sec[".type"] ~= UCINODE then
				uci:delete(CFG, s[".name"], "node")
				nodes_changed = true
				log("routing_node " .. tostring(s[".name"]) .. " referenced removed node " .. tostring(n) .. " -- cleared.")
			end
		end
		local l = s.urltest_nodes
		if type(l) == "table" then
			local kept, ch = {}, false
			for _, v in ipairs(l) do
				local sec = uci:get_all(CFG, v)
				if sec and sec[".type"] == UCINODE then kept[#kept + 1] = v else ch = true end
			end
			if ch then
				nodes_changed = true
				if #kept > 0 then uci:set(CFG, s[".name"], "urltest_nodes", kept)
				else uci:delete(CFG, s[".name"], "urltest_nodes") end
			end
		end
	end)

	-- When updating via proxy the service was never stopped, so it must be
	-- restarted whenever the node set actually changed -- previously it was
	-- only restarted when the main node needed repair, so committed nodes
	-- never took effect (H5).
	local need_restart = (via_proxy ~= "1") or added > 0 or removed > 0 or nodes_changed
	-- Prune the urltest member lists UNCONDITIONALLY: stale entries left while
	-- a plain node is active would dangle the moment the user switches to
	-- urltest before the next update run.
	local ut_n, ut_changed = prune_urltest_list("main_urltest_nodes")
	local utu_n, utu_changed = prune_urltest_list("main_udp_urltest_nodes")
	if ut_changed or utu_changed then need_restart = true end
	if not isEmpty(main_node) then
		local first
		uci:foreach(CFG, UCINODE, function(s) first = s[".name"]; return false end)
		if first then
			local function is_node(name)
				local sec = uci:get_all(CFG, name)
				return sec ~= nil and sec[".type"] == UCINODE
			end
			if main_node == "urltest" then
				if ut_n == 0 then
					uci:set(CFG, UCIMAIN, "main_node", first)
					need_restart = true
					log("Main node is gone, switching to the first node.")
				end
			elseif not is_node(main_node) then
				uci:set(CFG, UCIMAIN, "main_node", first)
				need_restart = true
				log("Main node is gone, switching to the first node.")
			end
			if not isEmpty(main_udp_node) and main_udp_node ~= "same" then
				if main_udp_node == "urltest" then
					if utu_n == 0 then
						uci:set(CFG, UCIMAIN, "main_udp_node", first)
						need_restart = true
						log("Main UDP node is gone, switching to the first node.")
					end
				elseif not is_node(main_udp_node) then
					uci:set(CFG, UCIMAIN, "main_udp_node", first)
					need_restart = true
					log("Main UDP node is gone, switching to the first node.")
				end
			end
		else
			uci:set(CFG, UCIMAIN, "main_node", "nil")
			uci:set(CFG, UCIMAIN, "main_udp_node", "nil")
			need_restart = true
			log("No available node, disable tproxy.")
		end
	end

	-- Single atomic commit for all node + main_node + urltest changes (H4).
	commit_uci()

	if need_restart then
		log("Restarting service...")
		os.execute("/etc/init.d/homeproxy restart >/dev/null 2>&1")
	end
	log(string.format("%s nodes added, %s removed. Successfully updated subscriptions.", added, removed))
end

local ok, res = pcall(main)
-- Always release the concurrency lock.
release_lock()
if not ok then
	log("[FATAL ERROR] " .. tostring(res))
	if via_proxy ~= "1" then
		os.execute("/etc/init.d/homeproxy stop >/dev/null 2>&1")
		os.execute("/etc/init.d/homeproxy start >/dev/null 2>&1")
	else
		os.execute("/etc/init.d/homeproxy restart >/dev/null 2>&1")
	end
	os.exit(1)
end
if res == false then
	-- main() already logged the reason and recovered the service.
	os.exit(1)
end
