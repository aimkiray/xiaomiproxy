#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy manual node importer. Reads share links (ss/vmess/vless/trojan/
-- hysteria2/anytls/socks/http/sip008 single-entry, ...) from argv or stdin
-- (one per line), parses them via subscription_parser.lua and upserts UCI
-- "node" sections into /etc/config/homeproxy.
--
-- Manual nodes intentionally carry NO grouphash: update_subscriptions.lua
-- only garbage-collects nodes that belong to a fetched subscription group,
-- so user-added nodes survive every subscription update.
--
-- Output: a single JSON line {"ok":true,"added":[labels],"skipped":[lines]}.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp        = require("homeproxy")
local sharelink = require("subscription_parser")
local uci       = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"
local UCINODE = "node"

uci:load(CFG)

-- Reuse the subscription feature cache when present (written by
-- update_subscriptions.lua, keyed by binary signature).  Absent a cache,
-- assume the feature set of an official sing-box release build; a node the
-- installed binary cannot actually load is still caught by the config check
-- on the next generate/start.
local function detect_features()
	local raw = hp.readfile(hp.RUN_DIR .. "/singbox-features.json")
	if raw then
		local data = hp.decode_json(raw)
		local f = data and data.features
		if type(f) == "table"
			and type(f.with_quic) == "boolean"
			and type(f.with_utls) == "boolean"
			and type(f.with_hysteria) == "boolean" then
			return f
		end
	end
	return { with_quic = true, with_utls = true, with_hysteria = false }
end

local parser_opts = {
	log = function() end,
	features = detect_features(),
	packet_encoding = uci:get(CFG, "subscription", "packet_encoding") or "xudp",
}
local allow_insecure = uci:get(CFG, "subscription", "allow_insecure")

local input
if arg and arg[1] then
	input = table.concat(arg, "\n")
else
	input = io.read("*a") or ""
end

local added, skipped = {}, {}
for line in input:gmatch("[^\r\n]+") do
	line = hp.trim(line)
	if line ~= "" then
		local pok, cfg = pcall(sharelink.parse_uri, hp, parser_opts, line)
		if not pok then cfg = nil end
		if cfg and not hp.isEmpty(cfg) then
			local label = cfg.label
			if hp.isEmpty(label) then
				label = tostring(cfg.address) .. ":" .. tostring(cfg.port)
				cfg.label = label
			end
			if cfg.tls == "1" and allow_insecure == "1" then
				cfg.tls_insecure = "1"
			end
			-- Same naming as `homeproxy add` (md5(label)): manual nodes share
			-- one namespace regardless of which command created them, and can
			-- never collide with subscription nodes (md5(grouphash|label)).
			-- Re-importing the same label updates the section in place.
			local name = hp.md5(label)
			local old = uci:get_all(CFG, name)
			if old and old[".type"] ~= UCINODE then
				skipped[#skipped + 1] = line
			else
				if old then
					for k in pairs(old) do
						if k:sub(1, 1) ~= "." then uci:delete(CFG, name, k) end
					end
				end
				uci:set(CFG, name, UCINODE)
				for k, v in pairs(cfg) do
					uci:set(CFG, name, k, v)
				end
				added[#added + 1] = label
			end
		else
			skipped[#skipped + 1] = line
		end
	end
end

if #added > 0 then
	uci:commit(CFG)
end

io.write(hp.encode_json({ ok = true, added = added, skipped = skipped }) .. "\n")
