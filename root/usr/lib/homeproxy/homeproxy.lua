-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy helper library (Lua port of the ucode `homeproxy` module).
-- Designed for OpenWrt/MiWiFi devices without ucode: pure Lua 5.1 +
-- luci.json + the uci Lua binding. No external shell helpers required for
-- core logic (base64/md5/URL parsing implemented in Lua).

local _M = {}

_M.HP_DIR  = "/etc/homeproxy"
_M.RUN_DIR = "/var/run/homeproxy"

-- ---------------------------------------------------------------------------
-- Filesystem helpers
-- ---------------------------------------------------------------------------
function _M.readfile(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

function _M.writefile(path, content)
    local f = io.open(path, "wb")
    if not f then return false end
    f:write(content or "")
    f:close()
    return true
end

function _M.appendfile(path, content)
    local f = io.open(path, "ab")
    if not f then return false end
    f:write(content or "")
    f:close()
    return true
end

function _M.mkdir_p(path)
    os.execute(string.format("mkdir -p %s", _M.shellQuote(path)))
end

-- ---------------------------------------------------------------------------
-- String helpers
-- ---------------------------------------------------------------------------
function _M.trim(s)
    if type(s) ~= "string" then return nil end
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

function _M.isEmpty(res)
    if res == nil or res == false then return true end
    if res == "nil" then return true end
    if res == "" then return true end
    if type(res) == "table" then return next(res) == nil end
    return false
end

function _M.shellQuote(s)
    s = tostring(s or "")
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

function _M.strToBool(str)
    return (str == "1") or nil
end

function _M.strToInt(str)
    if _M.isEmpty(str) then return nil end
    local n = tonumber(tostring(str))
    return n
end

-- The upstream ucode implementation appends "s" so numeric seconds become
-- sing-box duration strings ("300" -> "300s").
function _M.strToTime(str)
    if _M.isEmpty(str) then return nil end
    return tostring(str) .. "s"
end

function _M.split(s, pat)
    if not s then return {} end
    pat = pat or "%s"
    local t = {}
    local first = 1
    local a, b = s:find(pat, first)
    while a do
        t[#t + 1] = s:sub(first, a - 1)
        first = b + 1
        a, b = s:find(pat, first)
    end
    t[#t + 1] = s:sub(first)
    return t
end

-- ---------------------------------------------------------------------------
-- Validation (replaces /sbin/validate_data which may be absent on MiWiFi)
-- ---------------------------------------------------------------------------
local function is_ip4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    for _, v in ipairs({a, b, c, d}) do
        local n = tonumber(v)
        if not n or n < 0 or n > 255 then return false end
    end
    return true
end

local function is_ip6(s)
    if s == "" then return false end
    if s:find("[^0-9a-fA-F:.]") then return false end
    if s:sub(1, 1) == ":" and s:sub(2, 2) ~= ":" then return false end
    if s:sub(-1, -1) == ":" and s:sub(-2, -2) ~= ":" then return false end
    local groups = 0
    local seen_double = false
    for part in s:gmatch("([0-9a-fA-F]*)") do
        if part == "" then
            -- consecutive colons; allow at most one "::"
        else
            if #part > 4 then return false end
            groups = groups + 1
        end
    end
    -- crude: require at least a plausible structure
    if s:find("::") then seen_double = true end
    if not seen_double and groups ~= 8 then return false end
    return true
end

local function is_hostname(s)
    if s == "" then return false end
    if s:match("^[a-zA-Z0-9_]+$") then return true end
    if s:match("^[a-zA-Z0-9_][a-zA-Z0-9_%%%-%.]*[a-zA-Z0-9_]$") and s:match("[^0-9%.]") then
        return true
    end
    return false
end

function _M.validation(datatype, data)
    if not datatype or not data or data == "" then return nil end
    if datatype == "ip4addr" then return is_ip4(data)
    elseif datatype == "ip6addr" then return is_ip6(data)
    elseif datatype == "ipaddr"  then return is_ip4(data) or is_ip6(data)
    elseif datatype == "hostname" then return is_hostname(data)
    elseif datatype == "port" then
        local n = tonumber(data)
        return n ~= nil and n > 0 and n < 65536
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Base64 (pure Lua, standard + URL-safe input)
-- ---------------------------------------------------------------------------
local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64idx = {}
for i = 1, #b64 do b64idx[b64:sub(i, i):byte()] = i - 1 end

function _M.decodeBase64Str(str)
    if _M.isEmpty(str) then return nil end
    str = _M.trim(str):gsub("_", "/"):gsub("-", "+")
    local pad = #str % 4
    if pad > 0 then str = str .. string.rep("=", 4 - pad) end
    local out, val, bits = {}, 0, 0
    for i = 1, #str do
        local c = str:byte(i)
        if c == 61 then break end -- '='
        local v = b64idx[c]
        if v then
            val = val * 64 + v
            bits = bits + 6
            if bits >= 8 then
                bits = bits - 8
                local byte = math.floor(val / 2^bits) % 256
                if math.tointeger then byte = math.tointeger(byte) end
                out[#out + 1] = string.char(byte)
                val = val % 2^bits   -- keep residual bits, keep val bounded
            end
        end
    end
    return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- md5 (shell out to busybox md5sum; small and reliable)
-- ---------------------------------------------------------------------------
function _M.md5(s)
    if s == nil then return nil end
    local h = io.popen("printf %s " .. _M.shellQuote(s) .. " | md5sum 2>/dev/null | cut -d' ' -f1")
    local r = h:read("*l")
    h:close()
    return _M.trim(r)
end

-- ---------------------------------------------------------------------------
-- URL encoding (for subscription labels/params)
-- ---------------------------------------------------------------------------
function _M.urldecode(s)
    if not s then return nil end
    s = s:gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
    return s
end

function _M.urlencode(s)
    if s == nil then return nil end
    s = tostring(s)
    return (s:gsub("([^%w%-_.~])", function(c)
        return string.format("%%%02X", c:byte())
    end))
end

-- ---------------------------------------------------------------------------
-- URL parser (port of the ucode parseURL)
-- ---------------------------------------------------------------------------
function _M.parseURL(url)
    if type(url) ~= "string" then return nil end
    local services = { http = "80", https = "443" }
    local o = { href = url }

    -- fragment
    url = url:gsub("#(.+)$", function(v) o.hash = v; return "" end)
    -- scheme
    url = url:gsub("^([%w][%w%+%.%-]*):", function(v) o.protocol = v; return "" end)
    -- query
    url = url:gsub("%?(.+)$", function(v)
        o.search = v
        o.searchParams = {}
        for k, val in v:gmatch("([^&=]+)=?([^&]*)") do
            o.searchParams[_M.urldecode(k)] = _M.urldecode(val)
        end
        return ""
    end)
    -- authority
    url = url:gsub("^//([^/]*)", function(v)
        v = v:gsub("^([^@]+)@", function(u) o.userinfo = u; return "" end)
        v = v:gsub(":(%d+)$", function(p) o.port = p; return "" end)
        local bare = v:gsub("[%[%]]", "")
        if _M.validation("ip4addr", v) or _M.validation("ip6addr", bare) or _M.validation("hostname", v) then
            o.hostname = v
        end
        return ""
    end)

    o.pathname = (url ~= "" and url) or "/"
    if not o.protocol or not o.hostname then return nil end

    if o.userinfo then
        o.userinfo = o.userinfo:gsub(":(.+)$", function(v) o.password = v; return "" end)
        if o.userinfo:match("^[A-Za-z0-9%+%-%_%.]+$") then
            o.username = o.userinfo
        end
        o.userinfo = nil
    end

    if not o.port then o.port = services[o.protocol] end
    o.host = o.hostname .. (o.port and (":" .. o.port) or "")
    o.origin = o.protocol .. "://" .. o.host
    return o
end

-- ---------------------------------------------------------------------------
-- JSON: luci.json drops nil keys; we additionally drop "" / empty containers
-- to match the upstream removeBlankAttrs behaviour.
-- ---------------------------------------------------------------------------
local json = require("luci.json")

local function clean(res)
    local t = type(res)
    if t == "table" then
        local out = {}
        local isarray = true
        local n = 0
        for k in pairs(res) do
            if type(k) ~= "number" then isarray = false end
            n = n + 1
        end
        if n == 0 then return nil end
        if isarray then
            for i = 1, n do
                local v = clean(res[i])
                if v ~= nil then out[#out + 1] = v end
            end
            if #out == 0 then return nil end
            return out
        else
            for k, v in pairs(res) do
                v = clean(v)
                if v ~= nil then out[k] = v end
            end
            if next(out) == nil then return nil end
            return out
        end
    elseif res == nil or res == "" then
        return nil
    else
        return res
    end
end

function _M.encode_json(t)
    return json.encode(clean(t) or {}) .. "\n"
end

function _M.decode_json(s)
    return json.decode(s)
end

-- ---------------------------------------------------------------------------
-- Command execution / logging / HTTP fetch
-- ---------------------------------------------------------------------------
function _M.getTime()
    return os.date("%Y-%m-%d %H:%M:%S")
end

function _M.executeCommand(...)
    local args = { ... }
    local cmd = table.concat(args, " ")
    local out, err = {}, {}
    local tmp_o = "/tmp/.hp_out_" .. tostring(math.random(100000, 999999))
    local tmp_e = "/tmp/.hp_err_" .. tostring(math.random(100000, 999999))
    local code = os.execute(cmd .. " >" .. tmp_o .. " 2>" .. tmp_e)
    local fo = io.open(tmp_o, "rb"); if fo then out = fo:read("*a") or "" fo:close() end
    local fe = io.open(tmp_e, "rb"); if fe then err = fe:read("*a") or "" fe:close() end
    os.remove(tmp_o); os.remove(tmp_e)
    return { command = cmd, stdout = out, stderr = err, exitcode = code }
end

function _M.wGET(url, ua)
    if not url or type(url) ~= "string" then return nil end
    ua = ua or "Wget/1.21 (HomeProxy, like v2rayN)"
    local qua = _M.shellQuote(ua)
    local qurl = _M.shellQuote(url)
    -- Stock MiWiFi busybox wget cannot fetch HTTPS; prefer curl for https URLs
    -- and fall back to wget otherwise (or when curl is unavailable).
    if url:match("^https://") then
        local r = _M.executeCommand("/usr/bin/curl -fsS -m 20 -A " .. qua .. " " .. qurl)
        if not _M.isEmpty(r.stdout) then return _M.trim(r.stdout) end
    end
    local r = _M.executeCommand("/usr/bin/wget -qO- --user-agent " .. qua .. " --timeout=10 " .. qurl)
    return _M.trim(r.stdout)
end

function _M.log(msg, tag)
    _M.mkdir_p(_M.RUN_DIR)
    _M.appendfile(_M.RUN_DIR .. "/homeproxy.log",
        string.format("%s [%s] %s\n", _M.getTime(), tag or "DAEMON", msg))
end

return _M
