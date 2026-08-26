# 深度 Review：为什么 ss 订阅不工作

## 结论（先说结果）

**根因**：commit `d2acb22`（"fix(subscribe): align share-link parser with upstream
protocols"）将 ss（Shadowsocks）解析从**手动提取 userinfo** 改为**通过 `parseURL`
提取**。`parseURL` 的 username 字符集为 `[A-Za-z0-9+_.-]`，排除了 base64 的
**`=`（padding）**和 **`/`** 两个字符。这导致所有 base64 userinfo 含 `=` 或 `/`
的 ss 链接被**静默丢弃**。

由于 `base64("aes-256-gcm:password")` = `YWVzLTI1Ni1nY206cGFzc3dvcmQ=`（以 `=`
结尾），**最常见的 ss 加密方法恰好触发此 bug**，大量 ss 节点被跳过。

**已修复**：见 `root/usr/lib/homeproxy/update_subscriptions.lua` 第 342–410 行。

---

## 1. 上游 vs 当前代码对比

### 1.1 上游 `immortalwrt/homeproxy`（ucode）

文件：`root/etc/homeproxy/scripts/update_subscriptions.uc`，第 216–262 行。

上游的 ss 解析分两步：

```
① Shadowrocket 预解码（激进）：
   split(uri[1], '#') → 对 # 之前的整个 body 调 decodeBase64Str()，
   只要返回值 truthy 就替换 uri[1]。body 中可能含 @host:port，
   b64dec 的行为取决于 ucode 实现（是否跳过非 base64 字符）。

② parseURL 提取 username/password：
   if url.username && url.password → 明文 [username, urldecode(password)]
   else if url.username → base64 decode(urldecode(username)) 再 split(':')
```

上游 `parseURL`（`homeproxy.uc` 第 213 行）的 username 字符集：
```js
if (match(objurl.userinfo, /^[A-Za-z0-9\+\-\_\.]+$/))
```
**同样排除 `=` 和 `/`**。上游的"激进预解码"在某些情况下掩盖了这个问题（但也会
corrupt 其他情况），取决于 ucode `b64dec` 对非 base64 字符的处理行为。

### 1.2 当前项目（Lua 移植）

文件：`root/usr/lib/homeproxy/update_subscriptions.lua`。

#### 旧代码（d2acb22 之前）——手动提取

```lua
local at = body:find("@", 1, true)
if at then
    local userinfo = body:sub(1, at - 1)
    local hostport = body:sub(at + 1):gsub("%?.*$", "")
    method, pass = userinfo:match("^([^:]+):(.*)$")        -- 明文
    if not method then
        local dec = hp.decodeBase64Str(userinfo)            -- base64
        if dec then method, pass = dec:match("^([^:]+):(.*)$") end
    end
    host, port = hostport:match("^([^:]+):(%d+)$")
```

**优点**：不经过 `parseURL`，不受 username 字符集限制，`=` 和 `/` 正常处理。

**缺点**：
- `hostport:match("^([^:]+):(%d+)$")` 无法解析 IPv6（`[^:]+` 在第一个 `:` 处停止）
- tag 在 base64 内部时处理不完善

#### 新代码（d2acb22 之后，buggy）——parseURL 提取

```lua
local ssurl = hp.parseURL("http://" .. rest)
...
if ssurl.username and ssurl.password then
    method = ssurl.username
    pass = hp.urldecode(ssurl.password)
elseif ssurl.username then
    local d = hp.decodeBase64Str(hp.urldecode(ssurl.username))
    ...
```

`parseURL`（`homeproxy.lua` 第 250 行）的 username 字符集：
```lua
if o.userinfo:match("^[A-Za-z0-9%+%-%_%.]+$") then
    o.username = o.userinfo
```

**与上游完全一致**，同样排除 `=` 和 `/`。但由于 Lua 移植的 Shadowrocket 预解码
更保守（只在 body 无 `@` 且纯 base64 时才解码），没有上游的"激进预解码"兜底，
导致 `=` 和 `/` 的 case 直接失败。

#### 失败链路追踪

以 `ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#MyNode` 为例
（`YWVzLTI1Ni1nY206cGFzc3dvcmQ=` 是 `aes-256-gcm:password` 的标准 base64）：

```
1. rest = "YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#MyNode"
2. body 有 '@' → 跳过 Shadowrocket 预解码 ✓
3. parseURL("http://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#MyNode")
   → userinfo = "YWVzLTI1Ni1nY206cGFzc3dvcmQ="
   → match("^[A-Za-z0-9%+%-%_%.]+$") → 含 '=' → 不匹配 → username = nil ✗✗✗
4. ss handler: ssurl.username = nil → 两个分支都跳过 → method = nil
5. if method and ... → nil → return nil → 节点被丢弃 ✗
```

---

## 2. 影响范围

### 2.1 哪些 ss 链接受影响

| 链接格式 | 例子 | buggy 是否失败 | 原因 |
|---------|------|:---:|------|
| SIP002 base64 无 padding | `ss://YWVz...cmQ@h:p#n` | ✅ | 无 `=`/`/` |
| **SIP002 base64 有 `=` padding** | `ss://YWVz...cmQ=@h:p#n` | ❌ | `=` 被字符集排除 |
| **SIP002 base64 有 `==` padding** | `ss://Y2hh...MwNQ==@h:p#n` | ❌ | `==` 被字符集排除 |
| **SIP002 base64 含 `/`** | `ss://YmFz...c/zbG@h:p#n` | ❌ | `/` 被字符集排除 |
| SIP002 base64url | `ss://YWVz...cmQ@h:p#n` | ✅ | `-`/`_` 在字符集内 |
| SIP002 明文 | `ss://aes-256-gcm:pass@h:p#n` | ✅ | 不经 base64 |
| Shadowrocket 整体 base64 | `ss://base64(...)#n` | ✅ | 预解码先处理 |
| SIP008 JSON | `{"servers":[...]}` | ✅ | 不经 share-link 解析 |

### 2.2 为什么影响面大

- **base64 padding 极为常见**：当 `method:password` 的字节长度不是 3 的倍数时，
  base64 编码必然产生 `=` padding。常见加密方法：
  - `aes-256-gcm:password`（20 字节）→ `...cmQ=`（1 个 `=`）
  - `chacha20-ietf-poly1305:password`（30 字节）→ `...M5pw==`（2 个 `=`）
  - `aes-128-gcm:password`（19 字节）→ `...cmQ=`（1 个 `=`）
- **标准 base64（非 base64url）使用 `/`**：很多机场订阅用标准 base64 而非
  base64url 编码 userinfo。
- **静默失败**：buggy 代码返回 `nil`，主循环 `parse_uri` 返回 nil 的节点被跳过，
  日志只记 "No valid node found"，无明确错误指向 ss 解析失败。

### 2.3 对比：base64url vs 标准 base64

| 特性 | 标准 base64 | base64url |
|------|------------|-----------|
| 字符集 | `A-Za-z0-9+/` | `A-Za-z0-9-_` |
| padding | `=` | 无（通常省略） |
| parseURL 接受 | `+` ✅ `/` ❌ `=` ❌ | `-` ✅ `_` ✅ |
| SIP002 规范 | — | ✅ 推荐 |

SIP002 规范推荐 base64url 无 padding，但**大量实际订阅用标准 base64 含 padding**，
导致与上游一致的 parseURL 字符集在实践中大面积失效。

---

## 3. 修复方案

### 3.1 核心思路

**不再依赖 `parseURL` 的 username 提取**。手动从 body 中按最后一个 `@` 拆分
userinfo 和 host:port，只把 host:port 部分交给 `parseURL`（保留 IPv6 和 query
解析能力）。

### 3.2 修复代码（已实施）

```lua
elseif scheme == "ss" then
    local body, frag = rest, nil
    local hashpos = rest:find("#", 1, true)
    if hashpos then body, frag = rest:sub(1, hashpos - 1), rest:sub(hashpos + 1) end
    -- Shadowrocket 预解码（保持不变）
    if body and not body:find("@", 1, true) and body:match("^[A-Za-z0-9%+%/_%=%-]+$") then
        local dec = hp.decodeBase64Str(body)
        if dec and dec:find("@", 1, true) then
            local dh = dec:find("#", 1, true)
            if dh then body = dec:sub(1, dh - 1); if not frag then frag = dec:sub(dh + 1) end
            else body = dec end
        end
    end
    -- ★ 关键改动：手动拆分 userinfo（贪心 .* 匹配最后一个 @）
    local ssuserinfo, hostpart = body:match("^(.*)@([^@]*)$")
    if not ssuserinfo then return nil end
    -- parseURL 只处理 host:port（IPv6 + query）
    local ssurl = hp.parseURL("http://" .. hostpart)
    if not ssurl then return nil end
    local ssp = ssurl.searchParams or {}
    local method, pass
    -- 先试明文 "method:password"（password 可能 URI 编码）
    method, pass = ssuserinfo:match("^([^:]+):(.*)$")
    if method then pass = hp.urldecode(pass)
    else  -- 再试 base64 编码
        local d = hp.decodeBase64Str(hp.urldecode(ssuserinfo))
        if d then method, pass = d:match("^([^:]+):(.*)$") end
    end
    ...
    -- ★ 额外修复：去除 IPv6 方括号（上游 replace(/\[|\]/g, '')）
    local ssaddr = ssurl.hostname:gsub("[%[%]]", "")
    return { ..., address = ssaddr, ... }
end
```

### 3.3 改动要点

| 改动 | 原因 |
|------|------|
| `body:match("^(.*)@([^@]*)$")` 拆分 userinfo | 贪心 `.*` 匹配**最后一个** `@`，不受 userinfo 中 `=`/`/` 影响 |
| 只把 `hostpart` 交给 parseURL | 避免 parseURL 的 authority 解析在 userinfo 含 `/` 时中断 |
| 手动试明文再试 base64 | 与旧代码和上游逻辑一致，但绕过字符集限制 |
| `ssurl.hostname:gsub("[%[%]]","")` | 去除 IPv6 方括号，对齐上游行为 |

### 3.4 测试验证

`tests/test_ss_parse.py` 忠实复现 Lua 的 `parseURL`/`decodeBase64Str`/`urldecode`
及三个版本的 ss handler，覆盖 13 种 ss 链接格式：

```
DESCRIPTION                         OLD      BUGGY    FIXED    EXPECTED
SIP002 base64 NO padding            PASS     PASS     PASS     aes-256-gcm
SIP002 base64 WITH padding          PASS     FAIL     PASS     aes-256-gcm      ← 回归
SIP002 base64 chacha20 (==pad)      PASS     FAIL     PASS     chacha20-...      ← 回归
SIP002 base64url no pad             PASS     PASS     PASS     aes-256-gcm
SIP002 plaintext                    PASS     PASS     PASS     aes-256-gcm
SIP002 plaintext encoded pw         PASS     PASS     PASS     aes-256-gcm
SIP002 base64 no pad no tag         PASS     PASS     PASS     aes-256-gcm
SIP002 base64 padded no tag         PASS     FAIL     PASS     aes-256-gcm      ← 回归
Shadowrocket tag outside            PASS     PASS     PASS     aes-256-gcm
Shadowrocket tag inside             FAIL     PASS     PASS     aes-256-gcm      ← 旧代码的 bug
SIP002 plugin simple-obfs           PASS     PASS     PASS     aes-256-gcm
SIP002 IPv6 no pad                  FAIL     PASS     PASS     aes-256-gcm      ← 旧代码的 bug
SIP002 base64 with / char           PASS     FAIL     PASS     aes-256-gcm      ← 回归
-----------------------------------------------------------------------------------------------
Summary: OLD 11/13 | BUGGY 9/13 | FIXED 13/13
```

- **BUGGY 版本 4 个 FAIL** 全是 base64 含 `=`/`/` 的 case → 本次修复全部解决
- **FIXED 版本 13/13 PASS**，同时修复了旧代码的 2 个缺陷（Shadowrocket tag
  in base64, IPv6 地址）

---

## 4. 上游的相同问题

上游 `immortalwrt/homeproxy` 的 `parseURL` 有**完全相同的字符集限制**
（`/^[A-Za-z0-9\+\-\_\.]+$/`）。上游通过激进的整 body base64 预解码部分掩盖了
此问题，但该预解码本身也可能 corrupt URI（取决于 ucode `b64dec` 对非 base64
字符的行为）。

**本次修复实际上优于上游**：手动拆分 userinfo 既绕过了字符集限制，又保留了
parseURL 对 IPv6 和 query 的正确解析，且不会 corrupt 任何合法 URI。

---

## 5. 对照上游后的全局行为审计

本轮进一步对照 `upstream/master`，审计的不只是 ss，而是订阅更新的**默认行为、失败恢复和所有协议的公共路径**。

### 5.1 已确认并修复的高风险差异

| 问题 | 上游行为 | 原 Lua 移植行为 | 当前处理 |
|------|----------|------------------|----------|
| 订阅请求失败 | 空 cache 直接保留旧节点 | 空 cache 会删除该组旧节点 | 保留旧节点，避免网络抖动造成数据丢失 |
| 明文订阅响应 | 上游主要按 base64 处理 | 无条件 permissive base64 解码，明文会损坏 | 先识别 share-link 明文，仅在解码结果含 `scheme://` 时接受 |
| 无标签节点 | 回退为 `address:port` | `md5(nil)`，可能导致 UCI 写入异常 | 统一生成稳定 fallback label |
| whitelist | 显式按匹配结果取反 | `and/or` 表达式导致 whitelist 全部被跳过 | 改为显式分支 |
| 默认关键词 | 上游使用 JS regexp；默认值含 `\|` | Lua `string.find` 把 `\|` 当普通字符 | 支持 `|` 分割，并按字面量匹配 |
| IPv6 | 统一移除方括号并校验 | 只有 ss 特殊处理 | 公共 normalize 阶段统一移除和校验 |
| IPv6 / 主机名 / 端口校验 | `parse_uri` 末尾统一校验 | 公共校验缺失 | 统一拒绝非法地址和越界端口 |
| TLS 协议缺省端口 | 由协议语义决定 | synthetic `http://` 造成缺省为 80 | 为 trojan/vless/tuic/hysteria/anytls 等使用 443 |
| 协议 userinfo 中的 `+` | URI component 中是字面量 | 通用 `urldecode` 错按 form-urlencoded 转为空格 | 协议凭据改用 component 解码，保留 `+`；查询参数继续沿用原有 form 语义 |

### 5.2 有意优于上游的行为

1. **ss userinfo 不再经过通用 `parseURL` 的字符集门禁**：支持标准 base64 中常见的
   `=`、`/`、`+`，同时仍支持 base64url、URI percent-encoding、明文密码和 IPv6。
2. **Shadowrocket 整体 base64 只在 body 无 `@` 且字符集纯 base64 时尝试**：不会像上游
   那样对包含明文 host、端口的整个 URI 做激进解码，降低合法 URI 被误改写的概率。
3. **订阅失败采取 fail-safe**：对齐上游针对空 cache 的保护，并进一步把“至少解析出一个节点”作为
   成功条件，当前实现保留失败组旧节点，牺牲“自动清理失效节点”的激进性，换取不因一次超时
   清空生产配置。只有成功获取且解析出至少一个节点的订阅组才参与 stale-node 清理。
4. **可选 sing-box feature 探测失败时 fail-closed**：不假定 QUIC/uTLS 可用，避免写入
   当前 sing-box 无法加载的节点。

### 5.3 本轮完成的模块化与性能优化

- 新增 `root/usr/lib/homeproxy/subscription_parser.lua`，将协议 URI 解析、SS 特殊格式、
  订阅 body 解码、节点公共 normalize 和过滤匹配从 UCI 更新器中抽离。模块不依赖 UCI、
  service control 或文件 I/O，通过 `hp`、feature flags、日志和 packet encoding 注入运行时依赖。
- `update_subscriptions.lua` 从约 713 行缩减到约 377 行，主文件现在主要负责 feature 探测、
  HTTP 获取、节点去重、UCI 写入和服务生命周期。
- `hp.md5()` 增加单次进程内 memoization，并直接从 `md5sum` 首字段读取结果，去掉 `cut` 子进程。
  不改变 UCI hash 命名规则；缓存只存在于当前 Lua 进程。
- sing-box feature 探测结果缓存到 `RUN_DIR/singbox-features.json`，缓存签名包含二进制路径和
  `sing-box version` 输出。二进制升级或路径变化后自动重新执行三次 check；探测临时文件使用
  `os.tmpname()`，缓存采用临时文件后 rename 写入。
- `filter_check` 也移入模块，更新器只保留策略参数绑定。

### 5.4 仍然值得优化的项目

- `hp.md5()` 仍通过一次 `printf | md5sum` 外部调用计算每个不同输入；若订阅规模很大，可继续
  实现纯 Lua MD5，但需要在目标路由器上做 CPU/耗时对比。
- feature cache 的签名依赖 `sing-box version` 输出；极端情况下二进制内容变化但版本输出不变，
  仍可能命中旧缓存。若需要更强失效保证，可增加 binary mtime 或文件大小。
- 当前 `parseURL` 仍是轻量解析器，不是完整 RFC/WHATWG URL parser；复杂 percent-encoding、
  IPv4-mapped IPv6、极端 hostname 仍应通过 sing-box check 做最终验证。
- **parseURL IPv6 主机名变化影响 `generate_client.lua`**：`parse_dnsserver` 对无 `://` 的 IPv6
  DNS 地址手动加 `[...]` 括号后调用 `parseURL`，而 `parseURL` 现在统一去除括号，使 `server`
  字段获得裸地址（如 `::1`）。sing-box DNS `server` 字段接受裸 IPv6 地址（不需要方括号），
  因此这是正确行为，但与旧代码不同。建议在目标路由器上用 `homeproxy generate` 验证 IPv6 DNS。
- 订阅 JSON 现在只把包含 `server` 和 `method` 的数组识别为 SIP008；这是防止误把任意 JSON
  当 SIP008 的保守策略。若要支持更多供应商格式，应增加明确的格式分支，而不是放宽到任意数组。
- `filter_keywords` 目前支持常用的 `|` alternation 子集并按字面量匹配；若要完全兼容上游 JS
  regexp，需要引入正则实现，不建议直接把用户输入当 Lua pattern 执行。

### 5.5 当前实现的设计评价

整体上，当前实现比原 Lua 移植和上游默认路径更稳健：**解析器负责识别，normalize 负责公共
约束，更新器负责原子性和失败保留**。模块化后，协议解析可以在不加载 UCI 和服务控制的情况下
独立测试，更新器也更容易审查和维护。ss 的手动 userinfo 拆分是必要的兼容性修复，不是绕过
规范的临时 hack。

---

## 6. 本轮修改与验证

| 文件 | 改动 |
|------|------|
| `root/usr/lib/homeproxy/update_subscriptions.lua` | 模块接入、feature cache、订阅更新和 UCI 生命周期 |
| `root/usr/lib/homeproxy/subscription_parser.lua` | 新增独立协议解析/normalize/filter 模块 |
| `root/usr/lib/homeproxy/homeproxy.lua` | SS 兼容所需的 URL/IPv6/端口校验和 MD5 memoization |
| `tests/test_ss_parse.py` | 13 个 ss 格式回归用例 |
| `docs/ss-subscription-review.md` | 更新模块化和性能优化说明 |

验证结果：`python tests/test_ss_parse.py` **13/13 PASS**，`git diff --check` 通过，Python 测试脚本
编译检查通过。Windows 环境没有可用的 Lua 5.1 解释器，因此尚未执行真实 Lua/UCI 集成测试，
建议在目标路由器上运行 `homeproxy subscribe`、`homeproxy generate` 和
`sing-box check --config /var/run/homeproxy/sing-box-c.json` 做最终验证。