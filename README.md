# Rgateway (ZFSG)

Zero-Friction Security Gateway — Rust/Axum 反向代理网关，前置在 Go 业务后端之前，提供缓存层 + 请求加密 + 多层安全管道。

---

## 一、前端接入（Watchdog 安全模块）

### 什么是 fetch？

`fetch` 是浏览器内置的 **Fetch API**（`window.fetch`），用于以 JavaScript 发起 HTTP 请求。它是现代前端与后端通信的核心方式：

```javascript
const response = await fetch('/api/sites');
const data = await response.json();
```

几乎所有前端框架（React、Vue、Svelte 等）的网络请求底层都基于 `fetch`。

### 什么请求会被捕获？

Watchdog WASM 模块通过 **替换全局 `window.fetch` 函数** 来拦截请求。只有通过 `fetch()` 发起的请求会被自动加密：

| 请求方式              | 是否被捕获 | 说明                                          |
| --------------------- | ---------- | --------------------------------------------- |
| `fetch('/api/...')`   | **是**     | WASM 替换了 `window.fetch`                    |
| `axios.get(...)`      | **是**     | axios 默认使用 fetch（旧版用 XMLHttpRequest） |
| `XMLHttpRequest`      | **否**     | 浏览器原生 API，未被 hook                     |
| `WebSocket`           | **否**     | 不同协议，不经过 fetch                        |
| `<form>` 表单提交     | **否**     | 浏览器原生行为，不经过 fetch                  |
| `<img src="...">`     | **否**     | 资源加载，不经过 fetch                        |

### 接入步骤（三步完成）

#### 步骤 1：加载 WASM 胶水代码

```javascript
import * as bg from 'http://your-gateway:3000/gateway/watchdogheader';
```

#### 步骤 2：实例化 WASM 模块

```javascript
const BASE = 'http://your-gateway:3000';
const wasmUrl = `${BASE}/gateway/watchdogbody`;
const imports = { "./openatomic_watchdog_bg.js": bg };
const { instance } = await WebAssembly.instantiateStreaming(
    fetch(wasmUrl),
    imports
);
bg.__wbg_set_wasm(instance.exports);
```

#### 步骤 3：初始化（自动 hook fetch）

```javascript
await bg.initialize(BASE);

// 此后所有 fetch 请求自动加密，无需修改任何业务代码
const sites = await fetch('/api/sites').then(r => r.json());
```

### 完整示例

```html
<script type="module">
    const BASE = 'http://your-gateway:3000';
    import * as bg from `${BASE}/gateway/watchdogheader`;

    const wasmUrl = `${BASE}/gateway/watchdogbody`;
    const imports = { "./openatomic_watchdog_bg.js": bg };
    const { instance } = await WebAssembly.instantiateStreaming(
        fetch(wasmUrl), imports
    );
    bg.__wbg_set_wasm(instance.exports);
    await bg.initialize(BASE);

    // === 以下所有 fetch 调用自动加密 ===
    const res = await fetch('/api/sites');
    const data = await res.json();
</script>
```

### 工作原理

```text
前端代码              WASM (hook)           网关 (Rgateway)         后端
─────────────────────────────────────────────────────────────────────────
fetch('/api/sites')
        │
        ▼
  window.fetch 被替换 ──► AES-256-GCM 加密
                          [12B nonce][8B rolling_nonce]
                          [8B timestamp][8B counter]
                          [session_id][ciphertext][16B MAC]
        │
        ▼
  POST /gateway/encrypted_relay ──────► 解密 + 安全检查 ──────► /api/sites
                                         (注入检测/参数校验/
                                          速率限制/JA3过滤)
        │
        ▼
  响应返回 ◄──────────────────────────── 代理响应 ◄──────────── JSON 响应
```

### 网关端点

| 端点                        | 用途                             | 方法 |
| --------------------------- | -------------------------------- | ---- |
| `/gateway/watchdogbody`     | 下载 WASM 二进制模块             | GET  |
| `/gateway/watchdogheader`   | 下载 JS 胶水代码                 | GET  |
| `/gateway/bootstrap`        | 签发短期 bootstrap token         | POST |
| `/gateway/challenge`        | 请求挑战（握手第二步）           | POST |
| `/gateway/challenge/verify` | 验证挑战、获取临时密钥           | POST |
| `/gateway/encrypted_relay`  | 加密请求中继（所有加密流量入口） | POST |
| `/health`                   | 健康检查                         | GET  |

### 安全特性（自动生效）

- **Bootstrap Token 模式** — 客户端不再内置长期密钥，改为服务端签发短期一次性 token
- **AES-256-GCM 加密** — 每个请求使用独立密钥（HKDF 从临时密钥 + 滚动码派生）
- **防重放** — 严格递增的请求计数器 + 时间戳校验
- **防自动化** — 滚动码固定步长 + 最小请求间隔（clock fuse < 10ms 触发脏包）
- **防篡改** — HMAC-SHA256 MAC 验证，常量时间比较
- **会话隔离** — 每次握手签发独立临时密钥
- **IP 绑定** — bootstrap token、挑战、会话均与客户端 IP 绑定
- **Cookie 挑战** — 缺少有效 cookie 时返回 403 + Set-Cookie，携带 cookie 后重试

---

## 架构

```text
浏览器 ──→ Rgateway (:3000) ──→ Go Backend (:8080)
                │
           ┌────┴────┐
           │ 内存缓存  │
           │ LRU+TTL  │
           └─────────┘
```

## 启动

```bash
# 1. 复制配置文件，按需修改
cp .env.example .env

# 2. 启动（release 模式内存 < 10MB）
cargo run --release
```

配置项见 `.env` 文件，均有默认值，无 `.env` 时自动使用系统环境变量。

## API 文档

---

### 一、缓存管理 API（端口 3001，仅 127.0.0.1）

管理接口需要 Bearer Token 鉴权（`ADMIN_TOKEN` 环境变量）。生产环境必须设置 `ADMIN_TOKEN`。

#### GET / 或 /admin

管理面板（Web UI），提供缓存统计、按标签/路径失效、清空缓存功能。

#### GET /__gateway/stats

缓存统计。

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" 127.0.0.1:3001/__gateway/stats
```

响应：

```json
{
  "entries": 423,
  "hits": 15890,
  "misses": 423
}
```

| 字段 | 说明 |
|------|------|
| `entries` | 当前缓存条目数 |
| `hits` | 累计命中次数 |
| `misses` | 累计未命中次数 |

#### POST /__gateway/invalidate

按标签或路径失效缓存（路径前缀匹配，自动清除带 query 的变体）。

```bash
# 按标签批量失效（推荐）
curl -X POST 127.0.0.1:3001/__gateway/invalidate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tag":"sites"}'

# 按路径失效（前缀匹配）
curl -X POST 127.0.0.1:3001/__gateway/invalidate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path":"/api/sites"}'
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `tag` | string | 按标签失效，匹配 `X-Cache-Tag` |
| `path` | string | 按路径失效，前缀匹配（含 query 变体） |

两个字段二选一，`tag` 优先。

#### DELETE /__gateway/cache

清空全部缓存。

```bash
curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" 127.0.0.1:3001/__gateway/cache
```

---

## 后端对接清单

1. **正常响应即可**，无需修改现有接口
2. 需要缓存控制的接口，设置响应头 `X-Cache-Skip` / `X-Cache-TTL` / `X-Cache-Tag`
3. 数据变更时，调用 `POST 127.0.0.1:3001/__gateway/invalidate` 失效对应缓存
4. 建议写入/更新接口在事务提交后按 `tag` 批量失效：

```go
// Go 伪代码
func UpdateSite(site Site) error {
    db.Save(&site)
    // 失效缓存（fire-and-forget，失败不影响主流程）
    go func() {
        http.Post("http://127.0.0.1:3001/__gateway/invalidate",
            "application/json",
            strings.NewReader(`{"tag":"sites"}`))
    }()
    return nil
}
```
