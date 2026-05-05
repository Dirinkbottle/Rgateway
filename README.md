# Rgateway

导航站缓存外围网关。Rust + Axum，前置在 Go 业务后端之前提供缓存层。

## 架构

```
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

### 一、公开网关（端口 3000）

所有 `/api/*` 请求透明代理到 Go 后端，浏览器无感知。

#### GET /api/* — 读操作（带缓存）

```
GET /api/sites
GET /api/sites?category=tech
GET /api/sites/123
```

**行为：** 缓存命中直接返回，未命中转发后端并缓存。

**响应头（浏览器可见）：**

| 头 | 值 | 说明 |
|---|------|------|
| `X-Cache` | `HIT` / `MISS` | 本次是否命中缓存 |

#### POST/PUT/DELETE /api/* — 写操作（穿透）

```
POST /api/sites
PUT /api/sites/123
DELETE /api/sites/123
```

**行为：** 不查缓存、不写缓存，直接转发后端。

#### GET /health

返回 `ok`，用于健康检查。

---

### 二、后端响应头约定

Go 后端可通过以下响应头控制缓存行为，**这些头不会暴露给浏览器**（网关会剥离）。

| 响应头 | 示例 | 说明 |
|--------|------|------|
| `X-Cache-TTL` | `60` | 本条缓存 TTL（秒），覆盖默认 3 天。适合变化较快的接口 |
| `X-Cache-Skip` | `1` | 本次响应不缓存。适合用户相关数据、实时数据 |
| `X-Cache-Tag` | `sites` | 缓存标签，用于后续批量失效 |

**典型使用场景：**

```
# Go 后端伪代码

// 站点列表 — 变化少，走默认 3 天缓存，打标签方便后续失效
GET /api/sites
  → 不设任何头，默认缓存 3 天
  → 设置 X-Cache-Tag: sites

// 用户信息 — 每个用户不同，跳过缓存
GET /api/user/me
  → X-Cache-Skip: 1

// 实时统计 — 变化快，缓存 10 秒
GET /api/stats
  → X-Cache-TTL: 10
```

---

### 三、缓存管理 API（端口 3001，仅 127.0.0.1）

供 Go 后端在数据变更时主动失效缓存。

#### POST /__gateway/invalidate

按标签或路径失效缓存。

```bash
# 按标签批量失效（推荐）
curl -X POST 127.0.0.1:3001/__gateway/invalidate \
  -H "Content-Type: application/json" \
  -d '{"tag":"sites"}'

# 按精确路径失效
curl -X POST 127.0.0.1:3001/__gateway/invalidate \
  -H "Content-Type: application/json" \
  -d '{"path":"/api/sites"}'
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `tag` | string | 按标签失效，匹配 `X-Cache-Tag` |
| `path` | string | 按路径失效，需完全匹配 |

两个字段二选一，`tag` 优先。

#### DELETE /__gateway/cache

清空全部缓存。

```bash
curl -X DELETE 127.0.0.1:3001/__gateway/cache
```

#### GET /__gateway/stats

缓存统计。

```bash
curl 127.0.0.1:3001/__gateway/stats
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
