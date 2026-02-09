# API 接口文档

服务基础地址: `http://localhost:8000`

启动后可访问交互式文档:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Instagram 数据接口

### POST /api/instagram/user-info

获取 Instagram 用户信息。

**请求体**

```json
{
  "username": "jaychou"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| username | string | 是 | Instagram 用户名 |

**响应**

```json
{
  "success": true,
  "data": {
    "id": "317084564",
    "username": "jaychou",
    "full_name": "Jay Chou",
    "biography": "...",
    "profile_pic_url": "https://...",
    "profile_pic_url_hd": "https://...",
    "follower_count": 11013489,
    "following_count": 52,
    "media_count": 636,
    "is_private": false,
    "is_verified": true,
    "external_url": "https://..."
  },
  "raw_response": { ... },
  "error": null
}
```

---

### POST /api/instagram/posts

获取用户帖子列表。

**请求体**

```json
{
  "username": "jaychou",
  "max_id": ""
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| username | string | 是 | Instagram 用户名 |
| max_id | string | 否 | 分页游标，用于加载更多帖子 |

**响应**

```json
{
  "success": true,
  "posts": [
    {
      "node": {
        "id": "...",
        "shortcode": "...",
        "display_url": "https://...",
        "is_video": false,
        "edge_liked_by": { "count": 12345 },
        "edge_media_to_comment": { "count": 678 },
        "taken_at_timestamp": 1700000000
      }
    }
  ],
  "next_max_id": "...",
  "has_more": true,
  "raw_response": { ... },
  "error": null
}
```

分页获取: 将上一次响应的 `next_max_id` 作为下一次请求的 `max_id`。

---

### POST /api/instagram/post-detail

获取帖子详情（含下载链接）。

**请求体**

```json
{
  "url": "https://www.instagram.com/p/DBAvT_xuCFm/"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| url | string | 是 | Instagram 帖子 URL (`/p/` 或 `/reel/` 格式) |

**响应**

```json
{
  "success": true,
  "data": { ... },
  "raw_response": { ... },
  "error": null
}
```

---

## 密钥管理接口

### GET /api/key-status

查看当前密钥状态。

**响应**

```json
{
  "current_secret": "c0289c264e7fc43c0af3ae73719d339b...",
  "secret_length": 64,
  "last_update": "2026-02-09T14:42:50.556558",
  "last_check": "2026-02-09T14:46:24.886663",
  "js_hash": "7329f10ba3804062e35513f63570d30b",
  "update_count": 1,
  "error_count": 0
}
```

---

### POST /api/update-key

手动触发密钥更新。

**参数**

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| force | bool | false | 是否强制更新 (即使 JS 未变化) |

**示例**

```bash
curl -X POST "http://localhost:8000/api/update-key?force=true"
```

---

### GET /api/current-secret

获取当前有效密钥。若密钥不存在或已过期，会自动更新。

**响应**

```json
{
  "secret": "c0289c264e7fc43c0af3ae73719d339b9051dc3946d74837f43ac247355e7f27",
  "length": 64
}
```

---

### POST /api/fetch-remote-key

从远程重新获取密钥（完整流程：下载 JS → 反混淆 → 提取 → 解码）。

**请求体**

```json
{
  "js_url": "https://anonyig.com/js/link.chunk.js",
  "ch_param": null,
  "force_update": false
}
```

---

## 签名工具接口

### POST /api/generate-signature

生成 HMAC-SHA256 签名（用于调试）。

**请求体**

```json
{
  "request_data": {"username": "jaychou"},
  "timestamp": 1770242400000,
  "secret_key": null
}
```

**响应**

```json
{
  "signature": "a1b2c3d4e5f6...",
  "timestamp": 1770242400000,
  "data_string": "{\"username\":\"jaychou\"}"
}
```

---

### POST /api/create-signed-request

创建完整的带签名请求体。

**请求体**

```json
{
  "request_data": {"username": "jaychou"},
  "time_offset": 0
}
```

**响应**

```json
{
  "signed_body": {
    "username": "jaychou",
    "ts": 1770242400000,
    "_ts": 1770242354891,
    "_tsc": 0,
    "_sv": 2,
    "_s": "a1b2c3d4e5f6..."
  }
}
```

---

### POST /api/decode-secret

从加密 blob 解码密钥（用于调试）。

**请求体**

```json
{
  "encrypted_data": "SJP/SqBgNSFy...",
  "custom_alphabet": "SyNgB9AdF/Gp...UTH"
}
```

**响应**

```json
{
  "secret": "c0289c264e7fc43c0af3ae73719d339b9051dc3946d74837f43ac247355e7f27",
  "length": 64
}
```

---

## 基础接口

### GET /

健康检查。

### GET /msec

获取服务器时间 (用于时间同步)。

```json
{
  "msec": 1770242400.123,
  "timestamp": 1770242400123
}
```

---

## 错误响应

所有接口在失败时返回：

```json
{
  "success": false,
  "error": "错误描述信息"
}
```

常见上游错误码：

| 错误码 | 说明 |
|--------|------|
| `REQUEST_SIGNATURE_EXPIRED_BUILD_TIMESTAMP` | `_ts` 过期，需要更新密钥 |
| `INVALID_SIGNATURE` | 签名校验失败 |
| `Unauthorized` | 未授权 (通常是签名问题) |
