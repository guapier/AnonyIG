# 签名算法与密钥提取原理

本文档详细说明 AnonyIG 签名服务的核心算法逻辑，包括密钥提取流程、签名生成算法和请求构建规范。

---

## 1. 整体流程

```
远程 JS 文件                 密钥提取                  请求签名
┌──────────────┐    ┌───────────────────┐    ┌──────────────────┐
│ link.chunk.js │───>│ 反混淆 + 数据提取  │───>│ HMAC-SHA256 签名  │
│ (混淆代码)    │    │                   │    │                  │
└──────────────┘    │ 1. LZString 解压   │    │ key = 解码密钥    │
                    │ 2. 常量数组内联    │    │ msg = data + ts   │
                    │ 3. 字符串解码内联  │    │ sig = HMAC(key,msg)│
                    │ 4. 提取 blob+alpha │    └──────────────────┘
                    │ 5. 解码密钥        │
                    │ 6. 计算 _ts        │
                    └───────────────────┘
```

---

## 2. JS 反混淆 (deobfuscator-v4.js)

远程 JS 经过多层混淆，v4 反混淆器按以下阶段逐步还原：

### Phase 0: 预处理

- **解析 AST** — 使用 Babel Parser 将 JS 转为抽象语法树
- **提取常量数组** — 识别大数组声明 `const arr = [0, null, 32, ...]`，缓存其值
- **LZString 解压** — 检测 `decompressFromUTF16()` 调用，解压得到 `|` 分隔的字符串表

### Phase 1: 常量数组内联

将 `arr[0x1f]` 替换为数组中对应索引的字面值 `31`。

### Phase 2: 字符串解码内联

JS 中使用 `f6Z6dsn(502)` 形式调用解码函数。Phase 0 已获得字符串表，直接将调用替换为 `"now"` 等实际字符串。

### Phase 3: 字符串拼接合并

将 `"abc" + "def"` 合并为 `"abcdef"`，同时进行常量折叠。

### Phase 4: 全局解析器还原

JS 中有一个 `switch-case` 函数将字符串映射到全局对象：

```javascript
// 混淆形式
tdTr8GF("Date")     // → Date
tdTr8GF("console")  // → console
```

识别该函数的映射表，将所有调用替换为实际的全局标识符。

### Phase 5: 清理优化

- 十六进制数字还原 (`0x1f` → `31`)
- 属性访问简化 (`obj["prop"]` → `obj.prop`)
- 布尔值简化 (`!0` → `true`, `!1` → `false`)
- 死代码移除

---

## 3. 密钥数据提取

反混淆后，JS 中以明文出现以下关键数据（位于 `decodeSecretFromBlob` 引用附近）：

```javascript
tXDh_SQ = "SJP/SqBgNSFy...";     // 加密 blob (300+ 字符)
Q6RPppz = "SyNgB9AdF/Gp...UTH";  // 自定义 Base64 字母表 (64 字符)
gfkl3du = ["8kl", "ayz", "ml"];   // 密钥片段 (3 个短字符串)
p38LGU  = [2, 0, 1];              // 片段索引 (拼接顺序)
```

**提取方法**：以 `decodeSecretFromBlob` 最后一次出现位置为锚点，向前搜索 3000 字符，通过正则匹配提取。

---

## 4. 密钥解码 (decodeSecretFromBlob)

### 4.1 输入

| 参数 | 说明 |
|------|------|
| `encrypted_blob` | 自定义 Base64 编码的加密数据 |
| `custom_alphabet` | 64 字符的自定义 Base64 字母表 |

### 4.2 解码流程

```
自定义 Base64 字符串
        │
        ▼
┌─ 字母表映射 ─────────────────────────────┐
│ 将自定义字母表映射到标准 Base64 字母表     │
│ custom_char → std_char (逐字符替换)       │
└──────────────────────────────────────────┘
        │
        ▼
    标准 Base64 解码 → 字节数组
        │
        ▼
┌─ 解析 Blob 结构 ─────────────────────────┐
│ 字节 0: 版本号 (必须为 1)                 │
│ 字节 1: 分块数量 N                        │
│ 对每个分块:                               │
│   - preOps:  预处理操作列表               │
│   - b64Ops:  Base64 操作列表              │
│   - enc:     加密数据子串                 │
└──────────────────────────────────────────┘
        │
        ▼
┌─ 逐块解密 ───────────────────────────────┐
│ 1. 对加密子串执行 b64Ops 的逆操作         │
│    (字母表变换, 反转, 移位等)             │
│ 2. 标准 Base64 解码为字节                 │
│ 3. 对字节执行 preOps 的逆操作             │
│    (XOR, 反转, 移位等)                    │
│ 4. 字节转 ASCII 字符串                    │
└──────────────────────────────────────────┘
        │
        ▼
    拼接所有分块 → 64 字符 hex 密钥
```

### 4.3 操作类型

Blob 中的每个操作由 2 字节编码：`[操作ID, 参数]`

| 操作ID | 预处理操作 (preOps) | Base64操作 (b64Ops) |
|--------|---------------------|---------------------|
| 0 | 反转字节数组 | 反转字符串 |
| 1 | 每字节 XOR 参数 | 字母表循环移位 |
| 2 | 字节循环左移 n 位 | 交换大小写 |
| 3 | 相邻字节交换 | - |

解密时所有操作**逆序**执行，且每个操作取**逆操作**。

---

## 5. 构建时间戳 _ts

`_ts` 是 JS 构建时嵌入的固定时间戳，计算方式：

```
key_parts = ["8kl", "ayz", "ml"]    // 密钥片段
indices   = [2, 0, 1]               // 拼接顺序

combined = key_parts[2] + key_parts[0] + key_parts[1]
         = "ml" + "8kl" + "ayz"
         = "ml8klayz"

_ts = parseInt("ml8klayz", 36)       // 36 进制转十进制
    = 1770242354891
```

服务端会校验 `_ts` 是否过期（通常有效期数天到数周），过期后返回 `REQUEST_SIGNATURE_EXPIRED_BUILD_TIMESTAMP`。

---

## 6. 签名生成

### 6.1 算法

```
HMAC-SHA256(key, message)
```

| 组件 | 说明 |
|------|------|
| **key** | 解码后的密钥 hex 字符串转字节 (`bytes.fromhex(secret)`) → 32 字节 |
| **message** | `data_string + str(timestamp)` |

### 6.2 data_string 构建规则

| 请求类型 | data_string |
|----------|-------------|
| JSON 请求 (用户信息/帖子) | `JSON.stringify(sorted_keys(data))` — 键按字母排序、紧凑格式 |
| URL 请求 (帖子详情) | 直接使用 URL 字符串 |

**示例** (用户信息请求)：

```python
data = {"username": "jaychou"}
sorted_data = {"username": "jaychou"}     # 已排序
data_string = '{"username":"jaychou"}'     # 紧凑 JSON
timestamp = 1770242400000                  # 毫秒时间戳
message = '{"username":"jaychou"}1770242400000'
signature = HMAC-SHA256(key_bytes, message)
```

### 6.3 完整请求体

```json
{
  "username": "jaychou",
  "ts": 1770242400000,
  "_ts": 1770242354891,
  "_tsc": 0,
  "_sv": 2,
  "_s": "a1b2c3d4..."
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `ts` | int | 当前时间戳 (毫秒) |
| `_ts` | int | JS 构建时间戳 (从 JS 提取) |
| `_tsc` | int | 时间同步校正值 (通常为 0) |
| `_sv` | int | 签名版本号 (固定为 2) |
| `_s` | string | HMAC-SHA256 签名 (64 字符 hex) |

---

## 7. 时间同步机制

JS 前端在初始化时请求 `/msec` 接口获取服务器时间，计算本地与服务器的时间差 `_tsc`：

```
server_time = fetch("/msec").msec * 1000   // 服务器时间 (ms)
_tsc = Date.now() - server_time            // 时间差
ts = Date.now() - _tsc                     // 校正后的时间戳
```

如果 `/msec` 不可用或时间差小于 60 秒，`_tsc = 0`，`ts = Date.now()`。

本服务默认 `_tsc = 0`，使用本地当前时间作为 `ts`。

---

## 8. 密钥自动刷新

```
服务启动
    │
    ▼
下载 JS → 反混淆 → 提取密钥 → 缓存
    │
    ▼
启动后台任务 (每 6 小时)
    │
    ├── 下载 JS
    ├── 比较 MD5 哈希
    ├── 若有变化: 重新提取密钥 → 更新缓存
    └── 若无变化: 跳过
```

缓存存储在 `app/key_cache.json`，包含：
- `secret`: 64 字符 hex 密钥
- `fixed_ts`: 构建时间戳
- `js_hash`: JS 文件 MD5
- `updated_at`: 更新时间
