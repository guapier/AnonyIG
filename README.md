# AnonyIG Signature Service

AnonyIG 签名服务 — 通过逆向 `anonyig.com` 前端 JS，实现 Instagram 数据请求签名的自动化生成。

## 功能概述

| 功能 | 说明 |
|------|------|
| 自动密钥提取 | 定时下载远程 JS，反混淆后自动提取加密密钥 |
| HMAC-SHA256 签名 | 生成符合服务端校验的请求签名 |
| Instagram API | 获取用户信息、帖子列表、帖子详情 |
| 后台密钥刷新 | 每 6 小时自动检查 JS 变更并更新密钥 |

## 目录结构

```
.
├── README.md                # 项目文档
├── requirements.txt         # Python 依赖
├── package.json             # Node.js 依赖 (反混淆器)
├── deobfuscator-v4.js       # JS 反混淆工具 (Babel AST)
├── .gitignore
│
├── app/                     # FastAPI 服务
│   ├── __init__.py
│   ├── main.py              # 应用入口 + API 路由
│   ├── instagram_api.py     # Instagram API 客户端
│   ├── js_extractor.py      # JS 下载/反混淆/密钥提取
│   ├── key_updater.py       # 后台密钥自动刷新
│   ├── secret_decoder.py    # Blob 密钥解码
│   ├── signature.py         # HMAC-SHA256 签名
│   └── crypto_utils.py      # Base64/字节操作工具
│
└── docs/                    # 详细文档
    ├── algorithm.md         # 签名算法与密钥提取原理
    └── api.md               # API 接口文档
```

## 环境要求

- **Python** >= 3.10
- **Node.js** >= 16 (用于运行反混淆器)
- **pnpm** / npm (安装 Node.js 依赖)

## 快速部署

### 1. 安装依赖

```bash
# Python 依赖
pip install -r requirements.txt

# Node.js 依赖 (反混淆器所需)
pnpm install   # 或 npm install
```

### 2. 启动服务

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

服务启动后会自动：
1. 下载远程 JS 文件 (`anonyig.com/js/link.chunk.js`)
2. 运行反混淆器提取密钥数据
3. 解码得到 HMAC 密钥和构建时间戳 `_ts`
4. 启动后台定时刷新任务 (每 6 小时)

### 3. 访问文档

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 使用示例

### 获取用户信息

```bash
curl -X POST http://localhost:8000/api/instagram/user-info \
  -H "Content-Type: application/json" \
  -d '{"username": "jaychou"}'
```

### 获取帖子列表

```bash
curl -X POST http://localhost:8000/api/instagram/posts \
  -H "Content-Type: application/json" \
  -d '{"username": "jaychou"}'
```

### 获取帖子详情

```bash
curl -X POST http://localhost:8000/api/instagram/post-detail \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.instagram.com/p/DBAvT_xuCFm/"}'
```

### 查看密钥状态

```bash
curl http://localhost:8000/api/key-status
```

### 手动刷新密钥

```bash
curl -X POST "http://localhost:8000/api/update-key?force=true"
```

## 生产部署

```bash
# 使用多 worker 部署
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# 或使用 gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

## 核心模块说明

| 模块 | 职责 |
|------|------|
| `main.py` | FastAPI 应用入口，定义所有 API 路由和生命周期管理 |
| `instagram_api.py` | Instagram 数据获取客户端，封装签名构建和请求发送 |
| `js_extractor.py` | 下载远程 JS、调用反混淆器、提取加密 blob/字母表/`_ts` |
| `key_updater.py` | 密钥状态管理和后台自动刷新任务 |
| `secret_decoder.py` | `decodeSecretFromBlob` 实现，从加密 blob 解码 64 字符 hex 密钥 |
| `signature.py` | HMAC-SHA256 签名生成，支持同步/异步接口 |
| `crypto_utils.py` | 自定义 Base64 字母表映射、字节操作、可逆变换 |
| `deobfuscator-v4.js` | Babel AST 反混淆器，处理 LZString/常量数组/字符串解码/全局解析器 |

## 详细文档

- [签名算法与密钥提取原理](docs/algorithm.md)
- [API 接口文档](docs/api.md)
