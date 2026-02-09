"""
AnonyIG 签名服务 - FastAPI 应用主入口

提供 RESTful API 接口用于:
1. 生成请求签名
2. 创建带签名的请求体
3. 解码加密密钥
4. 自动从远程 JS 提取密钥

使用方法:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

API 文档:
    http://localhost:8000/docs (Swagger UI)
    http://localhost:8000/redoc (ReDoc)
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Union, Dict, Any, Optional
import time
import logging

from .secret_decoder import decode_secret_from_blob, get_default_secret
from .signature import (
    SignatureGenerator,
    generate_signature,
    create_signed_request,
    sha256_hash,
    sort_object_keys
)
from .js_extractor import (
    fetch_and_extract_secret,
    check_key_update,
    load_cached_key,
    JS_BASE_URL
)
from .key_updater import (
    get_current_secret,
    update_key,
    get_key_status,
    lifespan_key_updater,
    key_state
)
from .instagram_api import (
    InstagramAPIClient,
    UserInfoRequest,
    PostsRequest,
    PostDetailRequest,
    UserInfoResponse,
    PostsResponse,
    PostDetailResponse,
    generate_signature as ig_generate_signature,
    get_current_timestamp as ig_get_current_timestamp
)

# 配置日志
logger = logging.getLogger(__name__)


# ================== Pydantic 模型定义 ==================

class DecodeSecretRequest(BaseModel):
    """解密密钥请求模型"""
    encrypted_data: str = Field(
        ...,
        description="加密的 blob 数据 (自定义 Base64 编码)",
        example="0E6V0eR4c0VG0e6000VV..."
    )
    custom_alphabet: str = Field(
        ...,
        description="自定义 Base64 字母表 (64个字符)",
        example="05c4LAGfVl9d6pkOEQ1o8r+wz7FgRUTHeJqKDythXn3YSvBMsPjaiN2ub/CIWZmx"
    )


class DecodeSecretResponse(BaseModel):
    """解密密钥响应模型"""
    secret: str = Field(..., description="解密后的密钥")
    length: int = Field(..., description="密钥长度")


class SignatureRequest(BaseModel):
    """生成签名请求模型"""
    request_data: Union[str, Dict[str, Any]] = Field(
        ...,
        description="请求数据 (URL 字符串或请求体对象)",
        example="/api/user/profile"
    )
    timestamp: Optional[int] = Field(
        None,
        description="时间戳 (毫秒), 不提供则使用当前时间",
        example=1705123456789
    )
    secret_key: Optional[str] = Field(
        None,
        description="密钥, 不提供则使用默认解密的密钥"
    )


class SignatureResponse(BaseModel):
    """签名响应模型"""
    signature: str = Field(..., description="HMAC-SHA256 签名 (64位十六进制)")
    timestamp: int = Field(..., description="使用的时间戳")
    data_string: str = Field(..., description="签名原文的数据部分")


class SignedRequestRequest(BaseModel):
    """创建带签名请求体的请求模型"""
    request_data: Union[str, Dict[str, Any]] = Field(
        ...,
        description="原始请求数据",
        example={"sf_url": "/api/user/profile", "user_id": "12345"}
    )
    time_offset: int = Field(
        0,
        description="时间偏移量 (毫秒)",
        example=0
    )


class SignedRequestResponse(BaseModel):
    """带签名的请求体响应模型"""
    signed_body: Dict[str, Any] = Field(..., description="带签名的完整请求体")


class TimeSyncResponse(BaseModel):
    """时间同步响应模型"""
    msec: float = Field(..., description="当前服务器时间 (秒)")
    timestamp: int = Field(..., description="当前服务器时间 (毫秒)")


class FetchKeyRequest(BaseModel):
    """获取远程密钥请求模型"""
    js_url: str = Field(
        default=JS_BASE_URL,
        description="JS 文件 URL"
    )
    ch_param: Optional[str] = Field(
        None,
        description="ch 参数 (如 2fcb0a2062d7bec7.js)",
        example="2fcb0a2062d7bec7.js"
    )
    force_update: bool = Field(
        False,
        description="是否强制更新 (忽略缓存)"
    )


class FetchKeyResponse(BaseModel):
    """获取远程密钥响应模型"""
    secret: str = Field(..., description="解密后的密钥")
    js_hash: str = Field(..., description="JS 文件哈希")
    updated_at: str = Field(..., description="更新时间")
    from_cache: bool = Field(..., description="是否来自缓存")


class KeyStatusResponse(BaseModel):
    """密钥状态响应模型"""
    current_secret: Optional[str] = Field(None, description="当前密钥 (部分显示)")
    secret_length: int = Field(0, description="密钥长度")
    last_update: Optional[str] = Field(None, description="最后更新时间")
    last_check: Optional[str] = Field(None, description="最后检查时间")
    js_hash: Optional[str] = Field(None, description="JS 文件哈希")
    update_count: int = Field(0, description="更新次数")
    error_count: int = Field(0, description="错误次数")


# ================== 生命周期管理 ==================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动: 初始化密钥并开启后台更新
    logger.info("Starting AnonyIG Signature Service...")
    
    async with lifespan_key_updater(check_interval_hours=6):
        logger.info("Key updater initialized")
        yield
    
    logger.info("Shutting down...")


# ================== FastAPI 应用创建 ==================

app = FastAPI(
    title="AnonyIG 签名服务",
    description="""
## 概述

本服务提供 AnonyIG 网站请求签名算法的 Python 实现。

## 核心功能

1. **密钥解码** - 从加密的 blob 数据中解码出签名密钥
2. **签名生成** - 使用 SHA-256 算法生成请求签名
3. **请求体构建** - 创建包含签名的完整请求体
4. **自动密钥更新** - 自动从远程 JS 提取最新密钥 (每6小时检查一次)

## 签名算法

```
_s = SHA256(data + timestamp + secret_key)
```

其中:
- `data`: 请求数据 (URL 或 JSON 序列化后的对象, 键已排序)
- `timestamp`: 毫秒时间戳
- `secret_key`: 解密后的密钥

## 自动化流程

1. 服务启动时自动从远程获取最新 JS 文件
2. 解混淆 JS 代码,提取加密数据和字母表
3. 解密得到签名密钥
4. 后台每 6 小时检查一次密钥更新
5. 密钥约 3 天变化一次

## 使用示例

```python
import requests

# 方式 1: 使用自动更新的密钥创建签名
response = requests.post(
    "http://localhost:8000/api/auto-signed-request",
    json={"request_data": {"sf_url": "/api/user"}}
)
signed_body = response.json()["signed_body"]

# 方式 2: 手动获取最新密钥
response = requests.post(
    "http://localhost:8000/api/fetch-remote-key",
    json={"ch_param": "2fcb0a2062d7bec7.js"}
)
secret = response.json()["secret"]
```
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS 中间件配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局签名生成器
signature_generator = SignatureGenerator()


# ================== API 路由 ==================

@app.get("/", tags=["基础"])
async def root():
    """
    根路径 - 服务状态检查
    """
    return {
        "service": "AnonyIG Signature Service",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/msec", response_model=TimeSyncResponse, tags=["基础"])
async def get_server_time():
    """
    获取服务器时间
    
    用于客户端时间同步,返回当前服务器时间。
    客户端可以通过比较本地时间与服务器时间来计算时间偏移量。
    """
    current_time = time.time()
    return {
        "msec": current_time,
        "timestamp": int(current_time * 1000)
    }


@app.post(
    "/api/decode-secret",
    response_model=DecodeSecretResponse,
    tags=["密钥解码"]
)
async def api_decode_secret(request: DecodeSecretRequest):
    """
    解码加密的密钥
    
    从加密的 blob 数据中解码出原始密钥。
    
    ## 参数说明
    
    - **encrypted_data**: 加密的数据 (自定义 Base64 编码)
    - **custom_alphabet**: 自定义 Base64 字母表
    
    ## 返回
    
    - **secret**: 解密后的密钥
    - **length**: 密钥长度
    """
    try:
        secret = decode_secret_from_blob(
            request.encrypted_data,
            request.custom_alphabet
        )
        return {
            "secret": secret,
            "length": len(secret)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"解密失败: {str(e)}")


@app.get("/api/default-secret", response_model=DecodeSecretResponse, tags=["密钥解码"])
async def api_get_default_secret():
    """
    获取默认解密的密钥
    
    使用预配置的加密数据和字母表解密密钥。
    """
    try:
        secret = get_default_secret()
        return {
            "secret": secret,
            "length": len(secret)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取默认密钥失败: {str(e)}")


@app.post(
    "/api/generate-signature",
    response_model=SignatureResponse,
    tags=["签名生成"]
)
async def api_generate_signature(request: SignatureRequest):
    """
    生成请求签名
    
    计算 SHA-256 签名: `_s = SHA256(data + timestamp + secret)`
    
    ## 参数说明
    
    - **request_data**: 请求数据
        - 字符串: 直接使用 (如 URL)
        - 对象: 按键排序后 JSON 序列化
    - **timestamp**: 时间戳 (毫秒), 可选
    - **secret_key**: 密钥, 可选 (默认使用解密的密钥)
    
    ## 返回
    
    - **signature**: 64位十六进制签名
    - **timestamp**: 使用的时间戳
    - **data_string**: 签名原文的数据部分
    """
    try:
        # 处理时间戳
        timestamp = request.timestamp or int(time.time() * 1000)
        
        # 处理密钥
        secret_key = request.secret_key or get_default_secret()
        
        # 处理请求数据
        if isinstance(request.request_data, str):
            data_string = request.request_data
        else:
            sorted_data = sort_object_keys(request.request_data)
            import json
            data_string = json.dumps(sorted_data, separators=(',', ':'), ensure_ascii=False)
        
        # 生成签名
        signature = await generate_signature(request.request_data, timestamp, secret_key)
        
        return {
            "signature": signature,
            "timestamp": timestamp,
            "data_string": data_string
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"签名生成失败: {str(e)}")


@app.post(
    "/api/create-signed-request",
    response_model=SignedRequestResponse,
    tags=["签名生成"]
)
async def api_create_signed_request(request: SignedRequestRequest):
    """
    创建带签名的请求体
    
    生成完整的带签名请求体,可直接用于发送 API 请求。
    
    ## 参数说明
    
    - **request_data**: 原始请求数据 (字符串或对象)
    - **time_offset**: 时间偏移量 (毫秒), 用于时间校正
    
    ## 返回的请求体包含
    
    - 原始数据字段
    - **ts**: 校正后的时间戳
    - **_ts**: 原始时间戳
    - **_tsc**: 时间偏移量
    - **_s**: 签名
    
    ## 示例
    
    请求:
    ```json
    {
        "request_data": {"sf_url": "/api/user"},
        "time_offset": 0
    }
    ```
    
    响应:
    ```json
    {
        "signed_body": {
            "sf_url": "/api/user",
            "ts": 1705123456789,
            "_ts": 1705123456789,
            "_tsc": 0,
            "_s": "a1b2c3d4e5..."
        }
    }
    ```
    """
    try:
        signed_body = await create_signed_request(
            request.request_data,
            request.time_offset
        )
        return {"signed_body": signed_body}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"创建签名请求失败: {str(e)}")


@app.post("/api/sha256", tags=["工具"])
async def api_sha256(text: str):
    """
    计算 SHA-256 哈希
    
    工具接口,用于计算任意文本的 SHA-256 哈希值。
    
    ## 参数
    
    - **text**: 要哈希的文本
    
    ## 返回
    
    - **hash**: 64位十六进制哈希值
    """
    return {
        "text": text,
        "hash": sha256_hash(text)
    }


# ================== 自动化密钥管理 API ==================

@app.post(
    "/api/fetch-remote-key",
    response_model=FetchKeyResponse,
    tags=["自动化密钥管理"]
)
async def api_fetch_remote_key(request: FetchKeyRequest):
    """
    从远程获取密钥
    
    自动下载 JS 文件、解混淆、提取并解密密钥。
    
    ## 工作流程
    
    1. 下载远程 JS 文件
    2. 运行 deobfuscator 解混淆
    3. 使用正则表达式提取加密数据和字母表
    4. 解密得到密钥
    5. 缓存结果
    
    ## 参数
    
    - **js_url**: JS 文件 URL (默认使用预配置 URL)
    - **ch_param**: ch 查询参数
    - **force_update**: 是否强制更新 (忽略缓存)
    
    ## 注意
    
    - 首次调用可能需要较长时间 (下载 + 解混淆)
    - 建议使用缓存以提高性能
    """
    try:
        result = await fetch_and_extract_secret(
            js_url=request.js_url,
            ch_param=request.ch_param,
            use_cache=not request.force_update,
            force_update=request.force_update
        )
        
        return FetchKeyResponse(
            secret=result["secret"],
            js_hash=result["js_hash"],
            updated_at=result["updated_at"],
            from_cache=result.get("from_cache", False)
        )
        
    except Exception as e:
        logger.error(f"Fetch remote key failed: {e}")
        raise HTTPException(status_code=500, detail=f"获取远程密钥失败: {str(e)}")


@app.get(
    "/api/key-status",
    response_model=KeyStatusResponse,
    tags=["自动化密钥管理"]
)
async def api_get_key_status():
    """
    获取密钥状态
    
    返回当前密钥的状态信息,包括:
    - 当前密钥 (部分显示)
    - 最后更新时间
    - 最后检查时间
    - 更新次数
    - 错误次数
    """
    status = get_key_status()
    return KeyStatusResponse(**status)


@app.post("/api/update-key", tags=["自动化密钥管理"])
async def api_update_key(force: bool = False):
    """
    手动触发密钥更新
    
    检查远程 JS 是否有变化,如有则更新密钥。
    
    ## 参数
    
    - **force**: 是否强制更新 (即使 JS 未变化)
    """
    try:
        result = await update_key(force=force)
        return result
    except Exception as e:
        logger.error(f"Update key failed: {e}")
        raise HTTPException(status_code=500, detail=f"更新密钥失败: {str(e)}")


@app.get("/api/current-secret", tags=["自动化密钥管理"])
async def api_get_current_secret():
    """
    获取当前有效密钥
    
    返回当前使用的密钥。如果密钥不存在或已过期,会自动更新。
    
    这是推荐的获取密钥方式,会自动处理缓存和更新。
    """
    try:
        secret = await get_current_secret()
        return {
            "secret": secret,
            "length": len(secret)
        }
    except Exception as e:
        logger.error(f"Get current secret failed: {e}")
        raise HTTPException(status_code=500, detail=f"获取当前密钥失败: {str(e)}")


@app.post("/api/auto-signed-request", tags=["自动化密钥管理"])
async def api_auto_signed_request(request: SignedRequestRequest):
    """
    使用自动更新的密钥创建签名请求
    
    与 /api/create-signed-request 类似,但使用自动管理的密钥。
    
    ## 优势
    
    - 自动使用最新密钥
    - 无需手动管理密钥更新
    - 后台自动检查密钥变化
    
    ## 参数
    
    - **request_data**: 原始请求数据
    - **time_offset**: 时间偏移量 (毫秒)
    """
    try:
        # 获取当前密钥
        secret = await get_current_secret()
        
        # 创建签名生成器
        generator = SignatureGenerator()
        generator.secret_key = secret
        generator.set_time_offset(request.time_offset)
        
        # 生成带签名的请求体
        signed_body = await generator.create_signed_request(request.request_data)
        
        return {"signed_body": signed_body}
        
    except Exception as e:
        logger.error(f"Auto signed request failed: {e}")
        raise HTTPException(status_code=500, detail=f"创建签名请求失败: {str(e)}")


@app.get("/api/check-update", tags=["自动化密钥管理"])
async def api_check_key_update(ch_param: Optional[str] = None):
    """
    检查密钥是否需要更新
    
    比较远程 JS 文件与缓存的哈希值。
    
    ## 参数
    
    - **ch_param**: 可选的 ch 参数
    
    ## 返回
    
    - **needs_update**: 是否需要更新
    """
    try:
        needs_update = await check_key_update(ch_param=ch_param)
        return {
            "needs_update": needs_update,
            "current_hash": key_state.js_hash
        }
    except Exception as e:
        logger.error(f"Check update failed: {e}")
        raise HTTPException(status_code=500, detail=f"检查更新失败: {str(e)}")


# ================== Instagram API 路由 ==================

class IGUserInfoRequest(BaseModel):
    """Instagram 用户信息请求"""
    username: str = Field(..., description="Instagram 用户名", example="jaychou")


class IGPostsRequest(BaseModel):
    """Instagram 帖子列表请求"""
    username: str = Field(..., description="Instagram 用户名", example="jaychou")
    max_id: str = Field("", description="分页游标，用于加载更多帖子")


class IGPostDetailRequest(BaseModel):
    """Instagram 帖子详情请求"""
    url: str = Field(
        ..., 
        description="Instagram 帖子 URL", 
        example="https://www.instagram.com/p/DBAvT_xuCFm/"
    )


@app.post("/api/instagram/user-info", response_model=UserInfoResponse, tags=["Instagram API"])
async def api_instagram_user_info(request: IGUserInfoRequest):
    """
    获取 Instagram 用户信息
    
    通过 anonyig.com 代理获取指定用户的 Instagram 个人资料信息。
    
    ## 请求参数
    
    - **username**: Instagram 用户名
    
    ## 返回数据
    
    - **success**: 请求是否成功
    - **data**: 用户信息对象，包含:
        - username: 用户名
        - full_name: 全名
        - biography: 个人简介
        - profile_pic_url: 头像 URL
        - follower_count: 粉丝数
        - following_count: 关注数
        - media_count: 帖子数
        - is_private: 是否私密账户
        - is_verified: 是否认证账户
    - **raw_response**: 原始 API 响应
    - **error**: 错误信息 (如果失败)
    
    ## 示例
    
    ```bash
    curl -X POST "http://localhost:8000/api/instagram/user-info" \\
         -H "Content-Type: application/json" \\
         -d '{"username": "jaychou"}'
    ```
    """
    try:
        async with InstagramAPIClient() as client:
            return await client.get_user_info(request.username)
    except Exception as e:
        logger.error(f"Instagram user info failed: {e}")
        raise HTTPException(status_code=500, detail=f"获取用户信息失败: {str(e)}")


@app.post("/api/instagram/posts", response_model=PostsResponse, tags=["Instagram API"])
async def api_instagram_posts(request: IGPostsRequest):
    """
    获取 Instagram 用户帖子列表
    
    通过 anonyig.com 代理获取指定用户的帖子/视频列表。
    
    ## 请求参数
    
    - **username**: Instagram 用户名
    - **max_id**: 分页游标 (可选)，用于加载更多帖子
    
    ## 返回数据
    
    - **success**: 请求是否成功
    - **posts**: 帖子列表
    - **next_max_id**: 下一页游标
    - **has_more**: 是否还有更多数据
    - **raw_response**: 原始 API 响应
    - **error**: 错误信息 (如果失败)
    
    ## 示例
    
    ```bash
    # 获取第一页
    curl -X POST "http://localhost:8000/api/instagram/posts" \\
         -H "Content-Type: application/json" \\
         -d '{"username": "jaychou"}'
    
    # 获取更多 (使用 max_id)
    curl -X POST "http://localhost:8000/api/instagram/posts" \\
         -H "Content-Type: application/json" \\
         -d '{"username": "jaychou", "max_id": "xxx"}'
    ```
    """
    try:
        async with InstagramAPIClient() as client:
            return await client.get_posts(request.username, request.max_id)
    except Exception as e:
        logger.error(f"Instagram posts failed: {e}")
        raise HTTPException(status_code=500, detail=f"获取帖子列表失败: {str(e)}")


@app.post("/api/instagram/post-detail", response_model=PostDetailResponse, tags=["Instagram API"])
async def api_instagram_post_detail(request: IGPostDetailRequest):
    """
    获取 Instagram 帖子详情
    
    通过 anonyig.com 代理获取指定帖子的详细信息和下载链接。
    
    ## 请求参数
    
    - **url**: Instagram 帖子 URL
        - 格式: https://www.instagram.com/p/SHORTCODE/
        - 格式: https://www.instagram.com/reel/SHORTCODE/
    
    ## 返回数据
    
    - **success**: 请求是否成功
    - **data**: 帖子详情，可能包含:
        - 视频下载链接
        - 图片下载链接
        - 帖子信息
    - **raw_response**: 原始 API 响应
    - **error**: 错误信息 (如果失败)
    
    ## 示例
    
    ```bash
    curl -X POST "http://localhost:8000/api/instagram/post-detail" \\
         -H "Content-Type: application/json" \\
         -d '{"url": "https://www.instagram.com/p/DBAvT_xuCFm/"}'
    ```
    """
    try:
        async with InstagramAPIClient() as client:
            return await client.get_post_detail(request.url)
    except Exception as e:
        logger.error(f"Instagram post detail failed: {e}")
        raise HTTPException(status_code=500, detail=f"获取帖子详情失败: {str(e)}")


@app.get("/api/instagram/generate-signature", tags=["Instagram API"])
async def api_instagram_generate_signature(
    data: str,
    timestamp: Optional[int] = None
):
    """
    生成 Instagram API 签名
    
    用于调试和验证签名算法。
    
    ## 请求参数
    
    - **data**: 要签名的数据字符串 (JSON 或 URL)
    - **timestamp**: 时间戳 (毫秒)，不传则使用当前时间
    
    ## 返回数据
    
    - **data**: 输入数据
    - **timestamp**: 使用的时间戳
    - **signature**: 生成的签名 (64位十六进制)
    - **sign_string_preview**: 签名原文预览 (前100字符)
    
    ## 示例
    
    ```bash
    curl "http://localhost:8000/api/instagram/generate-signature?data=%7B%22username%22%3A%22jaychou%22%7D"
    ```
    """
    ts = timestamp or ig_get_current_timestamp()
    signature = ig_generate_signature(data, ts)
    
    return {
        "data": data,
        "timestamp": ts,
        "signature": signature,
        "sign_string_preview": f"{data}{ts}...secret..."[:100] + "..."
    }


# ================== 启动入口 ==================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=28000,
        reload=True
    )
