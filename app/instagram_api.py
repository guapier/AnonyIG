"""
Instagram 第三方平台 API 客户端模块

实现通过 anonyig.com 获取 Instagram 用户信息、帖子列表和帖子详情。

签名算法:
_s = SHA256(data + timestamp + secret_key)

其中:
- data: JSON字符串(用户信息/帖子列表) 或 URL字符串(帖子详情)
- timestamp: 时间戳 (毫秒)
- secret_key: 动态密钥 (从远程JS自动提取)
"""

import hashlib
import hmac
import json
import time
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import quote

from curl_cffi import requests as curl_requests
from curl_cffi.requests import AsyncSession
from pydantic import BaseModel, Field


# 配置日志
logger = logging.getLogger(__name__)

# ============================================================
# 配置常量
# ============================================================

# anonyig.com API 基础 URL
BASE_URL = "https://api-wh.anonyig.com"

# 默认密钥 (备用，优先使用动态获取的密钥)
DEFAULT_SECRET_KEY = "6c14d82216be80781fb79e3884392f2f79031225ea7e1c5f708d80806123f3a9"

# 默认的固定服务器时间戳 (从请求中观察到的固定值)
DEFAULT_FIXED_TS = 1770242354891


def get_dynamic_secret_key() -> str:
    """
    获取动态密钥
    
    优先从 key_updater 获取，失败时使用默认密钥
    """
    try:
        from .key_updater import key_state
        if key_state.current_secret:
            return key_state.current_secret
    except Exception as e:
        logger.warning(f"Failed to get dynamic secret: {e}")
    
    # 尝试从缓存加载
    try:
        from .js_extractor import load_cached_key
        cached = load_cached_key()
        if cached and "secret" in cached:
            return cached["secret"]
    except Exception as e:
        logger.warning(f"Failed to load cached secret: {e}")
    
    return DEFAULT_SECRET_KEY


def get_dynamic_fixed_ts() -> int:
    """
    获取动态 _ts 值
    
    优先从 key_state 获取，其次从缓存加载，最后使用默认值
    """
    try:
        from .key_updater import key_state
        if key_state.fixed_ts:
            return key_state.fixed_ts
    except Exception as e:
        logger.warning(f"Failed to get fixed_ts from key_state: {e}")
    
    try:
        from .js_extractor import load_cached_key
        cached = load_cached_key()
        if cached and "fixed_ts" in cached:
            return cached["fixed_ts"]
    except Exception as e:
        logger.warning(f"Failed to load cached fixed_ts: {e}")
    
    return DEFAULT_FIXED_TS


# 为兼容性保留 FIXED_TS 变量
FIXED_TS = DEFAULT_FIXED_TS

# 请求头模板 (与实际浏览器请求一致)
DEFAULT_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "cache-control": "no-cache",
    "content-type": "application/json",
    "dnt": "1",
    "origin": "https://anonyig.com",
    "pragma": "no-cache",
    "priority": "u=1, i",
    "referer": "https://anonyig.com/",
    "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
}


# ============================================================
# Pydantic 模型定义
# ============================================================

class UserInfoRequest(BaseModel):
    """用户信息请求参数"""
    username: str = Field(..., description="Instagram 用户名")


class PostsRequest(BaseModel):
    """帖子列表请求参数"""
    username: str = Field(..., description="Instagram 用户名")
    max_id: str = Field("", description="分页游标，用于获取更多帖子")


class PostDetailRequest(BaseModel):
    """帖子详情请求参数"""
    url: str = Field(..., description="Instagram 帖子 URL，如 https://www.instagram.com/p/xxxxx/")


class SignedRequest(BaseModel):
    """带签名的请求体 (仅用于文档说明)"""
    # 注意: 实际请求体是动态构建的字典，因为 Pydantic 不允许下划线开头的字段名
    # 字段: ts, _ts, _tsc, _s
    pass


class InstagramUser(BaseModel):
    """Instagram 用户信息"""
    id: Optional[str] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    biography: Optional[str] = None
    profile_pic_url: Optional[str] = None
    profile_pic_url_hd: Optional[str] = None
    follower_count: Optional[int] = None
    following_count: Optional[int] = None
    media_count: Optional[int] = None
    is_private: Optional[bool] = None
    is_verified: Optional[bool] = None
    external_url: Optional[str] = None


class InstagramPost(BaseModel):
    """Instagram 帖子信息"""
    id: Optional[str] = None
    shortcode: Optional[str] = None
    display_url: Optional[str] = None
    video_url: Optional[str] = None
    is_video: Optional[bool] = None
    caption: Optional[str] = None
    like_count: Optional[int] = None
    comment_count: Optional[int] = None
    timestamp: Optional[int] = None
    taken_at: Optional[int] = None


class UserInfoResponse(BaseModel):
    """用户信息响应"""
    success: bool
    data: Optional[InstagramUser] = None
    raw_response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class PostsResponse(BaseModel):
    """帖子列表响应"""
    success: bool
    posts: List[Dict[str, Any]] = []
    next_max_id: Optional[str] = None
    has_more: bool = False
    raw_response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class PostDetailResponse(BaseModel):
    """帖子详情响应"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    raw_response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ============================================================
# 签名生成函数
# ============================================================

def generate_signature(data: str, timestamp: int, secret_key: Optional[str] = None) -> str:
    """
    生成 API 请求签名
    
    签名算法: HMAC-SHA256(secret_key_bytes, data + timestamp)
    
    其中 secret_key 是 64 字符的十六进制字符串，转换为 32 字节作为 HMAC 密钥。
    签名消息为: data_string + str(timestamp)
    
    Args:
        data: 请求数据字符串 (JSON 或 URL)
        timestamp: 时间戳 (毫秒)
        secret_key: 密钥十六进制字符串 (可选，不传则使用动态密钥)
    
    Returns:
        64位十六进制签名字符串
    
    Example:
        >>> sig = generate_signature('{"username":"test"}', 1768448262037)
        >>> len(sig)
        64
    """
    # 如果未提供密钥，使用动态密钥
    if secret_key is None:
        secret_key = get_dynamic_secret_key()
    
    # 将十六进制密钥转换为字节 (HMAC-SHA256 密钥)
    key_bytes = bytes.fromhex(secret_key)
    
    # 拼接签名消息: data + timestamp
    message = f"{data}{timestamp}"
    
    # 计算 HMAC-SHA256
    return hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).hexdigest()


def get_current_timestamp() -> int:
    """获取当前时间戳(毫秒)"""
    return int(time.time() * 1000)


def sort_dict_keys(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    按字母顺序排序字典的键
    
    Args:
        d: 输入字典
    
    Returns:
        排序后的字典
    """
    return {k: d[k] for k in sorted(d.keys())}


# ============================================================
# API 客户端类
# ============================================================

class InstagramAPIClient:
    """
    Instagram API 客户端
    
    通过 anonyig.com 代理获取 Instagram 数据。
    
    使用示例:
        async with InstagramAPIClient() as client:
            # 获取用户信息
            user = await client.get_user_info("jaychou")
            print(user.data.username)
            
            # 获取帖子列表
            posts = await client.get_posts("jaychou")
            for post in posts.posts:
                print(post)
    """
    
    def __init__(
        self, 
        secret_key: Optional[str] = None,
        fixed_ts: Optional[int] = None,
        timeout: float = 30.0
    ):
        """
        初始化客户端
        
        Args:
            secret_key: 签名密钥 (可选，不传则使用动态密钥)
            fixed_ts: 固定服务器时间戳 (可选，不传则使用动态值)
            timeout: 请求超时时间(秒)
        """
        self._secret_key = secret_key  # 存储传入的密钥
        self._fixed_ts = fixed_ts  # 存储传入的 _ts
        self.timeout = timeout
        self._client: Optional[AsyncSession] = None
    
    @property
    def secret_key(self) -> str:
        """获取当前有效的密钥"""
        if self._secret_key:
            return self._secret_key
        return get_dynamic_secret_key()
    
    @property
    def fixed_ts(self) -> int:
        """获取当前有效的 _ts 值"""
        if self._fixed_ts:
            return self._fixed_ts
        return get_dynamic_fixed_ts()
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        # 使用 curl_cffi 模拟 Chrome 浏览器指纹
        self._client = AsyncSession(
            timeout=self.timeout,
            headers=DEFAULT_HEADERS,
            impersonate="chrome120"  # 模拟 Chrome 浏览器
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self._client:
            await self._client.close()
            self._client = None
    
    def _get_client(self) -> AsyncSession:
        """获取 HTTP 客户端"""
        if self._client is None:
            self._client = AsyncSession(
                timeout=self.timeout,
                headers=DEFAULT_HEADERS,
                impersonate="chrome120"
            )
        return self._client
    
    def _create_signed_payload(
        self, 
        data_dict: Dict[str, Any],
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        创建带签名的 JSON 请求体
        
        用于用户信息和帖子列表接口。
        
        Args:
            data_dict: 请求数据字典
            timestamp: 时间戳，不传则使用当前时间
        
        Returns:
            包含签名的完整请求体
        """
        ts = timestamp or get_current_timestamp()
        
        # 按字母顺序排序键
        sorted_data = sort_dict_keys(data_dict)
        
        # 生成 JSON 字符串 (紧凑格式，不转义 Unicode)
        data_string = json.dumps(sorted_data, separators=(',', ':'), ensure_ascii=False)
        
        # 生成签名
        signature = generate_signature(data_string, ts, self.secret_key)
        
        # 构建完整请求体
        payload = {
            **data_dict,
            "ts": ts,
            "_ts": self.fixed_ts,
            "_tsc": 0,
            "_sv": 2,
            "_s": signature
        }
        
        return payload
    
    def _create_signed_form(
        self,
        url: str,
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        创建带签名的表单请求体
        
        用于帖子详情接口。
        
        Args:
            url: Instagram 帖子 URL
            timestamp: 时间戳，不传则使用当前时间
        
        Returns:
            表单数据字典
        """
        ts = timestamp or get_current_timestamp()
        
        # 生成签名 (直接使用 URL 作为数据)
        signature = generate_signature(url, ts, self.secret_key)
        
        # 构建表单数据
        form_data = {
            "sf_url": url,
            "ts": str(ts),
            "_ts": str(self.fixed_ts),
            "_tsc": "0",
            "_sv": "2",
            "_s": signature
        }
        
        return form_data
    
    async def get_user_info(self, username: str) -> UserInfoResponse:
        """
        获取 Instagram 用户信息
        
        Args:
            username: Instagram 用户名
        
        Returns:
            用户信息响应
        
        Example:
            >>> async with InstagramAPIClient() as client:
            ...     resp = await client.get_user_info("jaychou")
            ...     print(resp.data.full_name)
        """
        try:
            client = self._get_client()
            
            # 构建请求体
            payload = self._create_signed_payload({"username": username})
            
            # 发送请求
            response = await client.post(
                f"{BASE_URL}/api/v1/instagram/userInfo",
                json=payload
            )
            
            response.raise_for_status()
            data = response.json()
            
            # 解析用户信息
            user_data = None
            if data and isinstance(data, dict):
                # 尝试多种可能的数据结构
                user = None
                
                # 结构1: { result: [{user: {...}, status: ...}] } - result 是列表
                if "result" in data:
                    result = data.get("result")
                    if isinstance(result, list) and len(result) > 0:
                        # result[0] 可能包含 user 键
                        first_result = result[0]
                        if isinstance(first_result, dict):
                            user = first_result.get("user", first_result)
                    elif isinstance(result, dict):
                        user = result.get("user", {}) or result
                
                # 结构2: { data: { user: {...} } }
                if not user and "data" in data:
                    sub_data = data.get("data", {})
                    if isinstance(sub_data, dict):
                        user = sub_data.get("user", {})
                
                # 结构3: { user: {...} }
                if not user:
                    user = data.get("user", {})
                
                if user and isinstance(user, dict):
                    user_data = InstagramUser(
                        id=user.get("id") or user.get("pk"),
                        username=user.get("username"),
                        full_name=user.get("full_name"),
                        biography=user.get("biography"),
                        profile_pic_url=user.get("profile_pic_url"),
                        profile_pic_url_hd=user.get("profile_pic_url_hd") or user.get("hd_profile_pic_url_info", {}).get("url"),
                        follower_count=user.get("edge_followed_by", {}).get("count") or user.get("follower_count"),
                        following_count=user.get("edge_follow", {}).get("count") or user.get("following_count"),
                        media_count=user.get("edge_owner_to_timeline_media", {}).get("count") or user.get("media_count"),
                        is_private=user.get("is_private"),
                        is_verified=user.get("is_verified"),
                        external_url=user.get("external_url")
                    )
            
            return UserInfoResponse(
                success=True,
                data=user_data,
                raw_response=data
            )
            
        except Exception as e:
            # curl_cffi 异常处理
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
            return UserInfoResponse(
                success=False,
                error=error_msg
            )
    
    async def get_posts(
        self, 
        username: str, 
        max_id: str = ""
    ) -> PostsResponse:
        """
        获取用户帖子列表
        
        Args:
            username: Instagram 用户名
            max_id: 分页游标，用于加载更多帖子
        
        Returns:
            帖子列表响应
        
        Example:
            >>> async with InstagramAPIClient() as client:
            ...     resp = await client.get_posts("jaychou")
            ...     for post in resp.posts:
            ...         print(post.get("shortcode"))
        """
        try:
            client = self._get_client()
            
            # 构建请求体
            payload = self._create_signed_payload({
                "maxId": max_id,
                "username": username
            })
            
            # 发送请求
            response = await client.post(
                f"{BASE_URL}/api/v1/instagram/postsV2",
                json=payload
            )
            
            response.raise_for_status()
            data = response.json()
            
            # 解析帖子列表
            posts = []
            next_max_id = None
            has_more = False
            
            if data and isinstance(data, dict):
                items = []
                
                # 结构1: { result: { items: [...] } }
                if "result" in data:
                    result = data.get("result", {})
                    if isinstance(result, dict):
                        items = result.get("items", []) or result.get("edges", [])
                        next_max_id = result.get("next_max_id") or result.get("end_cursor")
                
                # 结构2: { data: { items: [...] } }
                if not items and "data" in data:
                    sub_data = data.get("data", {})
                    if isinstance(sub_data, dict):
                        items = sub_data.get("items", [])
                        next_max_id = sub_data.get("next_max_id")
                
                # 结构3: { items: [...] }
                if not items:
                    items = data.get("items", [])
                    next_max_id = next_max_id or data.get("next_max_id")
                
                posts = items
                has_more = bool(next_max_id)
            
            return PostsResponse(
                success=True,
                posts=posts,
                next_max_id=next_max_id,
                has_more=has_more,
                raw_response=data
            )
            
        except Exception as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
            return PostsResponse(
                success=False,
                error=error_msg
            )
    
    async def get_post_detail(self, url: str) -> PostDetailResponse:
        """
        获取帖子详情
        
        Args:
            url: Instagram 帖子 URL
        
        Returns:
            帖子详情响应
        
        Example:
            >>> async with InstagramAPIClient() as client:
            ...     resp = await client.get_post_detail("https://www.instagram.com/p/xxxxx/")
            ...     print(resp.data)
        """
        try:
            client = self._get_client()
            
            # 构建表单数据
            form_data = self._create_signed_form(url)
            
            # 发送请求
            response = await client.post(
                f"{BASE_URL}/api/convert",
                data=form_data,
                headers={"content-type": "application/x-www-form-urlencoded;charset=UTF-8"}
            )
            
            response.raise_for_status()
            data = response.json()
            
            return PostDetailResponse(
                success=True,
                data=data,
                raw_response=data
            )
            
        except Exception as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
            return PostDetailResponse(
                success=False,
                error=error_msg
            )


# ============================================================
# 便捷函数
# ============================================================

async def get_instagram_user(username: str) -> UserInfoResponse:
    """
    便捷函数: 获取用户信息
    
    Args:
        username: Instagram 用户名
    
    Returns:
        用户信息响应
    """
    async with InstagramAPIClient() as client:
        return await client.get_user_info(username)


async def get_instagram_posts(username: str, max_id: str = "") -> PostsResponse:
    """
    便捷函数: 获取帖子列表
    
    Args:
        username: Instagram 用户名
        max_id: 分页游标
    
    Returns:
        帖子列表响应
    """
    async with InstagramAPIClient() as client:
        return await client.get_posts(username, max_id)


async def get_instagram_post_detail(url: str) -> PostDetailResponse:
    """
    便捷函数: 获取帖子详情
    
    Args:
        url: Instagram 帖子 URL
    
    Returns:
        帖子详情响应
    """
    async with InstagramAPIClient() as client:
        return await client.get_post_detail(url)


# ============================================================
# 测试代码
# ============================================================

if __name__ == "__main__":
    import asyncio
    
    async def test():
        print("=" * 60)
        print("Instagram API 客户端测试")
        print("=" * 60)
        
        # 测试签名生成
        print("\n1. 测试签名生成")
        test_data = '{"username":"jaychou"}'
        test_ts = 1768448262037
        sig = generate_signature(test_data, test_ts)
        print(f"   数据: {test_data}")
        print(f"   时间戳: {test_ts}")
        print(f"   签名: {sig}")
        
        # 验证签名长度
        assert len(sig) == 64, f"签名长度应为64，实际为{len(sig)}"
        print("   ✓ 签名长度验证通过")
        
        # 测试用户信息接口
        print("\n2. 测试用户信息接口")
        async with InstagramAPIClient() as client:
            # 构建请求体预览
            payload = client._create_signed_payload({"username": "jaychou"})
            print(f"   请求体: {json.dumps(payload, indent=2)}")
            
            # 实际请求 (注释掉以避免真实 API 调用)
            # resp = await client.get_user_info("jaychou")
            # print(f"   响应: {resp}")
        
        print("\n" + "=" * 60)
        print("测试完成!")
        print("=" * 60)
    
    asyncio.run(test())
