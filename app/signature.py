"""
签名生成模块

实现 _s 签名算法,用于生成 API 请求的签名。

签名算法:
_s = HMAC-SHA256(secret_key_bytes, data + timestamp)

其中:
- secret_key_bytes: 从加密 blob 解码的密钥 (hex 转 bytes)
- data: 请求数据 (URL 字符串或 JSON 序列化的对象)
- timestamp: 时间戳 (毫秒)
"""

import hashlib
import hmac
import json
import time
from typing import Union, Dict, Any, Optional

from .secret_decoder import decode_secret_from_blob, get_default_secret


def sort_object_keys(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    按字母顺序排序对象的键
    
    递归处理嵌套对象。
    
    Args:
        obj: 输入字典
    
    Returns:
        键已排序的字典
    """
    if not isinstance(obj, dict):
        return obj
    
    result = {}
    for key in sorted(obj.keys()):
        value = obj[key]
        if isinstance(value, dict):
            result[key] = sort_object_keys(value)
        else:
            result[key] = value
    return result


def sha256_hash(data: str) -> str:
    """
    计算字符串的 SHA-256 哈希值
    
    Args:
        data: 输入字符串
    
    Returns:
        十六进制格式的哈希值 (64个字符)
    """
    encoded = data.encode('utf-8')
    hash_bytes = hashlib.sha256(encoded).digest()
    return hash_bytes.hex()


def hmac_sha256_sign(message: str, secret_key: str) -> str:
    """
    使用 HMAC-SHA256 签名
    
    Args:
        message: 待签名消息
        secret_key: 十六进制密钥字符串 (64 字符 = 32 字节)
    
    Returns:
        十六进制格式的签名 (64个字符)
    """
    key_bytes = bytes.fromhex(secret_key)
    return hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).hexdigest()


async def generate_signature(
    request_data: Union[str, Dict[str, Any]],
    timestamp: int,
    secret_key: str
) -> str:
    """
    生成 API 请求签名
    
    这是核心签名函数,实现了 JavaScript 中的签名生成逻辑。
    
    签名计算公式:
    _s = HMAC-SHA256(secret_key_bytes, data_string + timestamp)
    
    Args:
        request_data: 请求数据
            - 字符串: 直接使用 (通常是 URL)
            - 字典: 先按键排序后 JSON 序列化
        timestamp: 时间戳 (毫秒)
        secret_key: 解密后的密钥 (十六进制字符串)
    
    Returns:
        64位十六进制签名字符串
    """
    # 根据数据类型处理
    if isinstance(request_data, str):
        data_string = request_data
    else:
        # 对象需要按键排序后序列化
        sorted_data = sort_object_keys(request_data)
        data_string = json.dumps(sorted_data, separators=(',', ':'), ensure_ascii=False)
    
    # 签名消息: data + timestamp
    message = f"{data_string}{timestamp}"
    
    # 计算 HMAC-SHA256
    return hmac_sha256_sign(message, secret_key)


def generate_signature_sync(
    request_data: Union[str, Dict[str, Any]],
    timestamp: int,
    secret_key: str
) -> str:
    """
    同步版本的签名生成函数
    
    功能与 generate_signature 完全相同,但是同步执行。
    
    Args:
        request_data: 请求数据 (字符串或字典)
        timestamp: 时间戳 (毫秒)
        secret_key: 解密后的密钥 (十六进制字符串)
    
    Returns:
        64位十六进制签名字符串
    """
    if isinstance(request_data, str):
        data_string = request_data
    else:
        sorted_data = sort_object_keys(request_data)
        data_string = json.dumps(sorted_data, separators=(',', ':'), ensure_ascii=False)
    
    message = f"{data_string}{timestamp}"
    return hmac_sha256_sign(message, secret_key)


class SignatureGenerator:
    """
    签名生成器类
    
    封装了密钥解码和签名生成的完整流程。
    支持时间校正功能。
    
    Attributes:
        secret_key: 解密后的密钥
        time_offset: 时间偏移量 (毫秒), 用于校正客户端与服务器时间差
    
    Example:
        >>> generator = SignatureGenerator()
        >>> signed_body = await generator.create_signed_request({"sf_url": "/api/user"})
    """
    
    def __init__(
        self,
        encrypted_data: Optional[str] = None,
        custom_alphabet: Optional[str] = None,
        time_offset: int = 0
    ):
        """
        初始化签名生成器
        
        Args:
            encrypted_data: 加密的 blob 数据 (默认使用预配置值)
            custom_alphabet: 自定义 Base64 字母表 (默认使用预配置值)
            time_offset: 时间偏移量 (毫秒)
        """
        if encrypted_data and custom_alphabet:
            self.secret_key = decode_secret_from_blob(encrypted_data, custom_alphabet)
        else:
            self.secret_key = get_default_secret()
        
        self.time_offset = time_offset
    
    def set_time_offset(self, offset: int):
        """
        设置时间偏移量
        
        用于校正客户端时间与服务器时间的差异。
        
        Args:
            offset: 时间偏移量 (毫秒), 正值表示客户端快于服务器
        """
        self.time_offset = offset
    
    def get_corrected_timestamp(self) -> int:
        """
        获取校正后的时间戳
        
        Returns:
            校正后的毫秒时间戳
        """
        return int(time.time() * 1000) - self.time_offset
    
    async def generate_signature(
        self,
        request_data: Union[str, Dict[str, Any]],
        timestamp: Optional[int] = None
    ) -> str:
        """
        生成请求签名
        
        Args:
            request_data: 请求数据
            timestamp: 可选的时间戳 (默认使用当前校正后的时间)
        
        Returns:
            签名字符串
        """
        if timestamp is None:
            timestamp = self.get_corrected_timestamp()
        
        return await generate_signature(request_data, timestamp, self.secret_key)
    
    async def create_signed_request(
        self,
        request_data: Union[str, Dict[str, Any]],
        timestamp_key: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        创建带签名的请求体
        
        返回的请求体包含:
        - 原始请求数据 (如果是字典则展开)
        - ts: 时间戳
        - _ts: 时间校正基准
        - _tsc: 时间偏移量
        - _s: 签名
        
        Args:
            request_data: 原始请求数据
            timestamp_key: 可选的指定时间戳
        
        Returns:
            带签名的完整请求体
        """
        timestamp = timestamp_key or self.get_corrected_timestamp()
        signature = await self.generate_signature(request_data, timestamp)
        
        # 构建请求体
        if isinstance(request_data, str):
            result = {"sf_url": request_data}
        else:
            result = dict(request_data)
        
        # 添加签名相关字段
        result.update({
            "ts": timestamp,
            "_ts": int(time.time() * 1000),  # 构建时间戳
            "_tsc": self.time_offset,
            "_sv": 2,
            "_s": signature
        })
        
        return result


# 全局默认签名生成器实例
_default_generator: Optional[SignatureGenerator] = None


def get_default_generator() -> SignatureGenerator:
    """
    获取默认的签名生成器实例
    
    使用懒加载模式,首次调用时初始化。
    
    Returns:
        SignatureGenerator 实例
    """
    global _default_generator
    if _default_generator is None:
        _default_generator = SignatureGenerator()
    return _default_generator


async def create_signed_request(
    request_data: Union[str, Dict[str, Any]],
    time_offset: int = 0
) -> Dict[str, Any]:
    """
    便捷函数: 创建带签名的请求体
    
    Args:
        request_data: 请求数据
        time_offset: 时间偏移量
    
    Returns:
        带签名的请求体
    """
    generator = get_default_generator()
    generator.set_time_offset(time_offset)
    return await generator.create_signed_request(request_data)
