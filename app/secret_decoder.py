"""
密钥解码模块

实现 decodeSecretFromBlob 函数,从加密的 blob 中解码出密钥。

Blob 格式说明:
- 字节 0: 版本号 (必须为 1)
- 字节 1: 分块数量
- 对于每个分块:
    - 1 字节: preOps 操作数量
    - N * 2 字节: preOps 操作列表 (每个操作 2 字节: [操作ID, 参数])
    - 1 字节: b64Ops 操作数量
    - M * 2 字节: b64Ops 操作列表
    - 2 字节: 加密数据长度 (大端序)
    - L 字节: 加密数据
"""

from typing import List, Tuple, Dict, Any
from .crypto_utils import (
    map_custom_to_std_b64,
    decode_base64_to_bytes,
    bytes_to_string,
    invert_ops
)


def parse_blob(data: bytes) -> List[Dict[str, Any]]:
    """
    解析加密 blob 数据
    
    Args:
        data: 解码后的字节数组
    
    Returns:
        分块列表, 每个分块包含:
        - preOps: 预处理操作列表
        - b64Ops: Base64 操作列表
        - enc: 加密的数据字符串
    
    Raises:
        ValueError: blob 格式无效
    """
    pos = 0
    
    # 读取版本号
    version = data[pos]
    pos += 1
    
    # 读取分块数量
    chunk_count = data[pos]
    pos += 1
    
    # 验证版本号
    if version != 1 or not chunk_count:
        raise ValueError("Invalid signing blob")
    
    chunks = []
    
    for _ in range(chunk_count):
        # 读取 preOps
        pre_ops_count = data[pos]
        pos += 1
        
        pre_ops = []
        for _ in range(pre_ops_count):
            op_id = data[pos]
            op_param = data[pos + 1]
            pos += 2
            pre_ops.append((op_id, op_param))
        
        # 读取 b64Ops
        b64_ops_count = data[pos]
        pos += 1
        
        b64_ops = []
        for _ in range(b64_ops_count):
            op_id = data[pos]
            op_param = data[pos + 1]
            pos += 2
            b64_ops.append((op_id, op_param))
        
        # 读取加密数据长度 (大端序)
        enc_length = (data[pos] << 8) | data[pos + 1]
        pos += 2
        
        # 读取加密数据
        enc_data = bytes_to_string(data, pos, enc_length)
        pos += enc_length
        
        chunks.append({
            "preOps": pre_ops,
            "b64Ops": b64_ops,
            "enc": enc_data
        })
    
    return chunks


def decode_chunk(chunk: Dict[str, Any], custom_alphabet: str) -> str:
    """
    解码单个分块
    
    解码流程:
    1. 对加密数据执行 b64Ops 逆操作
    2. 将自定义 Base64 转换为标准 Base64
    3. 解码 Base64 为字节
    4. 将字节转换为 UTF-8 字符串
    5. 对解密后的数据执行 preOps 逆操作
    
    Args:
        chunk: 分块数据 (包含 preOps, b64Ops, enc)
        custom_alphabet: 自定义 Base64 字母表
    
    Returns:
        解码后的明文字符串
    """
    enc_data = chunk["enc"]
    pre_ops = chunk["preOps"]
    b64_ops = chunk["b64Ops"]
    
    # 步骤 1: 执行 b64Ops 逆操作
    b64_transformed = invert_ops(enc_data, b64_ops)
    
    # 步骤 2: 自定义 Base64 -> 标准 Base64
    std_b64 = map_custom_to_std_b64(b64_transformed, custom_alphabet)
    
    # 步骤 3: Base64 解码
    decoded_bytes = decode_base64_to_bytes(std_b64)
    
    # 步骤 4: UTF-8 解码
    utf8_string = decoded_bytes.decode('utf-8')
    
    # 步骤 5: 执行 preOps 逆操作
    result = invert_ops(utf8_string, pre_ops)
    
    return result


def decode_secret_from_blob(encrypted_data: str, custom_alphabet: str) -> str:
    """
    从加密的 blob 中解码密钥
    
    这是主要的解密函数,完整实现了 JavaScript 中的 decodeSecretFromBlob 函数。
    
    工作流程:
    1. 将自定义 Base64 编码的数据转换为标准 Base64
    2. Base64 解码获取原始字节
    3. 解析 blob 格式,提取操作列表和加密数据
    4. 对每个分块执行解密操作
    5. 拼接所有解密后的分块
    
    Args:
        encrypted_data: 加密的 blob 数据 (自定义 Base64 编码)
        custom_alphabet: 自定义 Base64 字母表 (64个字符)
    
    Returns:
        解密后的密钥字符串
    
    Example:
        >>> encrypted = "0E6V0eR4c0VG0e6000VV..."
        >>> alphabet = "05c4LAGfVl9d6pkOEQ1o8r+wz7FgRUTHeJqKDythXn3YSvBMsPjaiN2ub/CIWZmx"
        >>> secret = decode_secret_from_blob(encrypted, alphabet)
    """
    # 步骤 1: 自定义 Base64 -> 标准 Base64
    std_b64 = map_custom_to_std_b64(encrypted_data, custom_alphabet)
    
    # 步骤 2: Base64 解码
    blob_bytes = decode_base64_to_bytes(std_b64)
    
    # 步骤 3: 解析 blob
    chunks = parse_blob(blob_bytes)
    
    # 步骤 4-5: 解密每个分块并拼接
    result_parts = []
    for chunk in chunks:
        decoded = decode_chunk(chunk, custom_alphabet)
        result_parts.append(decoded)
    
    return "".join(result_parts)


# 预配置的加密数据和字母表 (来自 link.chunk.js)
DEFAULT_ENCRYPTED_DATA = (
    "0E6V0eR4c0VG0e6000VV0ER45sDc5EAk0e80006L00051sLM0Eb0zfQC8GSi8hpYQulPRLv6FK7d"
    "1DQspLAdRfEu1Kzi64V2gNlkpuQQ1K7igfLug2PPpaQrQf5MoGX2gt741hrnptA/pfnJpaEuTw5A"
    "gwlbTh82z+PPRGAydazYTh6ugiQNTeX45EVG0005c06A000c0EVc0ez40ez4506G0eL5zs650eV0"
    "ohQDFw5dQr0u1unERGW26K7dptlYpLrJF2ZSU47iThrYga5JptZ+Fh5M6GnLz8VuFALio8vjgKzY"
    "ofrsgiAdTDSNQ4zYrtnszoU/TtZ1r0S5As6L0eRc5sL401i5+e000sV40EVccE000005As000e8c"
    "5ELc0oW0005AQ4zi7w82zoU9pqSbdunMRfE2zr7ERLSszKzi71W2QaJsginLFaEsUoUdRDvsQN7E"
    "ptAAFh0i7+AsT45aEolnRNVjpivs"
)

DEFAULT_CUSTOM_ALPHABET = "05c4LAGfVl9d6pkOEQ1o8r+wz7FgRUTHeJqKDythXn3YSvBMsPjaiN2ub/CIWZmx"


def get_default_secret() -> str:
    """
    获取默认的解密密钥
    
    使用预配置的加密数据和字母表解密密钥。
    
    Returns:
        解密后的密钥
    """
    return decode_secret_from_blob(DEFAULT_ENCRYPTED_DATA, DEFAULT_CUSTOM_ALPHABET)
