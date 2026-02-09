"""
JS 密钥提取模块

自动从远程 JS 文件中提取加密密钥。

功能:
1. 下载远程 JS 文件
2. 使用 Node.js deobfuscator 解混淆
3. 使用正则表达式提取加密数据和自定义字母表
4. 解密得到密钥
"""

import re
import os
import subprocess
import tempfile
import hashlib
import json
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from datetime import datetime
import asyncio

import httpx

from .secret_decoder import decode_secret_from_blob


# ==================== 配置 ====================

# 远程 JS 文件基础 URL
JS_BASE_URL = "https://anonyig.com/js/link.chunk.js"

# deobfuscator 脚本路径 (相对于项目根目录)
DEOBFUSCATOR_SCRIPT = "deobfuscator-v4.js"

# 密钥缓存文件
KEY_CACHE_FILE = "key_cache.json"

# 提取加密数据的正则表达式模式
# 模式1: 在反混淆后的代码中查找
ENCRYPTED_DATA_PATTERN = r'=\s*"(0E6V[A-Za-z0-9+/=]{300,})"\s*;'
CUSTOM_ALPHABET_PATTERN = r'=\s*"([A-Za-z0-9+/]{64})"\s*;'

# 备选模式: 匹配连续两个字符串赋值 (加密数据后紧跟字母表)
PAIR_PATTERN = r'"(0E6V[A-Za-z0-9+/=]{300,})"[^"]*"([A-Za-z0-9+/]{64})"'

# v4 反混淆输出专用模式 (基于 decodeSecretFromBlob 锚点)
# 加密 blob: 200+ 字符的 base64-like 字符串
V4_BLOB_PATTERN = r'=\s*"([A-Za-z0-9+/]{200,})"'
# 自定义字母表: 恰好 64 字符的 base64 字母表
V4_ALPHABET_PATTERN = r'=\s*"([A-Za-z0-9+/]{64})"'
# 密钥片段数组: ["xxx", "yyy", "zzz"] (2-5 字符的短字符串)
V4_KEY_PARTS_PATTERN = r'=\s*\["([a-z0-9]{2,5})",\s*"([a-z0-9]{2,5})",\s*"([a-z0-9]{2,5})"\]'
# 索引数组: [n, n, n] (0-2 的排列)
V4_INDEX_PATTERN = r'=\s*\[(\d),\s*(\d),\s*(\d)\]'


# ==================== 工具函数 ====================

def get_project_root() -> Path:
    """获取项目根目录"""
    return Path(__file__).parent.parent


def get_cache_path() -> Path:
    """获取缓存文件路径"""
    return get_project_root() / "app" / KEY_CACHE_FILE


def calculate_js_hash(content: str) -> str:
    """计算 JS 内容的 MD5 哈希"""
    return hashlib.md5(content.encode()).hexdigest()


# ==================== JS 下载 ====================

async def download_js_file(url: str, ch_param: Optional[str] = None) -> str:
    """
    下载远程 JS 文件
    
    Args:
        url: JS 文件 URL
        ch_param: 可选的 ch 参数 (如 "2fcb0a2062d7bec7.js")
    
    Returns:
        JS 文件内容
    
    Raises:
        httpx.HTTPError: 网络请求失败
    """
    if ch_param:
        full_url = f"{url}?ch={ch_param}"
    else:
        full_url = url
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(full_url, follow_redirects=True)
        response.raise_for_status()
        return response.text


def download_js_file_sync(url: str, ch_param: Optional[str] = None) -> str:
    """同步版本的 JS 下载函数"""
    if ch_param:
        full_url = f"{url}?ch={ch_param}"
    else:
        full_url = url
    
    with httpx.Client(timeout=30.0) as client:
        response = client.get(full_url, follow_redirects=True)
        response.raise_for_status()
        return response.text


# ==================== JS 解混淆 ====================

def run_deobfuscator(js_content: str, output_dir: Optional[Path] = None) -> str:
    """
    使用 Node.js deobfuscator 解混淆 JS 代码
    
    Args:
        js_content: 原始 JS 代码
        output_dir: 输出目录 (默认使用临时目录)
    
    Returns:
        解混淆后的 JS 代码
    
    Raises:
        RuntimeError: deobfuscator 执行失败
    """
    project_root = get_project_root()
    deobfuscator_path = project_root / DEOBFUSCATOR_SCRIPT
    
    if not deobfuscator_path.exists():
        raise FileNotFoundError(f"Deobfuscator not found: {deobfuscator_path}")
    
    # 使用临时目录
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp())
    
    input_file = output_dir / "input.js"
    output_file = output_dir / "input_deobfuscated_v4.js"
    
    # 写入输入文件
    input_file.write_text(js_content, encoding='utf-8')
    
    try:
        # 运行 deobfuscator
        # 使用 UTF-8 编码避免 Windows GBK 编码问题
        result = subprocess.run(
            ["node", str(deobfuscator_path), str(input_file)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',  # 替换无法解码的字符
            timeout=120
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Deobfuscator failed: {result.stderr}")
        
        # 读取输出
        if not output_file.exists():
            # 尝试其他可能的输出文件名
            possible_outputs = list(output_dir.glob("*_deobfuscated*.js"))
            if possible_outputs:
                output_file = possible_outputs[0]
            else:
                raise RuntimeError("Deobfuscator output file not found")
        
        return output_file.read_text(encoding='utf-8')
        
    finally:
        # 清理临时文件
        if output_dir and output_dir.exists():
            import shutil
            try:
                shutil.rmtree(output_dir)
            except:
                pass


# ==================== LZString 解压 ====================

def lz_decompress_from_utf16(input_str: str) -> Optional[str]:
    """
    LZString decompressFromUTF16 的 Python 实现
    
    Args:
        input_str: UTF16 压缩的字符串
    
    Returns:
        解压后的字符串，失败返回 None
    """
    if not input_str:
        return ""
    
    dictionary = {}
    enlargeIn = 4
    dictSize = 4
    numBits = 3
    result = []
    
    data = {
        'val': ord(input_str[0]) - 32,
        'position': 16384,
        'index': 1
    }
    
    for i in range(3):
        dictionary[i] = i
    
    # 读取前两位确定第一个字符的类型
    bits = 0
    maxpower = 4
    power = 1
    
    while power != maxpower:
        resb = data['val'] & data['position']
        data['position'] >>= 1
        if data['position'] == 0:
            data['position'] = 16384
            if data['index'] < len(input_str):
                data['val'] = ord(input_str[data['index']]) - 32
                data['index'] += 1
            else:
                data['val'] = 0
        bits |= (1 if resb > 0 else 0) * power
        power <<= 1
    
    if bits == 0:
        bits = 0
        maxpower = 256
        power = 1
        while power != maxpower:
            resb = data['val'] & data['position']
            data['position'] >>= 1
            if data['position'] == 0:
                data['position'] = 16384
                if data['index'] < len(input_str):
                    data['val'] = ord(input_str[data['index']]) - 32
                    data['index'] += 1
            bits |= (1 if resb > 0 else 0) * power
            power <<= 1
        c = chr(bits)
    elif bits == 1:
        bits = 0
        maxpower = 65536
        power = 1
        while power != maxpower:
            resb = data['val'] & data['position']
            data['position'] >>= 1
            if data['position'] == 0:
                data['position'] = 16384
                if data['index'] < len(input_str):
                    data['val'] = ord(input_str[data['index']]) - 32
                    data['index'] += 1
            bits |= (1 if resb > 0 else 0) * power
            power <<= 1
        c = chr(bits)
    elif bits == 2:
        return ""
    
    dictionary[3] = c
    w = c
    result.append(c)
    
    while True:
        if data['index'] > len(input_str):
            return ""
        
        bits = 0
        maxpower = 2 ** numBits
        power = 1
        
        while power != maxpower:
            resb = data['val'] & data['position']
            data['position'] >>= 1
            if data['position'] == 0:
                data['position'] = 16384
                if data['index'] < len(input_str):
                    data['val'] = ord(input_str[data['index']]) - 32
                    data['index'] += 1
                else:
                    data['val'] = 0
            bits |= (1 if resb > 0 else 0) * power
            power <<= 1
        
        c = bits
        
        if c == 0:
            bits = 0
            maxpower = 256
            power = 1
            while power != maxpower:
                resb = data['val'] & data['position']
                data['position'] >>= 1
                if data['position'] == 0:
                    data['position'] = 16384
                    if data['index'] < len(input_str):
                        data['val'] = ord(input_str[data['index']]) - 32
                        data['index'] += 1
                bits |= (1 if resb > 0 else 0) * power
                power <<= 1
            dictionary[dictSize] = chr(bits)
            dictSize += 1
            c = dictSize - 1
            enlargeIn -= 1
        elif c == 1:
            bits = 0
            maxpower = 65536
            power = 1
            while power != maxpower:
                resb = data['val'] & data['position']
                data['position'] >>= 1
                if data['position'] == 0:
                    data['position'] = 16384
                    if data['index'] < len(input_str):
                        data['val'] = ord(input_str[data['index']]) - 32
                        data['index'] += 1
                bits |= (1 if resb > 0 else 0) * power
                power <<= 1
            dictionary[dictSize] = chr(bits)
            dictSize += 1
            c = dictSize - 1
            enlargeIn -= 1
        elif c == 2:
            return "".join(result)
        
        if enlargeIn == 0:
            enlargeIn = 2 ** numBits
            numBits += 1
        
        if c in dictionary:
            entry = dictionary[c]
        else:
            if c == dictSize:
                entry = w + w[0]
            else:
                return None
        
        result.append(entry)
        dictionary[dictSize] = w + entry[0]
        dictSize += 1
        enlargeIn -= 1
        
        if enlargeIn == 0:
            enlargeIn = 2 ** numBits
            numBits += 1
        
        w = entry
    
    return "".join(result)


# ==================== 密钥提取 (v4 反混淆输出) ====================

def extract_from_v4_output(content: str) -> Optional[Dict[str, Any]]:
    """
    从 v4 反混淆输出中提取所有密钥数据
    
    v4 反混淆器将所有混淆层完全还原，关键数据以明文出现在 decodeSecretFromBlob 附近:
    - 加密 blob (300+ 字符的 base64-like 字符串)
    - 自定义字母表 (64 字符)
    - 密钥片段数组 (3 个短字符串, 用于计算 _ts)
    - 索引数组 (3 个数字, 用于确定片段拼接顺序)
    
    Args:
        content: v4 反混淆后的 JS 代码
    
    Returns:
        包含 encrypted_data, custom_alphabet, fixed_ts 的字典，失败返回 None
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # 以 decodeSecretFromBlob 为锚点 (使用最后一次出现，即实际使用位置)
    anchor_idx = content.rfind('decodeSecretFromBlob')
    if anchor_idx < 0:
        logger.debug("v4 extraction: decodeSecretFromBlob not found")
        return None
    
    # 在锚点前 3000 字符范围内搜索
    search_start = max(0, anchor_idx - 3000)
    search_region = content[search_start:anchor_idx + 200]
    
    # 1. 提取加密 blob (200+ 字符的 base64-like 字符串)
    blob_match = re.search(V4_BLOB_PATTERN, search_region)
    if not blob_match:
        logger.debug("v4 extraction: encrypted blob not found")
        return None
    encrypted_data = blob_match.group(1)
    logger.info(f"v4 extraction: found encrypted blob ({len(encrypted_data)} chars)")
    
    # 2. 提取自定义字母表 (恰好 64 字符)
    # 需要避免匹配 blob 的前 64 字符，所以从 blob 之后开始搜索
    blob_end = blob_match.end()
    alphabet_region = search_region[blob_end - search_start:] if blob_end > search_start else search_region
    alphabet_match = re.search(V4_ALPHABET_PATTERN, alphabet_region)
    if not alphabet_match:
        # 退而求其次，在整个区域搜索
        for m in re.finditer(V4_ALPHABET_PATTERN, search_region):
            candidate = m.group(1)
            if candidate not in encrypted_data:
                alphabet_match = m
                break
    
    if not alphabet_match:
        logger.debug("v4 extraction: custom alphabet not found")
        return None
    custom_alphabet = alphabet_match.group(1)
    logger.info(f"v4 extraction: found custom alphabet: {custom_alphabet[:20]}...")
    
    # 验证字母表: 应包含 64 个不重复的字符
    if len(set(custom_alphabet)) != 64:
        logger.warning(f"v4 extraction: alphabet has {len(set(custom_alphabet))} unique chars, expected 64")
    
    # 3. 提取密钥片段数组
    parts_match = re.search(V4_KEY_PARTS_PATTERN, search_region)
    if not parts_match:
        logger.debug("v4 extraction: key parts array not found")
        return {
            "encrypted_data": encrypted_data,
            "custom_alphabet": custom_alphabet,
            "fixed_ts": None
        }
    key_parts = [parts_match.group(1), parts_match.group(2), parts_match.group(3)]
    logger.info(f"v4 extraction: found key parts: {key_parts}")
    
    # 4. 提取索引数组
    idx_match = re.search(V4_INDEX_PATTERN, search_region)
    if not idx_match:
        logger.debug("v4 extraction: index array not found")
        return {
            "encrypted_data": encrypted_data,
            "custom_alphabet": custom_alphabet,
            "fixed_ts": None
        }
    indices = [int(idx_match.group(1)), int(idx_match.group(2)), int(idx_match.group(3))]
    logger.info(f"v4 extraction: found indices: {indices}")
    
    # 5. 计算 _ts (构建时间戳)
    # 公式: parseInt(key_parts[indices[0]] + key_parts[indices[1]] + key_parts[indices[2]], 36)
    combined = ""
    for idx in indices:
        if 0 <= idx < len(key_parts):
            combined += key_parts[idx]
        else:
            logger.warning(f"v4 extraction: index {idx} out of range for key_parts")
            return {
                "encrypted_data": encrypted_data,
                "custom_alphabet": custom_alphabet,
                "fixed_ts": None
            }
    
    try:
        fixed_ts = int(combined, 36)
        logger.info(f"v4 extraction: computed _ts = {fixed_ts} (from '{combined}' base36)")
    except ValueError:
        logger.warning(f"v4 extraction: failed to parse '{combined}' as base36")
        fixed_ts = None
    
    return {
        "encrypted_data": encrypted_data,
        "custom_alphabet": custom_alphabet,
        "key_parts": key_parts,
        "indices": indices,
        "fixed_ts": fixed_ts
    }


# ==================== 密钥提取 (旧格式兼容) ====================

def extract_key_data_from_lzstring(content: str) -> Optional[Tuple[str, str]]:
    """
    从使用 LZString 压缩的 JS 代码中提取加密数据
    
    新格式的 JS 将常量压缩在 UTF16 字符串中，需要先解压再提取。
    
    Args:
        content: 解混淆后的 JS 代码
    
    Returns:
        (encrypted_data, custom_alphabet) 元组，失败返回 None
    """
    # 查找 LZString 压缩字符串
    match = re.search(r'var LcSqQ8 = "(.+?)"\s*,\s*Cn7qVG', content, re.DOTALL)
    if not match:
        return None
    
    compressed = match.group(1)
    
    try:
        decompressed = lz_decompress_from_utf16(compressed)
        if not decompressed:
            return None
        
        arr = decompressed.split("|")
        
        # 加密数据在索引 490-496 + "M"，字母表在索引 497-501
        if len(arr) <= 501:
            return None
        
        # 组合加密数据: arr[490] + arr[491] + ... + arr[496] + "M"
        encrypted_data = "".join([arr[i] for i in range(490, 497)]) + "M"
        
        # 组合字母表: arr[497] + arr[498] + ... + arr[501]
        custom_alphabet = "".join([arr[i] for i in range(497, 502)])
        
        # 验证
        if len(encrypted_data) > 100 and len(custom_alphabet) == 64:
            return encrypted_data, custom_alphabet
        
        return None
        
    except Exception:
        return None


def extract_fixed_ts_from_lzstring(content: str) -> Optional[int]:
    """
    从使用 LZString 压缩的 JS 代码中提取 _ts 固定值
    
    _ts 是通过 agr9Oid 和 pX5BgRt 数组计算得出的。
    计算公式: parseInt(agr9Oid[0] + agr9Oid[2] + agr9Oid[1], 36)
    其中 agr9Oid = ["mk", arr[502], arr[503]]
    
    Args:
        content: 解混淆后的 JS 代码
    
    Returns:
        _ts 值，失败返回 None
    """
    match = re.search(r'var LcSqQ8 = "(.+?)"\s*,\s*Cn7qVG', content, re.DOTALL)
    if not match:
        return None
    
    compressed = match.group(1)
    
    try:
        decompressed = lz_decompress_from_utf16(compressed)
        if not decompressed:
            return None
        
        arr = decompressed.split("|")
        
        if len(arr) <= 503:
            return None
        
        # agr9Oid = ["mk", arr[502], arr[503]]
        # pX5BgRt = [0, 2, 1]
        # combined = agr9Oid[0] + agr9Oid[2] + agr9Oid[1] = "mk" + arr[503] + arr[502]
        agr9Oid = ["mk", arr[502], arr[503]]
        combined = agr9Oid[0] + agr9Oid[2] + agr9Oid[1]
        
        return int(combined, 36)
        
    except Exception:
        return None


def extract_key_data_from_deobfuscated(content: str) -> Tuple[str, str]:
    """
    从解混淆后的 JS 代码中提取加密数据和自定义字母表
    
    Args:
        content: 解混淆后的 JS 代码
    
    Returns:
        (encrypted_data, custom_alphabet) 元组
    
    Raises:
        ValueError: 无法提取数据
    """
    # 方法 0: v4 反混淆输出格式 (推荐，最可靠)
    v4_result = extract_from_v4_output(content)
    if v4_result and v4_result.get("encrypted_data") and v4_result.get("custom_alphabet"):
        return v4_result["encrypted_data"], v4_result["custom_alphabet"]
    
    # 方法 1: 尝试 LZString 压缩格式
    lz_result = extract_key_data_from_lzstring(content)
    if lz_result:
        return lz_result
    
    # 方法 2: 尝试配对模式 (旧格式)
    pair_match = re.search(PAIR_PATTERN, content)
    if pair_match:
        encrypted_data = pair_match.group(1)
        custom_alphabet = pair_match.group(2)
        
        # 验证
        if len(encrypted_data) > 300 and len(custom_alphabet) == 64:
            return encrypted_data, custom_alphabet
    
    # 方法 3: 分别查找
    encrypted_match = re.search(ENCRYPTED_DATA_PATTERN, content)
    alphabet_match = re.search(CUSTOM_ALPHABET_PATTERN, content)
    
    if encrypted_match and alphabet_match:
        encrypted_data = encrypted_match.group(1)
        custom_alphabet = alphabet_match.group(1)
        return encrypted_data, custom_alphabet
    
    # 方法 4: 查找特定变量赋值模式
    specific_pattern = r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*"(0E6V[A-Za-z0-9+/=]{300,})"'
    specific_match = re.search(specific_pattern, content)
    
    if specific_match:
        encrypted_data = specific_match.group(1)
        
        pos = specific_match.end()
        remaining = content[pos:pos+500]
        
        alphabet_in_remaining = re.search(r'"([A-Za-z0-9+/]{64})"', remaining)
        if alphabet_in_remaining:
            custom_alphabet = alphabet_in_remaining.group(1)
            return encrypted_data, custom_alphabet
    
    raise ValueError("Failed to extract encryption data from deobfuscated JS")


def extract_key_data_from_raw(content: str) -> Optional[Tuple[str, str]]:
    """
    尝试从原始 JS 代码中直接提取数据 (备用方法)
    
    某些情况下加密数据可能未被混淆,可以直接提取。
    
    Args:
        content: 原始 JS 代码
    
    Returns:
        (encrypted_data, custom_alphabet) 或 None
    """
    try:
        return extract_key_data_from_deobfuscated(content)
    except ValueError:
        return None


# ==================== 密钥缓存 ====================

def load_cached_key() -> Optional[Dict[str, Any]]:
    """
    加载缓存的密钥数据
    
    Returns:
        缓存数据字典或 None
    """
    cache_path = get_cache_path()
    
    if not cache_path.exists():
        return None
    
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return None


def save_key_cache(data: Dict[str, Any]):
    """
    保存密钥到缓存
    
    Args:
        data: 要缓存的数据
    """
    cache_path = get_cache_path()
    
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ==================== 主要接口 ====================

async def fetch_and_extract_secret(
    js_url: str = JS_BASE_URL,
    ch_param: Optional[str] = None,
    use_cache: bool = True,
    force_update: bool = False
) -> Dict[str, Any]:
    """
    获取并提取密钥 (主要接口)
    
    完整流程:
    1. 检查缓存是否有效
    2. 下载 JS 文件
    3. 检查 JS 是否有变化
    4. 解混淆
    5. 提取并解密密钥
    6. 更新缓存
    
    Args:
        js_url: JS 文件 URL
        ch_param: ch 参数
        use_cache: 是否使用缓存
        force_update: 是否强制更新
    
    Returns:
        {
            "secret": 解密后的密钥,
            "encrypted_data": 加密数据,
            "custom_alphabet": 自定义字母表,
            "js_hash": JS 文件哈希,
            "updated_at": 更新时间,
            "from_cache": 是否来自缓存
        }
    """
    # 检查缓存
    if use_cache and not force_update:
        cached = load_cached_key()
        if cached and "secret" in cached:
            cached["from_cache"] = True
            return cached
    
    # 下载 JS
    js_content = await download_js_file(js_url, ch_param)
    js_hash = calculate_js_hash(js_content)
    
    # 检查是否与缓存相同
    if use_cache and not force_update:
        cached = load_cached_key()
        if cached and cached.get("js_hash") == js_hash:
            cached["from_cache"] = True
            return cached
    
    # 尝试直接从原始 JS 提取 (可能未混淆)
    direct_result = extract_key_data_from_raw(js_content)
    deobfuscated = None
    fixed_ts = None
    
    if direct_result:
        encrypted_data, custom_alphabet = direct_result
    else:
        # 需要解混淆
        deobfuscated = run_deobfuscator(js_content)
        
        # 优先使用 v4 提取 (能同时获取加密数据、字母表和 _ts)
        v4_result = extract_from_v4_output(deobfuscated)
        if v4_result and v4_result.get("encrypted_data") and v4_result.get("custom_alphabet"):
            encrypted_data = v4_result["encrypted_data"]
            custom_alphabet = v4_result["custom_alphabet"]
            fixed_ts = v4_result.get("fixed_ts")
        else:
            # 降级到旧的提取方式
            encrypted_data, custom_alphabet = extract_key_data_from_deobfuscated(deobfuscated)
    
    # 解密密钥
    secret = decode_secret_from_blob(encrypted_data, custom_alphabet)
    
    # 如果 v4 未成功提取 _ts，尝试旧方式
    if fixed_ts is None and deobfuscated:
        fixed_ts = extract_fixed_ts_from_lzstring(deobfuscated)
    
    # 构建结果
    result = {
        "secret": secret,
        "encrypted_data": encrypted_data,
        "custom_alphabet": custom_alphabet,
        "js_hash": js_hash,
        "updated_at": datetime.now().isoformat(),
        "from_cache": False
    }
    
    # 添加 _ts 如果成功提取
    if fixed_ts:
        result["fixed_ts"] = fixed_ts
    
    # 保存缓存
    save_key_cache(result)
    
    return result


def fetch_and_extract_secret_sync(
    js_url: str = JS_BASE_URL,
    ch_param: Optional[str] = None,
    use_cache: bool = True,
    force_update: bool = False
) -> Dict[str, Any]:
    """同步版本的密钥获取函数"""
    return asyncio.run(fetch_and_extract_secret(
        js_url, ch_param, use_cache, force_update
    ))


async def check_key_update(js_url: str = JS_BASE_URL, ch_param: Optional[str] = None) -> bool:
    """
    检查密钥是否需要更新
    
    比较远程 JS 文件的哈希与缓存的哈希。
    
    Args:
        js_url: JS 文件 URL
        ch_param: ch 参数
    
    Returns:
        True 如果需要更新, False 否则
    """
    cached = load_cached_key()
    if not cached:
        return True
    
    # 只获取文件头部来计算哈希
    js_content = await download_js_file(js_url, ch_param)
    js_hash = calculate_js_hash(js_content)
    
    return js_hash != cached.get("js_hash")


# ==================== CLI 入口 ====================

if __name__ == "__main__":
    import sys
    
    print("JS Key Extractor")
    print("=" * 50)
    
    # 检查命令行参数
    ch_param = None
    if len(sys.argv) > 1:
        ch_param = sys.argv[1]
        print(f"Using ch parameter: {ch_param}")
    
    try:
        result = fetch_and_extract_secret_sync(
            ch_param=ch_param,
            force_update="--force" in sys.argv
        )
        
        print(f"\nResult:")
        print(f"  Secret: {result['secret'][:40]}...")
        print(f"  JS Hash: {result['js_hash']}")
        print(f"  Updated At: {result['updated_at']}")
        print(f"  From Cache: {result['from_cache']}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
