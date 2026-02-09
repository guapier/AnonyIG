"""
加密工具模块

提供 Base64 转换、字节操作、字符串变换等加密相关工具函数。
"""

import base64
from typing import List, Tuple, Dict, Optional


# 标准 Base64 字母表
STD_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def build_char_map(from_alphabet: str, to_alphabet: str) -> Dict[str, str]:
    """
    构建字符映射表
    
    Args:
        from_alphabet: 源字母表 (64个字符)
        to_alphabet: 目标字母表 (64个字符)
    
    Returns:
        字符映射字典
    
    Raises:
        ValueError: 字母表长度不是64
    """
    if len(from_alphabet) != 64 or len(to_alphabet) != 64:
        raise ValueError("Alphabet must be 64 chars")
    
    return {from_alphabet[i]: to_alphabet[i] for i in range(64)}


def map_string_with_dict(s: str, char_map: Dict[str, str]) -> str:
    """
    使用字符映射表转换字符串
    
    Args:
        s: 输入字符串
        char_map: 字符映射字典
    
    Returns:
        转换后的字符串
    """
    result = []
    for char in s:
        result.append(char_map.get(char, char))
    return "".join(result)


def map_custom_to_std_b64(data: str, custom_alphabet: str) -> str:
    """
    将自定义 Base64 编码转换为标准 Base64 编码
    
    Args:
        data: 自定义 Base64 编码的数据
        custom_alphabet: 自定义的 64 字符字母表
    
    Returns:
        标准 Base64 编码的数据
    """
    char_map = build_char_map(custom_alphabet, STD_B64_ALPHABET)
    return map_string_with_dict(data, char_map)


def map_std_to_custom_b64(data: str, custom_alphabet: str) -> str:
    """
    将标准 Base64 编码转换为自定义 Base64 编码
    
    Args:
        data: 标准 Base64 编码的数据
        custom_alphabet: 自定义的 64 字符字母表
    
    Returns:
        自定义 Base64 编码的数据
    """
    char_map = build_char_map(STD_B64_ALPHABET, custom_alphabet)
    return map_string_with_dict(data, char_map)


def decode_base64_to_bytes(b64_str: str) -> bytes:
    """
    将 Base64 字符串解码为字节数组
    
    自动处理 padding (补齐 '=' 字符)
    
    Args:
        b64_str: Base64 编码的字符串
    
    Returns:
        解码后的字节数组
    """
    # 计算需要补齐的 padding
    padding_needed = (4 - len(b64_str) % 4) % 4
    b64_str_padded = b64_str + "=" * padding_needed
    
    return base64.b64decode(b64_str_padded)


def bytes_to_string(data: bytes, offset: int, length: int) -> str:
    """
    从字节数组中提取指定范围的内容并转换为字符串
    
    Args:
        data: 字节数组
        offset: 起始偏移量
        length: 提取长度
    
    Returns:
        提取的字符串
    """
    return "".join(chr(data[offset + i]) for i in range(length))


class StringOperations:
    """
    字符串变换操作类
    
    实现混淆算法中的 4 种字符串操作及其逆操作:
    - 操作 0: 字符串反转
    - 操作 1: 字符串循环移位
    - 操作 2: 移除前缀 padding
    - 操作 3: 移除后缀 padding
    """
    
    @staticmethod
    def invert_op_0(s: str) -> str:
        """
        操作 0 的逆操作: 字符串反转
        
        Args:
            s: 输入字符串
        
        Returns:
            反转后的字符串
        """
        return s[::-1]
    
    @staticmethod
    def invert_op_1(s: str, shift: int) -> str:
        """
        操作 1 的逆操作: 字符串循环移位 (反向)
        
        原操作将字符串向左循环移动 shift 位
        逆操作将字符串向右循环移动 shift 位
        
        Args:
            s: 输入字符串
            shift: 移位量
        
        Returns:
            移位后的字符串
        """
        if not s:
            return s
        
        shift = shift % len(s)
        # 逆向移位: 向右移动 = 从 (length - shift) 处切分
        actual_shift = (len(s) - shift) % len(s)
        return s[actual_shift:] + s[:actual_shift]
    
    @staticmethod
    def invert_op_2(s: str, length: int) -> str:
        """
        操作 2 的逆操作: 移除前缀 padding
        
        Args:
            s: 输入字符串
            length: padding 长度
        
        Returns:
            移除前缀后的字符串
        """
        length = max(0, int(length))
        return s[length:] if len(s) >= length else ""
    
    @staticmethod
    def invert_op_3(s: str, length: int) -> str:
        """
        操作 3 的逆操作: 移除后缀 padding
        
        Args:
            s: 输入字符串
            length: padding 长度
        
        Returns:
            移除后缀后的字符串
        """
        length = max(0, int(length))
        return s[:len(s) - length] if len(s) >= length else ""


def invert_ops(data: str, ops: List[Tuple[int, int]]) -> str:
    """
    按逆序执行操作列表的逆操作
    
    Args:
        data: 输入字符串
        ops: 操作列表, 每个元素为 (操作ID, 参数)
    
    Returns:
        执行所有逆操作后的字符串
    """
    result = data
    
    # 从后向前遍历操作列表
    for op_id, param in reversed(ops):
        if op_id == 0:
            result = StringOperations.invert_op_0(result)
        elif op_id == 1:
            result = StringOperations.invert_op_1(result, param)
        elif op_id == 2:
            result = StringOperations.invert_op_2(result, param)
        elif op_id == 3:
            result = StringOperations.invert_op_3(result, param)
    
    return result
