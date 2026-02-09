"""
AnonyIG 签名服务

通过逆向 anonyig.com 前端 JS，实现请求签名的自动化生成。

核心模块:
- secret_decoder: 从加密 blob 解码 HMAC 密钥
- signature: HMAC-SHA256 签名生成
- js_extractor: 自动下载并提取密钥数据
- key_updater: 后台密钥自动刷新
- instagram_api: Instagram 数据获取客户端
"""

__version__ = "2.0.0"
