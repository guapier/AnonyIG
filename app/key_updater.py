"""
密钥自动更新服务

提供后台任务定时检查和更新密钥。

功能:
1. 定时检查远程 JS 文件是否更新
2. 自动提取并更新密钥
3. 密钥变更通知
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Any
from contextlib import asynccontextmanager

from .js_extractor import (
    fetch_and_extract_secret,
    check_key_update,
    load_cached_key,
    JS_BASE_URL
)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== 配置 ====================

# 默认检查间隔 (小时)
DEFAULT_CHECK_INTERVAL_HOURS = 6

# 密钥最大有效期 (小时)
MAX_KEY_AGE_HOURS = 72  # 3天


# ==================== 全局状态 ====================

class KeyState:
    """密钥状态管理"""
    
    def __init__(self):
        self.current_secret: Optional[str] = None
        self.fixed_ts: Optional[int] = None
        self.last_update: Optional[datetime] = None
        self.last_check: Optional[datetime] = None
        self.js_hash: Optional[str] = None
        self.update_count: int = 0
        self.error_count: int = 0
        self.last_error: Optional[str] = None
        self._callbacks: list = []
    
    def register_callback(self, callback: Callable[[str, str], None]):
        """
        注册密钥更新回调
        
        callback(old_secret, new_secret)
        """
        self._callbacks.append(callback)
    
    def notify_update(self, old_secret: Optional[str], new_secret: str):
        """通知所有回调密钥已更新"""
        for callback in self._callbacks:
            try:
                callback(old_secret, new_secret)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "current_secret": self.current_secret[:40] + "..." if self.current_secret else None,
            "secret_length": len(self.current_secret) if self.current_secret else 0,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "js_hash": self.js_hash,
            "update_count": self.update_count,
            "error_count": self.error_count,
            "last_error": self.last_error
        }


# 全局状态实例
key_state = KeyState()


# ==================== 更新逻辑 ====================

async def update_key(
    js_url: str = JS_BASE_URL,
    ch_param: Optional[str] = None,
    force: bool = False
) -> Dict[str, Any]:
    """
    更新密钥
    
    Args:
        js_url: JS 文件 URL
        ch_param: ch 参数
        force: 是否强制更新
    
    Returns:
        更新结果
    """
    global key_state
    
    try:
        key_state.last_check = datetime.now()
        
        # 检查是否需要更新
        if not force:
            needs_update = await check_key_update(js_url, ch_param)
            if not needs_update:
                logger.info("Key is up to date, no update needed")
                return {
                    "status": "unchanged",
                    "message": "Key is up to date"
                }
        
        # 执行更新
        logger.info("Updating key...")
        result = await fetch_and_extract_secret(
            js_url, ch_param,
            use_cache=False,
            force_update=True
        )
        
        old_secret = key_state.current_secret
        new_secret = result["secret"]
        
        # 更新状态
        key_state.current_secret = new_secret
        key_state.fixed_ts = result.get("fixed_ts")
        key_state.last_update = datetime.now()
        key_state.js_hash = result["js_hash"]
        key_state.update_count += 1
        key_state.last_error = None
        
        # 检查密钥是否变化
        key_changed = old_secret != new_secret
        if key_changed:
            logger.info(f"Key updated: {new_secret[:20]}...")
            key_state.notify_update(old_secret, new_secret)
        
        return {
            "status": "updated" if key_changed else "refreshed",
            "secret": new_secret,
            "js_hash": result["js_hash"],
            "key_changed": key_changed,
            "updated_at": key_state.last_update.isoformat()
        }
        
    except Exception as e:
        key_state.error_count += 1
        key_state.last_error = str(e)
        logger.error(f"Key update failed: {e}")
        raise


async def get_current_secret() -> str:
    """
    获取当前密钥
    
    如果密钥不存在或已过期,会自动更新。
    
    Returns:
        当前有效的密钥
    """
    global key_state
    
    # 检查是否需要初始化
    if key_state.current_secret is None:
        # 尝试从缓存加载
        cached = load_cached_key()
        if cached and "secret" in cached:
            key_state.current_secret = cached["secret"]
            key_state.fixed_ts = cached.get("fixed_ts")
            key_state.js_hash = cached.get("js_hash")
            if "updated_at" in cached:
                try:
                    key_state.last_update = datetime.fromisoformat(cached["updated_at"])
                except:
                    pass
    
    # 检查密钥是否过期
    if key_state.current_secret is None or _is_key_expired():
        await update_key(force=key_state.current_secret is None)
    
    return key_state.current_secret


def _is_key_expired() -> bool:
    """检查密钥是否过期"""
    if key_state.last_update is None:
        return True
    
    age = datetime.now() - key_state.last_update
    return age > timedelta(hours=MAX_KEY_AGE_HOURS)


# ==================== 后台更新任务 ====================

class KeyUpdaterTask:
    """后台密钥更新任务"""
    
    def __init__(
        self,
        check_interval_hours: float = DEFAULT_CHECK_INTERVAL_HOURS,
        js_url: str = JS_BASE_URL,
        ch_param: Optional[str] = None
    ):
        self.check_interval = timedelta(hours=check_interval_hours)
        self.js_url = js_url
        self.ch_param = ch_param
        self._task: Optional[asyncio.Task] = None
        self._running = False
    
    async def _run_loop(self):
        """后台循环"""
        while self._running:
            try:
                await update_key(self.js_url, self.ch_param)
            except Exception as e:
                logger.error(f"Background update failed: {e}")
            
            # 等待下次检查
            await asyncio.sleep(self.check_interval.total_seconds())
    
    def start(self):
        """启动后台任务"""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"Key updater started, interval: {self.check_interval}")
    
    def stop(self):
        """停止后台任务"""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("Key updater stopped")


# 全局更新任务实例
_updater_task: Optional[KeyUpdaterTask] = None


def get_updater_task() -> KeyUpdaterTask:
    """获取全局更新任务实例"""
    global _updater_task
    if _updater_task is None:
        _updater_task = KeyUpdaterTask()
    return _updater_task


@asynccontextmanager
async def lifespan_key_updater(check_interval_hours: float = DEFAULT_CHECK_INTERVAL_HOURS):
    """
    FastAPI lifespan 上下文管理器
    
    用于在应用启动时开始后台更新,关闭时停止。
    
    Example:
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            async with lifespan_key_updater(check_interval_hours=6):
                yield
        
        app = FastAPI(lifespan=lifespan)
    """
    updater = get_updater_task()
    updater.check_interval = timedelta(hours=check_interval_hours)
    
    # 初始化密钥
    try:
        await get_current_secret()
    except Exception as e:
        logger.error(f"Initial key fetch failed: {e}")
    
    # 启动后台更新
    updater.start()
    
    try:
        yield
    finally:
        updater.stop()


# ==================== 便捷函数 ====================

async def ensure_key_initialized() -> str:
    """
    确保密钥已初始化
    
    适用于应用启动时调用。
    
    Returns:
        当前密钥
    """
    return await get_current_secret()


def get_key_status() -> Dict[str, Any]:
    """
    获取密钥状态
    
    Returns:
        状态字典
    """
    return key_state.to_dict()


# ==================== CLI 入口 ====================

if __name__ == "__main__":
    import sys
    
    async def main():
        print("Key Updater Test")
        print("=" * 50)
        
        # 强制更新
        force = "--force" in sys.argv
        
        try:
            result = await update_key(force=force)
            print(f"\nResult: {result['status']}")
            if "secret" in result:
                print(f"Secret: {result['secret'][:40]}...")
            print(f"\nKey State: {get_key_status()}")
            
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    
    asyncio.run(main())
