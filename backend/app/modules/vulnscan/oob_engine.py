"""OOB 外带检测模块 — 使用 interactsh 服务实现 Blind SSRF/RCE/XXE 验证

与 Nuclei 同样的实现方式:
- 从 public interactsh 服务器 (interact.sh) 获取唯一回调标识
- 替换 POC 中的 {{interactsh-url}}
- 轮询检查目标是否触发了回调
- 支持 HTTP/DNS/SMTP 协议检测
"""

import asyncio
import time
import uuid
from typing import Dict, Optional

import httpx


class InteractshClient:
    """Interactsh OOB 客户端 — 与 Nuclei 兼容"""

    # 公共 interactsh 服务器
    INTERACTSH_SERVERS = [
        "https://interact.sh",
    ]

    def __init__(self, server: str = None):
        self.server = (server or self.INTERACTSH_SERVERS[0]).rstrip("/")
        self.correlation_id = uuid.uuid4().hex[:20]
        self.secret = uuid.uuid4().hex[:16]
        self.domain = ""
        self._registered = False
        self._client = None

    async def register(self) -> Optional[str]:
        """注册 OOB 会话，返回回调 URL 或域名"""
        url = f"{self.server}/register"
        payload = {
            "public-key": "skyeye",
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    self.domain = data.get("interactsh_domain", "")
                    token = data.get("token", "")
                    if token and not self.domain:
                        self.domain = f"{token}.interact.sh"
                    self._registered = True
                    return self.domain
        except Exception as e:
            print(f"  [OOB] 注册失败: {e}")
        return None

    def get_url(self) -> str:
        """获取完整的回调 URL"""
        if not self.domain:
            return ""
        return f"http://{self.domain}"

    def get_dns(self) -> str:
        """获取 DNS 回调域名"""
        return self.domain

    async def poll(self, max_wait: int = 15, interval: int = 3) -> Dict:
        """轮询检查是否有 OOB 交互

        Returns:
            {
                "triggered": True/False,
                "interactions": ["http", "dns", "smtp"],
                "raw_data": [...],
            }
        """
        if not self._registered or not self.correlation_id:
            return {"triggered": False, "interactions": [], "raw_data": []}

        url = f"{self.server}/poll"
        params = {
            "id": self.correlation_id,
            "secret": self.secret,
        }
        started = time.time()
        interactions_found = []

        while time.time() - started < max_wait:
            try:
                async with httpx.AsyncClient(timeout=10, verify=False) as client:
                    resp = await client.get(url, params=params)
                    if resp.status_code == 200:
                        data = resp.json()
                        logs = data.get("data", [])
                        if logs:
                            protocols = set()
                            for log in logs:
                                proto = log.get("protocol", "")
                                protocols.add(proto)
                                interactions_found.append(log)
                            return {
                                "triggered": True,
                                "interactions": list(protocols),
                                "raw_data": interactions_found,
                            }
            except Exception:
                pass
            await asyncio.sleep(interval)

        return {"triggered": False, "interactions": [], "raw_data": []}

    async def deregister(self):
        """注销 OOB 会话"""
        if not self._registered:
            return
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                await client.post(f"{self.server}/deregister",
                                  json={"correlation-id": self.correlation_id, "secret": self.secret})
        except Exception:
            pass


class OOBEngine:
    """OOB 外带检测引擎 — 与 Nuclei POC 集成"""

    def __init__(self):
        self.active_sessions = []

    async def execute_with_oob(self, poc_id: str, target_url: str,
                               execute_poc_callback, timeout: int = 20) -> Dict:
        """执行带 OOB 检测的 POC

        Args:
            poc_id: POC ID
            target_url: 目标 URL
            execute_poc_callback: 执行 POC 的回调函数, 接受 (url, oob_url) → response
            timeout: 总超时

        Returns:
            {vulnerable, oob_triggered, interactions, matched, ...}
        """
        client = InteractshClient()
        domain = await client.register()
        if not domain:
            return {"vulnerable": False, "oob_triggered": False, "error": "OOB registration failed"}

        oob_url = client.get_url()
        try:
            # 执行 POC（OOB URL 已注入）
            poc_result = await execute_poc_callback(target_url, oob_url)

            # 等待并检查 OOB 回连
            oob_result = await client.poll(max_wait=timeout, interval=2)

            if oob_result["triggered"]:
                poc_result["vulnerable"] = True
                poc_result["matched"].extend(
                    [f"oob:{p}" for p in oob_result["interactions"]]
                )
                poc_result["oob_triggered"] = True
                poc_result["oob_interactions"] = oob_result["interactions"]
                poc_result["oob_raw"] = oob_result["raw_data"][:5]
            else:
                poc_result["oob_triggered"] = False

            return poc_result
        finally:
            await client.deregister()


# 全局单例
oob_engine = OOBEngine()
