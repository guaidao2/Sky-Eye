"""Web 存活探测模块

批量检测 HTTP/HTTPS 存活、获取标题、状态码、响应头信息
"""

import asyncio
import re
from typing import Dict, List, Tuple

import httpx
from bs4 import BeautifulSoup

from app.config import settings


class WebProber:
    """Web 存活探测器"""

    COMMON_PORTS = {
        80: "http", 443: "https", 8080: "http", 8443: "https",
        8000: "http", 8888: "http", 9090: "http", 9443: "https",
        7001: "http", 7080: "http", 18080: "http", 18081: "http",
    }

    def __init__(self):
        self.timeout = settings.WEB_PROBE_TIMEOUT
        self.concurrent = settings.WEB_PROBE_CONCURRENT

    async def probe(self, targets: List[Dict]) -> List[Dict]:
        """批量探测 Web 存活

        Args:
            targets: [{"host": "x.com", "port": 80, "scheme": "http"}, ...]
        """
        sem = asyncio.Semaphore(self.concurrent)

        async def _probe_one(target: Dict) -> Dict | None:
            async with sem:
                return await self._check(target)

        tasks = [_probe_one(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        alive = []
        for r in results:
            if r and not isinstance(r, Exception):
                alive.append(r)
        return alive

    def _build_url(self, scheme: str, host: str, port: int, path: str = "/") -> str:
        return f"{scheme}://{host}:{port}{path}"

    async def _check(self, target: Dict) -> Dict | None:
        """探测单个 Web 服务"""
        host = target["host"]
        port = target.get("port", 80)
        scheme = target.get("scheme", "http")
        url = self._build_url(scheme, host, port)

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                follow_redirects=True,
                max_redirects=5,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            ) as client:
                resp = await client.get(url)

                # 提取标题
                title = self._extract_title(resp.text)

                # 提取技术栈（简单的 Server/Headers 识别）
                tech_stack = self._detect_tech(resp.headers, resp.text)

                return {
                    "url": url,
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "status_code": resp.status_code,
                    "title": title or "",
                    "content_type": resp.headers.get("content-type", ""),
                    "content_length": len(resp.content),
                    "tech_stack": ",".join(tech_stack) if tech_stack else "",
                    "headers": dict(resp.headers),
                    "alive": True,
                }

        except (httpx.TimeoutException, httpx.ConnectError, Exception):
            return {
                "url": url,
                "host": host,
                "port": port,
                "scheme": scheme,
                "alive": False,
            }

    def _extract_title(self, html: str) -> str | None:
        """从 HTML 中提取标题"""
        try:
            soup = BeautifulSoup(html, "lxml")
            title = soup.title.string if soup.title else None
            return title.strip()[:200] if title else None
        except Exception:
            # fallback 正则
            match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip()[:200] if match else None

    def _detect_tech(self, headers: dict, html: str) -> List[str]:
        """简单技术栈识别"""
        tech = []
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")

        if "nginx" in server.lower():
            tech.append("Nginx")
        if "apache" in server.lower():
            tech.append("Apache")
        if "IIS" in server:
            tech.append("IIS")
        if "openresty" in server.lower():
            tech.append("OpenResty")
        if "cloudflare" in server.lower():
            tech.append("Cloudflare")

        if "PHP" in x_powered:
            tech.append("PHP")
        if "ASP.NET" in x_powered or "ASP" in x_powered:
            tech.append("ASP.NET")
        if "Express" in x_powered:
            tech.append("Express")
        if "Java" in x_powered:
            tech.append("Java")

        if "WordPress" in html or "/wp-content/" in html:
            tech.append("WordPress")
        if "DedeCMS" in html:
            tech.append("DedeCMS")
        if "ThinkPHP" in html:
            tech.append("ThinkPHP")
        if "Laravel" in html:
            tech.append("Laravel")

        return tech

    async def probe_url(self, url: str) -> Dict | None:
        """探测单个 URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return await self._check({
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "scheme": parsed.scheme,
        })
