"""空间搜索引擎集成 — Fofa / Hunter / Quake / Shodan"""

import asyncio
import base64
import hashlib
from typing import Dict, List, Set
from urllib.parse import quote

import httpx

from app.config import settings


class SpaceEngineCollector:
    """空间搜索引擎资产收集"""

    def __init__(self):
        self.timeout = 30

    async def collect_all(self, domain: str) -> Dict:
        """从所有已配置的搜索引擎收集资产"""
        results = {
            "domain": domain,
            "subdomains": set(),
            "ips": set(),
            "urls": set(),
            "sources": {},
        }
        tasks = []
        if settings.FOFA_EMAIL and settings.FOFA_KEY:
            tasks.append(self._from_fofa(domain))
        if settings.HUNTER_API_KEY:
            tasks.append(self._from_hunter(domain))
        if settings.QUAKE_TOKEN:
            tasks.append(self._from_quake(domain))

        source_results = await asyncio.gather(*tasks, return_exceptions=True)
        source_names = []
        if settings.FOFA_EMAIL and settings.FOFA_KEY:
            source_names.append("fofa")
        if settings.HUNTER_API_KEY:
            source_names.append("hunter")
        if settings.QUAKE_TOKEN:
            source_names.append("quake")

        for name, result in zip(source_names, source_results):
            if isinstance(result, Exception):
                results["sources"][name] = f"error: {result}"
                continue
            if result:
                results["subdomains"].update(result.get("subdomains", set()))
                results["ips"].update(result.get("ips", set()))
                results["urls"].update(result.get("urls", set()))
                results["sources"][name] = len(result.get("subdomains", set()))

        return results

    async def _from_fofa(self, domain: str) -> Dict:
        """Fofa API 查询"""
        result = {"subdomains": set(), "ips": set(), "urls": set()}
        try:
            query = f'domain="{domain}"'
            qbase64 = base64.b64encode(query.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?email={settings.FOFA_EMAIL}&key={settings.FOFA_KEY}&qbase64={qbase64}&size=500&fields=host,ip"

            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("error"):
                        return result
                    for row in data.get("results", []):
                        host, ip = row[0], row[1] if len(row) > 1 else ""
                        if host.endswith(f".{domain}") or host == domain:
                            result["subdomains"].add(host)
                        if ip:
                            result["ips"].add(ip)
                        result["urls"].add(host if "://" in host else f"http://{host}")
        except Exception as e:
            print(f"  [Fofa] 查询失败: {e}")
        return result

    async def _from_hunter(self, domain: str) -> Dict:
        """Hunter API 查询"""
        result = {"subdomains": set(), "ips": set(), "urls": set()}
        try:
            url = f"https://hunter.qianxin.com/openApi/search?api-key={settings.HUNTER_API_KEY}&search=domain%3D%22{domain}%22&page_size=500"

            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("code") != 200:
                        return result
                    for item in data.get("data", {}).get("arr", []):
                        host = item.get("url", "")
                        ip = item.get("ip", "")
                        if host.endswith(f".{domain}") or host == domain:
                            result["subdomains"].add(host)
                        if ip:
                            result["ips"].add(ip)
                        result["urls"].add(host if "://" in host else f"http://{host}")
        except Exception as e:
            print(f"  [Hunter] 查询失败: {e}")
        return result

    async def _from_quake(self, domain: str) -> Dict:
        """Quake API 查询"""
        result = {"subdomains": set(), "ips": set(), "urls": set()}
        try:
            url = "https://quake.360.cn/api/v3/search/quake_service"
            headers = {
                "X-QuakeToken": settings.QUAKE_TOKEN,
                "Content-Type": "application/json",
            }
            payload = {
                "query": f'domain:"{domain}"',
                "size": 500,
            }
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        host = item.get("service", {}).get("http", {}).get("host", "")
                        ip = item.get("ip", "")
                        port = item.get("port", 80)
                        if host and (host.endswith(f".{domain}") or host == domain):
                            result["subdomains"].add(host)
                        if ip:
                            result["ips"].add(ip)
                        if host:
                            scheme = "https" if port in [443, 8443] else "http"
                            result["urls"].add(f"{scheme}://{host}:{port}")
        except Exception as e:
            print(f"  [Quake] 查询失败: {e}")
        return result

    async def search_fofa_syntax(self, query: str, size: int = 100) -> List[Dict]:
        """Fofa 自定义语法查询"""
        results = []
        if not (settings.FOFA_EMAIL and settings.FOFA_KEY):
            return results
        try:
            qbase64 = base64.b64encode(query.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?email={settings.FOFA_EMAIL}&key={settings.FOFA_KEY}&qbase64={qbase64}&size={size}&fields=host,ip,port,title,server"

            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for row in data.get("results", []):
                        results.append({
                            "host": row[0] if len(row) > 0 else "",
                            "ip": row[1] if len(row) > 1 else "",
                            "port": row[2] if len(row) > 2 else "",
                            "title": row[3] if len(row) > 3 else "",
                            "server": row[4] if len(row) > 4 else "",
                        })
        except Exception as e:
            print(f"  [Fofa] 语法查询失败: {e}")
        return results
