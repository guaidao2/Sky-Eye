"""IP 解析与 ASN 发现模块"""

import asyncio
import socket
from typing import Dict, List, Tuple

import httpx


class IPResolver:
    """IP解析器 — 域名→IP、CDN识别、ASN查询"""

    def __init__(self):
        self.timeout = 10

    async def resolve(self, domains: List[str]) -> List[Dict]:
        """批量解析域名到 IP"""
        results = []
        tasks = [self._resolve_single(d) for d in domains if d]
        for r in await asyncio.gather(*tasks):
            if r:
                results.append(r)
        return results

    async def _resolve_single(self, domain: str) -> Dict | None:
        """解析单个域名"""
        try:
            info = socket.getaddrinfo(domain, 80)
            ips = list(set(addr[4][0] for addr in info))
            if ips:
                return {"domain": domain, "ips": ips, "ip_count": len(ips)}
        except socket.gaierror:
            pass
        return None

    async def resolve_with_asn(self, domains: List[str]) -> List[Dict]:
        """解析域名并查询 ASN"""
        results = await self.resolve(domains)
        cdn_domains = self._cdn_domains()

        for item in results:
            # CDN 检测
            item["is_cdn"] = any(cdn in item.get("domain", "") for cdn in cdn_domains)
            item["asn_info"] = []

            # ASN 查询（简单通过 IP 的反向查询）
            for ip in item.get("ips", []):
                asn = await self._query_asn(ip)
                if asn:
                    item["asn_info"].append(asn)

        return results

    async def _query_asn(self, ip: str) -> Dict | None:
        """查询 IP 的 ASN 信息"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(f"https://ipinfo.io/{ip}/json")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": ip,
                        "org": data.get("org", ""),
                        "country": data.get("country", ""),
                        "city": data.get("city", ""),
                        "region": data.get("region", ""),
                        "loc": data.get("loc", ""),
                    }
        except Exception:
            pass
        return None

    def _cdn_domains(self) -> set:
        """简单 CDN 域名检测"""
        return {
            "cloudfront.net", "akamaiedge.net", "akamai.net",
            "edgesuite.net", "azureedge.net", "azurefd.net",
            "trafficmanager.net", "cdn.cloudflare.net", "cloudflare.com",
            "fastly.net", "stackpathdns.com", "cdn77.net",
            "cdn.aliyuncs.com", "kunluncan.com", "kunlungsl.com",
            "tencent-cloud-cdn.com", "cdn.dnsv1.com", "qhcdn.com",
            "xcdncache.com", "wsdvs.com", "cloudfront.net",
            "worldcdn.net", "incapdns.net", "kxcdn.com",
        }
