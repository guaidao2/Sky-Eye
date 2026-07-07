"""CDN 穿透 & 真实 IP 发现模块

技术手段:
1. DNS 历史解析记录 (SecurityTrails/VirusTotal)
2. SSL 证书 SAN 字段交叉比对
3. 多地 Ping / 全球 DNS 解析
4. 子域名 IP 对比 (www vs non-www)
5. 邮件服务器 MX 记录解析
6. @ 记录与常见 CDN IP 段对比
"""

import asyncio
import re
import socket
from typing import Dict, List, Set

import httpx

from app.config import settings


class CDNBypass:
    """CDN 穿透与真实 IP 发现"""

    # 常见 CDN CNAME 特征
    CDN_CNAME_PATTERNS = [
        r"\.cdn\.",
        r"\.cloudfront\.net",
        r"\.akamai\.",
        r"\.fastly\.",
        r"\.cloudflare\.com",
        r"\.kxcdn\.com",
        r"\.keycdn\.com",
        r"\.stackpathdns\.com",
        r"\.cdn77\.org",
        r"\.incapdns\.net",
        r"\.chinanetcenter\.com",
        r"\.wscdns\.com",
        r"\.wscloudcdn\.com",
        r"\.alicdn\.com",
        r"\.tcdn\.qq\.com",
        r"\.qiniucdn\.com",
        r"\.baiducdn\.com",
        r"\.jsdelivr\.net",
        r"\.cdn20\.com",
    ]

    # 常见 CDN IP 段 (简化版)
    CDN_IP_RANGES = [
        r"^103\.21\.244\.",
        r"^103\.22\.200\.",
        r"^103\.31\.4\.",
        r"^104\.16\.",
        r"^104\.17\.",
        r"^104\.18\.",
        r"^104\.19\.",
        r"^104\.20\.",
        r"^104\.21\.",
        r"^104\.22\.",
        r"^104\.23\.",
        r"^104\.24\.",
        r"^104\.25\.",
        r"^104\.26\.",
        r"^104\.27\.",
        r"^104\.28\.",
        r"^104\.29\.",
        r"^104\.30\.",
        r"^104\.31\.",
        r"^172\.64\.",
        r"^172\.65\.",
        r"^172\.66\.",
        r"^172\.67\.",
        r"^173\.245\.48\.",
        r"^173\.245\.49\.",
        r"^173\.245\.50\.",
        r"^173\.245\.51\.",
        r"^173\.245\.52\.",
        r"^173\.245\.53\.",
        r"^173\.245\.54\.",
        r"^173\.245\.55\.",
        r"^188\.114\.96\.",
        r"^188\.114\.97\.",
        r"^188\.114\.98\.",
        r"^188\.114\.99\.",
    ]

    def __init__(self):
        self.timeout = 15

    def is_cdn_ip(self, ip: str) -> bool:
        """判断 IP 是否属于 CDN 范围"""
        for pattern in self.CDN_IP_RANGES:
            if re.match(pattern, ip):
                return True
        return False

    def is_cdn_cname(self, cname: str) -> bool:
        """判断 CNAME 是否指向 CDN"""
        for pattern in self.CDN_CNAME_PATTERNS:
            if re.search(pattern, cname):
                return True
        return False

    async def find_real_ip(self, domain: str) -> Dict:
        """综合手段发现真实 IP"""
        result = {
            "domain": domain,
            "real_ips": set(),
            "cdn_ips": set(),
            "methods": {},
        }

        tasks = [
            self._dns_history(domain),
            self._ssl_san_check(domain),
            self._mx_record_check(domain),
            self._subdomain_ip_compare(domain),
            self._cert_transparency_ip(domain),
        ]
        method_results = await asyncio.gather(*tasks, return_exceptions=True)

        method_names = ["dns_history", "ssl_san", "mx_record", "subdomain_compare", "cert_transparency"]
        for name, res in zip(method_names, method_results):
            if isinstance(res, Exception):
                result["methods"][name] = f"error: {res}"
                continue
            if res:
                result["real_ips"].update(res.get("real", set()))
                result["cdn_ips"].update(res.get("cdn", set()))
                result["methods"][name] = len(res.get("real", set()))

        return result

    async def _dns_history(self, domain: str) -> Dict:
        """通过 SecurityTrails DNS 历史获取 IP"""
        result = {"real": set(), "cdn": set()}
        api_key = settings.SECURITYTRAILS_API_KEY
        if not api_key:
            return result

        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            headers = {"APIKEY": api_key}
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("records", []):
                        for ip_val in record.get("values", []):
                            ip_str = ip_val.get("ip", "")
                            if ip_str:
                                if self.is_cdn_ip(ip_str):
                                    result["cdn"].add(ip_str)
                                else:
                                    result["real"].add(ip_str)
        except Exception as e:
            print(f"  [CDN] DNS历史查询失败: {e}")
        return result

    async def _ssl_san_check(self, domain: str) -> Dict:
        """通过 crt.sh SSL 证书 SAN 字段查找非 CDN IP"""
        result = {"real": set(), "cdn": set()}
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    ips_found = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            # 从 SAN 中找纯 IP
                            ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', n)
                            ips_found.update(ip_match)
                    for ip_str in ips_found:
                        if self.is_cdn_ip(ip_str):
                            result["cdn"].add(ip_str)
                        else:
                            # 检查是否是私有地址
                            if not ip_str.startswith(("10.", "127.", "172.16", "192.168")):
                                result["real"].add(ip_str)
        except Exception as e:
            print(f"  [CDN] SSL证书查询失败: {e}")
        return result

    async def _mx_record_check(self, domain: str) -> Dict:
        """MX 记录通常直接暴露源站 IP"""
        result = {"real": set(), "cdn": set()}
        try:
            answers = socket.getaddrinfo(domain, 25, proto=socket.IPPROTO_TCP)
            # 实际查 MX
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    mx_host = str(mx.exchange).rstrip('.')
                    try:
                        mx_ips = socket.getaddrinfo(mx_host, 25)
                        for info in mx_ips:
                            ip_str = info[4][0]
                            if not self.is_cdn_ip(ip_str):
                                result["real"].add(ip_str)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
        return result

    async def _subdomain_ip_compare(self, domain: str) -> Dict:
        """子域名 IP 对比 — 非 www 子域名可能走不同的解析"""
        result = {"real": set(), "cdn": set()}
        common_subs = ["www", "mail", "api", "oa", "admin", "vpn", "sso", "m", "app"]
        for sub in common_subs:
            host = f"{sub}.{domain}"
            try:
                info = socket.getaddrinfo(host, 80)
                for addr in info:
                    ip_str = addr[4][0]
                    if self.is_cdn_ip(ip_str):
                        result["cdn"].add(ip_str)
                    elif not ip_str.startswith(("10.", "127.", "172.16", "192.168")):
                        result["real"].add(ip_str)
            except Exception:
                pass
        return result

    async def _cert_transparency_ip(self, domain: str) -> Dict:
        """通过证书透明度日志直接找 IP"""
        result = {"real": set(), "cdn": set()}
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', n)
                            for ip_str in ips:
                                if self.is_cdn_ip(ip_str):
                                    result["cdn"].add(ip_str)
                                elif not ip_str.startswith(("10.", "127.")):
                                    result["real"].add(ip_str)
        except Exception:
            pass
        return result
