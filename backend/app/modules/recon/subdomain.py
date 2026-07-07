"""子域名收集模块

支持方式：
1. crt.sh 证书透明度查询（无需API Key）
2. 被动枚举 (SecurityTrails API 可选)
3. DNS 爆破（内置字典）
"""

import asyncio
import random
from typing import Set
from urllib.parse import quote

import httpx

from app.config import settings


class SubdomainCollector:
    """子域名收集器"""

    def __init__(self):
        self.timeout = settings.SUBDOMAIN_TIMEOUT

    async def collect(self, domain: str, brute: bool = True) -> dict:
        """全量收集子域名"""
        results = {
            "domain": domain,
            "subdomains": set(),
            "sources": {},
        }

        # 并发执行被动收集
        tasks = [
            self._from_crtsh(domain),
            self._from_securitytrails(domain),
        ]
        if brute:
            tasks.append(self._dns_bruteforce(domain))

        # 执行所有收集任务
        source_results = await asyncio.gather(*tasks, return_exceptions=True)

        for source_name, result in zip(
            ["crtsh", "securitytrails", "dns_bruteforce"], source_results
        ):
            if isinstance(result, Exception):
                print(f"  [⚠] {source_name} 失败: {result}")
                continue
            if result:
                for sd in result:
                    if sd.endswith(f".{domain}") or sd == domain:
                        results["subdomains"].add(sd)
                results["sources"][source_name] = list(result)

        return results

    async def _from_crtsh(self, domain: str) -> Set[str]:
        """从 crt.sh 证书透明度日志获取子域名"""
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            if n and not n.startswith("*"):
                                subdomains.add(n)
            except Exception as e:
                print(f"    crt.sh 查询异常: {e}")
        return subdomains

    async def _from_securitytrails(self, domain: str) -> Set[str]:
        """从 SecurityTrails API 获取子域名（需配置 API Key）"""
        subdomains = set()
        api_key = settings.SECURITYTRAILS_API_KEY
        if not api_key:
            return subdomains

        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key}
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for sd in data.get("subdomains", []):
                        subdomains.add(f"{sd}.{domain}")
            except Exception as e:
                print(f"    SecurityTrails 查询异常: {e}")
        return subdomains

    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """DNS爆破枚举子域名"""
        subdomains = set()
        wordlist = self._load_wordlist()

        # 分批并发查询
        batch_size = 50
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i : i + batch_size]
            tasks = [self._check_subdomain(f"{word}.{domain}") for word in batch]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    subdomains.add(r)

        return subdomains

    async def _check_subdomain(self, subdomain: str) -> str | None:
        """检查单个子域名是否解析"""
        try:
            import socket
            socket.getaddrinfo(subdomain, 80, proto=socket.IPPROTO_TCP)
            return subdomain
        except (socket.gaierror, OSError):
            return None

    def _load_wordlist(self) -> list:
        """加载子域名字典"""
        # 内置高频子域名列表（Top 200+）
        common_subdomains = [
            "www", "mail", "webmail", "admin", "blog", "api", "app", "dev",
            "test", "beta", "demo", "shop", "m", "mobile", "wap", "bbs",
            "forum", "news", "video", "wiki", "help", "support", "service",
            "oa", "erp", "crm", "vpn", "sso", "portal", "login", "smtp",
            "pop3", "imap", "ftp", "ssh", "git", "svn", "jenkins", "jira",
            "confluence", "gitlab", "nexus", "sonar", "grafana", "kibana",
            "elastic", "nacos", "sentinel", "skywalking", "zabbix", "nagios",
            "prometheus", "alertmanager", "dashboard", "monitor", "status",
            "cdn", "static", "assets", "img", "css", "js", "upload", "download",
            "file", "files", "data", "db", "database", "redis", "mq", "rabbitmq",
            "rocketmq", "kafka", "es", "solr", "lucene", "logs", "log",
            "backup", "bak", "temp", "tmp", "cache", "test", "uat", "stage",
            "pre", "preprod", "prod", "release", "patch", "update", "upgrade",
            "gateway", "proxy", "auth", "cert", "ssl", "pay", "payment",
            "order", "trade", "account", "user", "member", "passport",
            "open", "openapi", "third", "thirdparty", "callback", "webhook",
            "doc", "docs", "api-docs", "swagger", "redoc", "graphql",
            "boss", "hr", "job", "jobs", "zhaopin", "recruit", "resume",
            "school", "edu", "learn", "training", "video", "live",
            "activity", "event", "h5", "wechat", "wx", "weixin", "alipay",
            "sdk", "jsapi", "map", "search", "suggest", "recommend",
            "feedback", "satisfaction", "survey", "questionnaire",
            "report", "charts", "bi", "analytics", "stat", "tongji",
            "click", "collect", "collector", "track", "tracking",
            "ad", "ads", "advert", "advertisement", "promote",
            "partner", "channel", "agent", "agency", "distribute",
            "yun", "cloud", "oss", "cos", "pan", "disk", "drive",
            "message", "msg", "sms", "push", "notice", "notify",
            "im", "chat", "talk", "meeting", "conf", "room",
            "calendar", "schedule", "plan", "task", "todo",
            "wlan", "wifi", "network", "router", "switch",
            "intranet", "inner", "internal", "corp", "office",
            "mis", "kms", "ids", "ips", "waf", "fw", "firewall",
            "hadoop", "hive", "spark", "flink", "storm", "zookeeper",
            "dubbo", "grpc", "thrift", "soa", "micro", "service-mesh",
            "registry", "config", "discovery", "eureka", "consul",
            "dan", "anquan", "safe", "security", "hackerone", "bugcrowd",
        ]
        return common_subdomains
