"""未授权访问检测模块

对存活 Web 资产进行自动化未授权端点探测：
- Spring Boot Actuator
- Swagger / API Docs
- Druid Monitor
- Nacos
- Jenkins
- Docker API
- Kubernetes Dashboard
- 常见管理后台
"""

import asyncio
from typing import Dict, List, Optional

import httpx

from app.config import settings


class UnauthorizedChecker:
    """未授权访问检测器"""

    # 未授权检测规则: {path: (name, category, severity)}
    UNAUTH_RULES = {
        # Spring Boot Actuator
        "/actuator": ("Spring Boot Actuator", "spring", "medium"),
        "/actuator/health": ("Actuator Health", "spring", "low"),
        "/actuator/env": ("Actuator Env Config", "spring", "high"),
        "/actuator/info": ("Actuator Info", "spring", "low"),
        "/actuator/mappings": ("Actuator Mappings", "spring", "medium"),
        "/actuator/configprops": ("Actuator ConfigProps", "spring", "medium"),
        "/actuator/beans": ("Actuator Beans", "spring", "low"),
        "/actuator/heapdump": ("Actuator HeapDump", "spring", "high"),
        "/actuator/loggers": ("Actuator Loggers", "spring", "low"),
        "/actuator/gateway/routes": ("Actuator Gateway Routes", "spring", "medium"),
        "/env": ("Spring Env (Old)", "spring", "high"),
        # Swagger / API Docs
        "/swagger-ui.html": ("Swagger UI", "api-doc", "medium"),
        "/swagger-ui/index.html": ("Swagger UI v3", "api-doc", "medium"),
        "/swagger/index.html": ("Swagger Index", "api-doc", "medium"),
        "/api-docs": ("API Docs", "api-doc", "medium"),
        "/v2/api-docs": ("API Docs v2", "api-doc", "medium"),
        "/v3/api-docs": ("API Docs v3", "api-doc", "medium"),
        "/doc.html": ("Knife4j Doc", "api-doc", "medium"),
        # Druid
        "/druid/index.html": ("Druid Monitor", "monitor", "high"),
        "/druid/websession.html": ("Druid WebSession", "monitor", "high"),
        "/druid/spring.html": ("Druid Spring Monitor", "monitor", "high"),
        "/druid/sql.html": ("Druid SQL Monitor", "monitor", "high"),
        # Nacos
        "/nacos/": ("Nacos Dashboard", "middleware", "high"),
        "/nacos/v1/auth/users": ("Nacos User List", "middleware", "critical"),
        "/nacos/v1/cs/configs": ("Nacos Configs", "middleware", "high"),
        # Jenkins
        "/jenkins/script": ("Jenkins Script Console", "ci-cd", "critical"),
        "/jenkins/manage": ("Jenkins Manage", "ci-cd", "high"),
        "/jenkins/configureSecurity/": ("Jenkins Security Config", "ci-cd", "high"),
        # Docker
        "/containers/json": ("Docker API Containers", "docker", "critical"),
        "/version": ("Docker API Version", "docker", "medium"),
        "/info": ("Docker API Info", "docker", "medium"),
        # Kubernetes
        "/api/v1/namespaces": ("K8s API Namespaces", "kubernetes", "critical"),
        "/api/v1/pods": ("K8s API Pods", "kubernetes", "critical"),
        # Middleware
        "/solr/admin/": ("Solr Admin", "middleware", "high"),
        "/solr/": ("Solr Dashboard", "middleware", "medium"),
        "/rabbitmq/": ("RabbitMQ Management", "middleware", "medium"),
        "/activemq/": ("ActiveMQ Console", "middleware", "medium"),
        "/zabbix/": ("Zabbix Dashboard", "monitor", "medium"),
        "/grafana/": ("Grafana Dashboard", "monitor", "low"),
        "/prometheus/": ("Prometheus Dashboard", "monitor", "low"),
        "/prometheus/targets": ("Prometheus Targets", "monitor", "medium"),
        "/kibana/": ("Kibana Dashboard", "elk", "medium"),
        "/elasticsearch/": ("Elasticsearch", "elk", "medium"),
        "/_cat/indices": ("ES Indices", "elk", "high"),
        "/elk/": ("ELK Stack", "elk", "low"),
        # Database Web UI
        "/phpmyadmin/": ("phpMyAdmin", "database", "high"),
        "/phpMyAdmin/": ("phpMyAdmin", "database", "high"),
        "/adminer.php": ("Adminer", "database", "high"),
        "/_dashconsole": ("Mongo Express", "database", "medium"),
        # Remote / Admin
        "/_next/": ("Next.js Dev", "framework", "low"),
        "/console/": ("Web Console", "admin", "medium"),
        "/.json": ("JSON Endpoint", "info", "low"),
        "/web-console/": ("Web Console", "admin", "medium"),
        "/server-status": ("Apache Server Status", "middleware", "low"),
        "/server-info": ("Apache Server Info", "middleware", "medium"),
        # Cloud metadata (SSRF targets)
        "/latest/meta-data/": ("AWS Metadata", "cloud", "critical"),
        "/metadata/v1/": ("Cloud Metadata", "cloud", "critical"),
        # Huawei
        "/umc/" : ("Huawei UMC", "device", "medium"),
    }

    def __init__(self):
        self.timeout = 10

    async def check(self, base_url: str) -> List[Dict]:
        """对单个 URL 进行全面未授权检测

        Returns:
            [{name, path, url, status_code, category, severity, evidence}, ...]
        """
        base = base_url.rstrip("/")
        results = []
        sem = asyncio.Semaphore(20)

        async def _check(path: str, info: tuple) -> Dict | None:
            async with sem:
                return await self._probe(base, path, *info)

        tasks = [_check(path, info) for path, info in self.UNAUTH_RULES.items()]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for r in outcomes:
            if r and not isinstance(r, Exception) and r.get("vulnerable"):
                results.append(r)

        return sorted(results, key=lambda x: {
            "critical": 5, "high": 4, "medium": 3, "low": 2
        }.get(x.get("severity", "low"), 0), reverse=True)

    async def _probe(self, base: str, path: str,
                     name: str, category: str, severity: str) -> Optional[Dict]:
        """探测单个路径"""
        url = base + path
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                follow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                },
            ) as client:
                resp = await client.get(url)
                status = resp.status_code
                body = resp.text[:2000]
                content_type = resp.headers.get("content-type", "")

                # 未授权判定条件
                is_unauth = False
                evidence = ""

                if status == 200:
                    # Spring Actuator 通常是 JSON
                    if category == "spring" and "json" in content_type:
                        is_unauth = True
                        evidence = f"返回JSON数据 {len(resp.text)} 字节"
                    elif category == "api-doc":
                        if "swagger" in body.lower() or "openapi" in body.lower() or status == 200:
                            is_unauth = True
                            evidence = f"API文档可访问"
                    elif category == "monitor":
                        is_unauth = True
                        evidence = f"监控面板可访问"
                    elif category == "middleware":
                        is_unauth = True
                        evidence = f"中间件管理界面可访问"
                    elif category == "ci-cd":
                        is_unauth = True
                        evidence = f"CI/CD管理界面可访问"
                    elif category in ["docker", "kubernetes"]:
                        is_unauth = is_unauth or True
                        evidence = f"{category} API可访问"
                    elif category == "database":
                        is_unauth = True
                        evidence = f"数据库管理界面可访问"
                    elif category == "cloud":
                        is_unauth = is_unauth or True
                        evidence = f"云元数据接口可访问"
                elif status in [301, 302]:
                    # 有些重定向到登录页
                    location = resp.headers.get("location", "")
                    if "login" not in location.lower() and "auth" not in location.lower():
                        is_unauth = True
                        evidence = f"重定向到 {location} (非登录页)"
                elif status in [401, 403]:
                    # 有认证但可访问
                    is_unauth = False

                if is_unauth:
                    return {
                        "name": name,
                        "path": path,
                        "url": url,
                        "status_code": status,
                        "category": category,
                        "severity": severity,
                        "evidence": evidence or f"Status {status}",
                        "content_type": content_type,
                        "vulnerable": True,
                    }
        except Exception:
            pass
        return None

    async def scan_services(self, host: str, open_ports: List[int]) -> List[Dict]:
        """根据开放端口检测未授权服务"""
        results = []

        port_checks = {
            2375: ("http", 2375, "/containers/json", "Docker API (no TLS)", "docker", "critical"),
            2376: ("https", 2376, "/containers/json", "Docker API (TLS)", "docker", "critical"),
            6443: ("https", 6443, "/api/v1/namespaces", "Kubernetes API", "kubernetes", "critical"),
            10250: ("https", 10250, "/metrics", "Kubelet Metrics", "kubernetes", "medium"),
            9200: ("http", 9200, "/_cat/indices", "Elasticsearch", "elk", "high"),
            27017: ("mongodb", 27017, "", "MongoDB", "database", "high"),
            6379: ("redis", 6379, "", "Redis", "database", "critical"),
        }

        for port in open_ports:
            if port in port_checks:
                scheme, p, path, name, cat, sev = port_checks[port]
                results.append({
                    "name": name,
                    "port": port,
                    "category": cat,
                    "severity": sev,
                    "vulnerable": True,
                    "evidence": f"Port {port} open - service may be unauthorized",
                })

        return results
