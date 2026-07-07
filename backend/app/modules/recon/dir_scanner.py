"""目录/路径扫描模块

对存活 Web 资产进行轻量级敏感路径扫描：
- 备份文件 (.git/.svn/.DS_Store/.env.bak)
- 未授权接口 (actuator/swagger/druid)
- 管理后台
- 源码泄露
"""

import asyncio
from typing import Dict, List

import httpx

from app.config import settings


class DirScanner:
    """目录扫描器"""

    # 敏感路径字典
    PATHS = {
        "backup": [
            "/.git/HEAD", "/.svn/entries", "/.DS_Store", "/.env", "/.env.bak",
            "/.env.local", "/.env.production", "/.env.development",
            "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.rar",
            "/www.zip", "/www.tar.gz", "/web.zip", "/web.tar.gz",
            "/database.sql", "/dump.sql", "/db.sql", "/backup.sql",
            "/config.php.bak", "/config.php~", "/config.php.swp",
            "/web.config.bak", "/web.config.old",
            "/wp-config.php.bak", "/wp-config.php~",
            "/application.properties.bak", "/application.yml.bak",
        ],
        "unauth": [
            "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
            "/actuator/mappings", "/actuator/configprops",
            "/swagger-ui.html", "/swagger-ui/index.html", "/swagger/index.html",
            "/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/druid/index.html", "/druid/websession.html",
            "/nacos/", "/nacos/v1/auth/users",
            "/api/console", "/api.html",
            "/graphql", "/graphiql",
            "/phpinfo.php", "/info.php", "/test.php",
            "/phpMyAdmin/", "/phpmyadmin/", "/pma/",
            "/.vscode/", "/.idea/", "/.git/config",
        ],
        "admin": [
            "/admin/", "/admin/login", "/admin/index",
            "/manager/", "/manage/", "/system/",
            "/login", "/admin/login", "/user/login",
            "/console/", "/dashboard/", "/panel/",
            "/jenkins/", "/jenkins/login",
            "/solr/", "/solr/admin/",
            "/_next/", "/wp-admin/", "/wp-login.php",
            "/user/login", "/admin.php", "/adminer.php",
        ],
        "source_leak": [
            "/.git/config", "/.svn/wc.db", "/.hg/requires",
            "/WEB-INF/web.xml", "/WEB-INF/classes/",
            "/META-INF/", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz",
            "/composer.json", "/package.json", "/Gemfile",
            "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
            "/README.md", "/CHANGELOG.md", "/LICENSE",
        ],
    }

    def __init__(self):
        self.timeout = 10
        self.concurrent = settings.DIR_SCAN_CONCURRENT

    async def scan(self, base_url: str, wordlist_type: str = "all") -> List[Dict]:
        """扫描目标 URL

        Args:
            base_url: 目标基础URL (e.g. http://example.com)
            wordlist_type: common/backup/unauth/admin/source_leak/all
        """
        base = base_url.rstrip("/")
        paths = self._get_paths(wordlist_type)
        results = []
        sem = asyncio.Semaphore(self.concurrent)

        async def _check(path: str) -> Dict | None:
            async with sem:
                return await self._probe(base, path)

        tasks = [_check(p) for p in paths]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in probe_results:
            if r and not isinstance(r, Exception) and r.get("found"):
                results.append(r)

        return sorted(results, key=lambda x: x.get("priority", 0), reverse=True)

    async def _probe(self, base: str, path: str) -> Dict | None:
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
                if resp.status_code in [200, 301, 302, 403, 401, 500]:
                    priority = self._calc_priority(path, resp)
                    return {
                        "url": url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "content_type": resp.headers.get("content-type", ""),
                        "title": self._extract_title(resp.text),
                        "found": True,
                        "priority": priority,
                        "category": self._categorize_path(path),
                    }
        except Exception:
            pass
        return None

    def _get_paths(self, wordlist_type: str) -> List[str]:
        if wordlist_type == "all":
            paths = []
            for v in self.PATHS.values():
                paths.extend(v)
            return paths
        return self.PATHS.get(wordlist_type, self.PATHS["common"] if "common" in self.PATHS else self.PATHS["all"])

    def _calc_priority(self, path: str, resp) -> int:
        """计算发现优先级 1-10"""
        priority = 0
        if "/.git/" in path:
            priority = 10
        elif "/.env" in path:
            priority = 9
        elif "/actuator" in path:
            priority = 8
        elif "/swagger" in path or "/api-docs" in path:
            priority = 7
        elif "backup" in path.lower() or ".bak" in path or ".zip" in path:
            priority = 6
        elif "/druid" in path or "/nacos" in path:
            priority = 5
        elif "/admin" in path or "/jenkins" in path:
            priority = 3
        else:
            priority = 1
        return priority

    def _categorize_path(self, path: str) -> str:
        for cat, paths in self.PATHS.items():
            if path in paths:
                return cat
        return "other"

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:200] if match else ""
