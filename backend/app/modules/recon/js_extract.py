"""JS 文件提取与分析模块

从 HTML 中提取 JS 文件 URL，分析其中的敏感信息
"""

import asyncio
import re
from typing import Dict, List, Set
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup


class JSExtractor:
    """JS 提取与敏感信息分析器"""

    # 敏感信息正则模式
    PATTERNS = {
        "api_key": [
            r'(?i)(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?i)(?:secret|token|access_key|access_token)\s*[:=]\s*["\']([^"\']+)["\']',
        ],
        "endpoint": [
            r'(?i)(?:api[_-]?url|base[_-]?url|api_endpoint)\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        ],
        "internal_ip": [
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
            r'(?:192\.168\.\d{1,3}\.\d{1,3})',
        ],
        "cloud_key": [
            r'(?i)(?:AKIA[0-9A-Z]{16})',  # AWS Access Key
            r'(?i)(?:sk-[a-zA-Z0-9]{32,})',  # OpenAI/阿里云 Secret
            r'(?i)(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)',  # 私钥
        ],
        "internal_domain": [
            r'(?:[\w-]+\.(?:corp|internal|local|lan|dev|test|staging)\.(?:com|cn|net))',
        ],
        "password": [
            r'(?i)(?:password|pwd|passwd)\s*[:=]\s*["\']([^"\']+)["\']',
        ],
    }

    # 需要忽略的常见 JS 库
    IGNORED_JS = [
        "jquery", "bootstrap", "vue", "react", "angular", "lodash",
        "moment", "axios", "d3", "echarts", "chart", "swiper",
        "font-awesome", "fontawesome",
    ]

    def __init__(self):
        self.timeout = 15

    async def extract_from_html(self, base_url: str, html: str) -> List[Dict]:
        """从 HTML 中提取 JS 文件"""
        js_urls = self._find_js_urls(base_url, html)
        return js_urls

    async def analyze_js(self, js_url: str, content: str) -> Dict:
        """分析 JS 文件中的敏感信息"""
        findings = []
        for info_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    findings.append({
                        "type": info_type,
                        "content": match.strip()[:500],
                        "source_url": js_url,
                    })
        return {"url": js_url, "findings": findings}

    async def analyze_page(self, url: str, html: str) -> Dict:
        """一站式：提取页面 JS 并分析所有敏感信息"""
        all_findings = []

        # 1. 提取页面内联敏感信息
        inline_findings = await self.analyze_js(url, html)
        all_findings.extend(inline_findings.get("findings", []))

        # 2. 提取 JS 文件并分析
        js_urls = self._find_js_urls(url, html)
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for js_url in js_urls:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code == 200:
                        result = await self.analyze_js(js_url, resp.text)
                        all_findings.extend(result.get("findings", []))
                except Exception:
                    pass

        return {"url": url, "findings": all_findings, "js_files": js_urls}

    def _find_js_urls(self, base_url: str, html: str) -> List[str]:
        """从 HTML 中提取所有 JS 文件 URL"""
        js_urls = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if self._is_interesting_js(src):
                    full_url = urljoin(base_url, src)
                    js_urls.append(full_url)
        except Exception:
            # fallback 正则
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html):
                src = match.group(1)
                if self._is_interesting_js(src):
                    full_url = urljoin(base_url, src)
                    js_urls.append(full_url)

        return js_urls

    def _is_interesting_js(self, src: str) -> bool:
        """判断 JS 文件是否值得分析（排除常见库）"""
        src_lower = src.lower()
        # 排除 data: URI
        if src_lower.startswith("data:"):
            return False
        # 排除常见 CDN 库
        for ignored in self.IGNORED_JS:
            if ignored in src_lower:
                return False
        return True
