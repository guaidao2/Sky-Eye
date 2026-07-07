"""Sky-Eye POC 执行引擎 v2

增强:
- {{BaseURL}} / {{Hostname}} 变量替换
- raw HTTP 请求执行
- 多步链式请求
- 多个 matchers 之间 AND/OR 逻辑
- WAF 规避 (随机 UA, 延迟抖动, X-Forwarded-For)
- 代理支持
"""

import asyncio
import random
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.modules.vulnscan.poc_parser import NucleiPOC, POCParser


class POCEngine:
    """POC 执行引擎 v2"""

    # WAF 规避 User-Agent 池
    EVASION_UA_POOL = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    ]

    def __init__(self):
        self.pocs: Dict[str, NucleiPOC] = {}
        self._loaded = False

    def load_poc_file(self, filepath: str) -> int:
        """从文件加载 POC（支持多文档 YAML）"""
        pocs = POCParser.parse_file(filepath)
        for poc in pocs:
            self.pocs[poc.id] = poc
        return len(pocs)

    def load_poc_dir(self, dirpath: str) -> int:
        """批量加载目录下的所有 POC"""
        import glob as g
        count = 0
        for f in g.glob(f"{dirpath}/**/*.yaml", recursive=True):
            count += self.load_poc_file(f)
        self._loaded = True
        return count

    def _get_waf_evasion_headers(self) -> dict:
        """生成 WAF 规避请求头"""
        headers = {
            "User-Agent": random.choice(self.EVASION_UA_POOL),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        if settings.WAF_EVASION:
            # 随机 X-Forwarded-For 伪造来源
            fwd = f"{random.randint(10, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            headers["X-Forwarded-For"] = fwd
            headers["X-Real-IP"] = fwd
            headers["X-Originating-IP"] = fwd
        return headers

    def _resolve_variable(self, value: str, target_url: str) -> str:
        """替换 POC 中的变量

        支持:
        - {{BaseURL}} → http://target:port
        - {{Hostname}} → target host
        - {{Host}} → target host:port
        - {{Port}} → port
        """
        parsed = urlparse(target_url)
        host = parsed.hostname or "localhost"
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
        base_url = f"{parsed.scheme}://{host}:{port}"

        replacements = {
            "{{BaseURL}}": base_url,
            "{{baseurl}}": base_url,
            "{{Hostname}}": host,
            "{{hostname}}": host,
            "{{Host}}": f"{host}:{port}",
            "{{host}}": f"{host}:{port}",
            "{{Port}}": port,
            "{{port}}": port,
            "{{Scheme}}": parsed.scheme,
            "{{scheme}}": parsed.scheme,
        }

        for var, val in replacements.items():
            value = value.replace(var, val)
        return value

    async def execute(self, target_url: str, poc_id: str,
                      timeout: int = 15, proxy: str = None) -> Dict:
        """执行单个 POC

        Returns:
            {poc_id, name, severity, vulnerable, matched, extracted, error}
        """
        poc = self.pocs.get(poc_id)
        if not poc:
            return {"error": f"POC '{poc_id}' not found", "poc_id": poc_id}

        result = {
            "poc_id": poc.id,
            "name": poc.name,
            "severity": poc.severity,
            "description": poc.description,
            "vulnerable": False,
            "matched": [],
            "extracted": {},
            "error": None,
        }

        # 链式请求上下文（用于多步 POC）
        context = {"variables": {}}

        client_kwargs = {
            "timeout": timeout,
            "verify": False,
            "follow_redirects": False,
        }
        if proxy:
            client_kwargs["proxy"] = proxy
        elif settings.HTTP_PROXY:
            client_kwargs["proxy"] = settings.HTTP_PROXY

        async with httpx.AsyncClient(**client_kwargs) as client:
            for req_idx, req_tmpl in enumerate(poc.requests):
                try:
                    # 构建 URL
                    path = self._resolve_variable(req_tmpl["path"], target_url)
                    if path.startswith("http"):
                        url = path
                    else:
                        base = target_url.rstrip("/")
                        url = base + "/" + path.lstrip("/")

                    # WAF 规避 Headers
                    headers = self._get_waf_evasion_headers()
                    if req_tmpl.get("headers"):
                        for k, v in req_tmpl["headers"].items():
                            headers[k] = self._resolve_variable(str(v), target_url)

                    # Body
                    body = self._resolve_variable(req_tmpl.get("body", ""), target_url)
                    # 也替换 body 中的变量
                    for ctx_var, ctx_val in context.get("variables", {}).items():
                        body = body.replace(f"{{{{{ctx_var}}}}}", str(ctx_val))

                    # WAF 规避: 随机延迟
                    if settings.WAF_EVASION and req_idx > 0:
                        await asyncio.sleep(random.uniform(0.3, 1.0))

                    method = req_tmpl.get("method", "GET")
                    if method == "GET":
                        resp = await client.get(url, headers=headers)
                    elif method == "POST":
                        content_type = headers.get("Content-Type", "application/x-www-form-urlencoded")
                        resp = await client.post(url, headers=headers, content=body)
                    elif method == "PUT":
                        resp = await client.put(url, headers=headers, content=body)
                    elif method == "DELETE":
                        resp = await client.delete(url, headers=headers)
                    elif method == "PATCH":
                        resp = await client.patch(url, headers=headers, content=body)
                    elif method == "HEAD":
                        resp = await client.head(url, headers=headers)
                    elif method == "OPTIONS":
                        resp = await client.options(url, headers=headers)
                    else:
                        continue

                    # 执行匹配 (支持 matchers-condition)
                    matchers_condition = req_tmpl.get("matchers_condition", "or")
                    req_matched = []
                    req_missed = 0

                    for matcher in req_tmpl.get("matchers", []):
                        matched = self._match(matcher, resp)
                        is_negative = matcher.get("negative", False)

                        if is_negative:
                            matched = not bool(matched)

                        if matched:
                            if isinstance(matched, list):
                                req_matched.extend(matched)
                            else:
                                req_matched.append(matched)
                        else:
                            req_missed += 1

                    # 判断漏洞
                    if matchers_condition == "and":
                        if req_missed == 0:
                            result["vulnerable"] = True
                            result["matched"].extend(req_matched)
                    else:  # or
                        if req_matched:
                            result["vulnerable"] = True
                            result["matched"].extend(req_matched)

                    # 执行提取
                    for ext in req_tmpl.get("extractors", []):
                        extracted = self._extract(ext, resp)
                        if extracted:
                            result["extracted"].update(extracted)
                            context["variables"].update(extracted)

                except httpx.TimeoutException:
                    result["error"] = f"Timeout: {url}"
                except httpx.ConnectError:
                    result["error"] = f"Connection refused: {url}"
                except Exception as e:
                    result["error"] = f"{type(e).__name__}: {str(e)[:200]}"

        return result

    async def execute_batch(self, target_url: str, poc_ids: List[str],
                            concurrency: int = 5) -> List[Dict]:
        """批量执行 POC"""
        sem = asyncio.Semaphore(concurrency)

        async def _run(poc_id):
            async with sem:
                return await self.execute(target_url, poc_id)

        return await asyncio.gather(*[_run(pid) for pid in poc_ids])

    def _match(self, matcher: dict, resp: httpx.Response) -> List[str] | bool:
        """执行响应匹配"""
        part = matcher.get("part", "body")
        cond = matcher.get("condition", "or")
        case_insensitive = matcher.get("case_insensitive", True)

        # 不支持的部分直接跳过，避免误报
        unsupported_parts = ["interactsh_protocol", "interactsh_request", "interactsh", "dns"]
        if part in unsupported_parts:
            return False

        # 选择匹配源
        if part == "status" or matcher.get("type") == "status":
            source = str(resp.status_code)
        elif part == "header":
            source = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        elif part == "all":
            source = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + resp.text
        else:
            source = resp.text

        matched = []
        words = matcher.get("words", [])
        status_codes = matcher.get("status", [])
        regex_patterns = matcher.get("regex", [])

        # 状态码匹配
        if status_codes:
            if resp.status_code in status_codes:
                matched.append(f"status:{resp.status_code}")

        # 关键字匹配
        if words:
            flags = re.IGNORECASE if case_insensitive else 0
            if cond == "and":
                if all(w.lower() in source.lower() if case_insensitive else w in source for w in words):
                    matched.extend([f"word:{w}" for w in words])
            else:
                for w in words:
                    if case_insensitive:
                        if w.lower() in source.lower():
                            matched.append(f"word:{w}")
                    else:
                        if w in source:
                            matched.append(f"word:{w}")

        # 正则匹配
        for pattern in regex_patterns:
            try:
                flags = re.IGNORECASE if case_insensitive else 0
                if re.search(pattern, source, flags):
                    matched.append(f"regex:{pattern[:40]}")
            except re.error:
                pass

        return matched if matched else False

    def _extract(self, extractor: dict, resp: httpx.Response) -> Dict:
        """从响应中提取信息"""
        result = {}
        part = extractor.get("part", "body")
        group = extractor.get("group", 0)

        if part == "body":
            source = resp.text
        elif part == "header":
            source = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        else:
            source = resp.text

        for pattern in extractor.get("regex", []):
            try:
                matches = re.findall(pattern, source, re.IGNORECASE)
                if matches:
                    name = extractor.get("name", "extracted")
                    if isinstance(matches[0], tuple):
                        result[name] = matches[0][group] if len(matches[0]) > group else matches[0][0]
                    else:
                        result[name] = matches[group] if len(matches) > group else matches[0]
            except re.error:
                pass

        return result
