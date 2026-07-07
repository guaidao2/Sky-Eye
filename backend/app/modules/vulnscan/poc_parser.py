"""Nuclei YAML POC 解析器 v2

增强支持:
- {{BaseURL}} 变量替换
- raw HTTP 请求格式
- 多步链式请求 (多个 requests 元素)
- matchers-condition: and
- 负向匹配 (negative: true)
- Host 头覆盖
"""

import re
from typing import Dict, List, Optional, Any

import yaml


class NucleiPOC:
    """解析后的 POC 对象"""

    def __init__(self, data: dict):
        self.id: str = data.get("id", "")
        self.info: dict = data.get("info", {})
        self.name: str = self.info.get("name", self.id)
        self.author: str = self.info.get("author", "")
        self.severity: str = self.info.get("severity", "info")
        self.description: str = self.info.get("description", "")
        self.reference: str | list = self.info.get("reference", [])
        self.tags: str = self.info.get("tags", "")
        self.matchers_condition: str = data.get("matchers-condition", "or")

        # 解析 HTTP 请求
        self.requests: List[dict] = []
        # 支持两种格式: requests (旧) 和 http (Nuclei 标准)
        raw_requests = data.get("requests", [])
        if not raw_requests:
            http_data = data.get("http", [])
            raw_requests = http_data

        for req in raw_requests:
            parsed = self._parse_request(req)
            if parsed:
                self.requests.append(parsed)

        # 目标分类标签
        self.target_tags: list = (
            self.info.get("tags", "").split(",")
            if isinstance(self.info.get("tags"), str) else []
        )

    def _parse_request(self, req: dict) -> Optional[dict]:
        """解析单条 HTTP 请求，支持 raw 和结构化格式"""
        result = {
            "method": "GET",
            "path": "/",
            "headers": {},
            "body": "",
            "raw": None,       # raw HTTP 请求模板
            "matchers": [],
            "extractors": [],
            "matchers_condition": req.get("matchers-condition", "or"),
        }

        # -- raw 格式: 完整 HTTP 请求文本 --
        raw_data = req.get("raw")
        if raw_data:
            if isinstance(raw_data, list):
                raw_data = raw_data[0]
            result["raw"] = raw_data
            # 从 raw 中解析 method/path/headers/body
            parsed = self._parse_raw_request(raw_data)
            result.update(parsed)

        # -- 结构化格式 --
        method = req.get("method", "GET")
        if isinstance(method, list):
            method = method[0] if method else "GET"
        if not method:
            method = "GET"
        result["method"] = str(method).upper()

        path = req.get("path", "/")
        if isinstance(path, list):
            path = path[0] if path else "/"
        result["path"] = str(path)

        headers = req.get("headers", {})
        if headers:
            result["headers"].update(headers)

        body = req.get("body", "")
        if body:
            result["body"] = body

        # Host 头覆盖
        if "host" in req:
            result["headers"]["Host"] = req["host"]

        # 解析匹配器
        for matcher in req.get("matchers", []):
            m = self._parse_matcher(matcher)
            if m:
                result["matchers"].append(m)

        # 解析提取器
        for ext in req.get("extractors", []):
            e = self._parse_extractor(ext)
            if e:
                result["extractors"].append(e)

        return result

    def _parse_raw_request(self, raw: str) -> dict:
        """解析 raw HTTP 请求文本"""
        result = {"method": "GET", "path": "/", "headers": {}, "body": ""}
        lines = raw.split("\n")
        if not lines:
            return result

        # 第一行: METHOD /path HTTP/1.1
        first = lines[0].strip()
        parts = first.split(" ")
        if len(parts) >= 2:
            result["method"] = parts[0].upper()
            result["path"] = parts[1]

        # 解析 Headers
        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                header_end = i
                break
            if ":" in line:
                key, val = line.split(":", 1)
                result["headers"][key.strip()] = val.strip()

        # Body
        if header_end and header_end < len(lines) - 1:
            result["body"] = "\n".join(lines[header_end + 1:])

        return result

    def _parse_matcher(self, matcher: dict) -> dict:
        """解析匹配器"""
        return {
            "type": matcher.get("type", "word"),
            "part": matcher.get("part", "body"),
            "condition": matcher.get("condition", "or"),
            "words": matcher.get("words", []),
            "regex": matcher.get("regex", []),
            "status": matcher.get("status", []),
            "negative": matcher.get("negative", False),
            "case_insensitive": matcher.get("case-insensitive", True),
        }

    def _parse_extractor(self, extractor: dict) -> dict:
        """解析提取器"""
        return {
            "type": extractor.get("type", "regex"),
            "part": extractor.get("part", "body"),
            "regex": extractor.get("regex", []),
            "name": extractor.get("name", ""),
            "group": extractor.get("group", 0),
        }

    def __repr__(self):
        return f"<POC(id='{self.id}', sev='{self.severity}', reqs={len(self.requests)})>"


class POCParser:
    """Nuclei YAML POC 解析器"""

    @staticmethod
    def parse_all(yaml_content: str) -> list:
        """解析多文档 YAML 为 POC 对象列表"""
        results = []
        try:
            docs = yaml.safe_load_all(yaml_content)
            for data in docs:
                if data and "id" in data:
                    results.append(NucleiPOC(data))
        except Exception as e:
            print(f"  [POC] 解析失败: {e}")
        return results

    @staticmethod
    def parse_file(filepath: str) -> list:
        """从文件加载 POC（支持多文档）"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return POCParser.parse_all(f.read())
        except Exception:
            return []
