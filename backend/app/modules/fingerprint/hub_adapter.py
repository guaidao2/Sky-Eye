"""FingerprintHub JSON 指纹适配器

从 web_fingerprint_v4.json 加载 3290 条规则，
与现有引擎兼容，用统一的 match() 接口输出。
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from app.config import settings


class FingerprintHubAdapter:
    """FingerprintHub 指纹引擎（JSON 版）"""

    def __init__(self):
        self.rules = []
        self._loaded = False

    def load(self) -> int:
        """加载 web_fingerprint_v4.json"""
        if self._loaded:
            return len(self.rules)

        fp_path = settings.FINGERPRINT_DIR / "web_fingerprint_v4.json"
        if not fp_path.exists():
            print(f"  [FPHub] 文件不存在: {fp_path}")
            return 0

        try:
            with open(fp_path, "r", encoding="utf-8") as f:
                self.rules = json.load(f)
            self._loaded = True
            print(f"  [FPHub] 已加载 {len(self.rules)} 条指纹规则")
        except Exception as e:
            print(f"  [FPHub] 加载失败: {e}")

        return len(self.rules)

    def match(self, url: str, status_code: int, headers: dict,
              body: str = "", favicon_hash: str = None) -> List[Dict]:
        """执行指纹匹配（兼容现有引擎接口）"""
        if not self._loaded:
            self.load()

        results = []

        for rule in self.rules:
            matched, matched_rules = self._match_rule(rule, url, headers, body, favicon_hash)
            if matched:
                info = rule.get("info", {})
                metadata = info.get("metadata", {})
                tags = info.get("tags", "").split(",")

                results.append({
                    "name": info.get("name", rule.get("id", "Unknown")),
                    "category": self._categorize(tags),
                    "value": self._severity_value(info.get("severity", "info")),
                    "tags": [t.strip() for t in tags if t.strip()],
                    "matched_rules": matched_rules,
                    "source": "fingerprinthub",
                })

        return results

    def _match_rule(self, rule: dict, url: str, headers: dict,
                    body: str, favicon_hash: str) -> tuple:
        """匹配单条规则"""
        http_blocks = rule.get("http", [])
        all_matched = []

        for http_block in http_blocks:
            for matcher in http_block.get("matchers", []):
                mtype = matcher.get("type", "word")
                part = matcher.get("part", "body")
                words = matcher.get("words", [])
                condition = matcher.get("condition", "or")
                case_insensitive = matcher.get("case-insensitive", False)

                # 选择匹配源
                if part == "header":
                    source = str(headers)
                elif part == "title":
                    # 从 body 提取 title
                    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                    source = m.group(1) if m else ""
                elif part == "cookie":
                    source = headers.get("Set-Cookie", "") + headers.get("Cookie", "")
                elif mtype == "favicon":
                    source = favicon_hash or ""
                else:
                    source = body

                if case_insensitive:
                    source = source.lower()
                    words = [w.lower() for w in words]

                # 执行匹配
                if mtype == "word":
                    if condition == "and":
                        if all(w in source for w in words):
                            all_matched.extend([f"fh_word:{w[:30]}" for w in words])
                    else:
                        for w in words:
                            if w in source:
                                all_matched.append(f"fh_word:{w[:30]}")

                elif mtype == "favicon":
                    if source in words:
                        all_matched.append(f"fh_favicon:{source}")

                elif mtype == "regex":
                    for pattern in words:
                        try:
                            if re.search(pattern, source, re.IGNORECASE if case_insensitive else 0):
                                all_matched.append(f"fh_regex:{pattern[:40]}")
                        except re.error:
                            pass

        return bool(all_matched), all_matched

    def _categorize(self, tags: list) -> str:
        """标签转分类"""
        tag_str = " ".join(tags).lower()
        if any(t in tag_str for t in ["oa", "office", "mail", "crm", "erp"]):
            return "oa"
        if any(t in tag_str for t in ["cms", "blog", "wp", "wordpress"]):
            return "cms"
        if any(t in tag_str for t in ["framework", "thinkphp", "spring", "laravel"]):
            return "framework"
        if any(t in tag_str for t in ["middleware", "tomcat", "nginx", "server"]):
            return "middleware"
        if any(t in tag_str for t in ["vpn", "firewall", "security", "waf"]):
            return "security_device"
        if any(t in tag_str for t in ["devops", "git", "jenkins", "monitor"]):
            return "enterprise"
        return "web"

    def _severity_value(self, severity: str) -> int:
        """严重等级转价值分"""
        mapping = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 2, "unknown": 2}
        return mapping.get(severity, 2)
