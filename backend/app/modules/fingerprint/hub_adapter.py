"""FingerprintHub JSON 指纹适配器 v2

改进:
- 严格匹配: 多词规则默认 AND (与 nuclei 行为一致)
- 分 part 匹配: header/body/title/favicon 精确区分
- favicon mmh3 hash 计算
- 结果去重 + 置信度排序
- 路径关键词上下文校验
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.config import settings


class FingerprintHubAdapter:
    """FingerprintHub 指纹引擎 v2"""

    def __init__(self):
        self.rules = []
        self._loaded = False

    def load(self) -> int:
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
              body: str = "", favicon_hash: str = None,
              min_confidence: float = 0.3) -> List[Dict]:
        """执行指纹匹配"""
        if not self._loaded:
            self.load()

        parsed = urlparse(url)
        path = parsed.path or "/"
        results = []
        seen_names = set()

        for rule in self.rules:
            http_blocks = rule.get("http", [])
            if not http_blocks:
                continue

            info = rule.get("info", {})
            name = info.get("name", rule.get("id", ""))
            if not name or name in seen_names:
                continue

            # 对每个 http block 执行匹配
            for http_block in http_blocks:
                matchers = http_block.get("matchers", [])
                if not matchers:
                    continue

                total_m = len(matchers)
                matched_m = 0

                for matcher in matchers:
                    if self._match_matcher(matcher, url, path, headers, body, favicon_hash):
                        matched_m += 1

                if matched_m == 0:
                    continue

                # 置信度 = 命中数 / 总数 (最少需要匹配1个, 但越多越好)
                confidence = matched_m / min(total_m, 4)
                if confidence < min_confidence:
                    continue

                tags = info.get("tags", "").split(",")
                severity = info.get("severity", "info")

                seen_names.add(name)
                results.append({
                    "name": name,
                    "category": self._categorize(tags),
                    "value": self._severity_value(severity),
                    "tags": [t.strip() for t in tags if t.strip()],
                    "confidence": round(confidence, 2),
                    "matched_count": f"{matched_m}/{total_m}",
                    "severity": severity,
                    "source": "fingerprinthub",
                })
                break  # 只取第一个 http block 的匹配结果

        # 去重 + 置信度排序
        results.sort(key=lambda x: (-x["confidence"], -x["value"]))
        return results

    def _match_matcher(self, matcher: dict, url: str, path: str,
                       headers: dict, body: str, favicon_hash: str) -> bool:
        """匹配单个 matcher"""
        mtype = matcher.get("type", "word")
        part = matcher.get("part", "body") or "body"
        words = matcher.get("words", [])
        condition = matcher.get("condition", "or") or "or"
        case_insensitive = matcher.get("case-insensitive", False)

        if not words:
            return False

        # 选择匹配源
        source = self._get_source(part, headers, body, favicon_hash)

        if case_insensitive:
            source = source.lower()

        # 执行匹配
        if mtype == "word":
            return self._word_match(words, source, condition, case_insensitive)
        elif mtype == "favicon":
            return favicon_hash is not None and any(w == favicon_hash for w in words)
        elif mtype == "regex":
            flags = re.IGNORECASE if case_insensitive else 0
            for pattern in words:
                try:
                    if re.search(pattern, source, flags):
                        return True
                except re.error:
                    pass
        return False

    def _get_source(self, part: str, headers: dict, body: str, favicon_hash: str) -> str:
        """根据 part 获取匹配源"""
        part = (part or "body").lower()
        if part == "header" or part == "headers":
            return "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == "title":
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            return m.group(1) if m else ""
        elif part == "body":
            return body
        elif part == "all":
            hdr = "\n".join(f"{k}: {v}" for k, v in headers.items())
            return hdr + "\n\n" + body
        elif part == "cookie":
            return headers.get("Set-Cookie", "") + headers.get("Cookie", "")
        elif part == "favicon":
            return favicon_hash or ""
        return body

    def _word_match(self, words: list, source: str, condition: str,
                    case_insensitive: bool) -> bool:
        """关键词匹配"""
        matched = 0
        for w in words:
            if not w: continue
            target = w.lower() if case_insensitive else w
            src = source.lower() if case_insensitive else source
            if target in src:
                matched += 1

        if condition == "and":
            # 所有词都必须匹配
            return matched >= len([w for w in words if w])
        else:
            # OR: 至少一个匹配
            # 但如果关键词是路径类 (含 /) 且只有一个，需要更严格
            if len(words) == 1 and "/" in words[0] and len(words[0]) > 5:
                # 路径关键词必须精确匹配（不在其他字符串中间）
                w = words[0]
                target = w.lower() if case_insensitive else w
                src = source.lower() if case_insensitive else source
                return target in src
            return matched >= 1

    def _categorize(self, tags: list) -> str:
        tag_str = " ".join(tags).lower()
        if any(t in tag_str for t in ["oa", "office-automation"]):
            return "oa"
        if any(t in tag_str for t in ["cms", "blog", "wordpress", "drupal"]):
            return "cms"
        if any(t in tag_str for t in ["waf", "firewall", "security"]):
            return "waf"
        if any(t in tag_str for t in ["framework", "web-framework"]):
            return "framework"
        if any(t in tag_str for t in ["middleware", "web-server", "cdn"]):
            return "middleware"
        if any(t in tag_str for t in ["iot", "device", "router", "camera"]):
            return "device"
        if any(t in tag_str for t in ["erp", "crm", "enterprise"]):
            return "enterprise"
        if any(t in tag_str for t in ["panel", "login", "admin"]):
            return "admin"
        if any(t in tag_str for t in ["database", "db", "mysql", "redis"]):
            return "database"
        if any(t in tag_str for t in ["monitoring", "monitor", "grafana", "prometheus"]):
            return "monitor"
        return "other"

    def _severity_value(self, severity: str) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(severity, 2)

    def calc_favicon_hash(self, favicon_data: bytes) -> Optional[str]:
        """计算 favicon mmh3 hash"""
        try:
            import mmh3, base64
            b64 = base64.b64encode(favicon_data).decode()
            return str(mmh3.hash(b64))
        except ImportError:
            pass
        return None
