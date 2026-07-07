"""Sky-Eye 指纹识别引擎

从 YAML 指纹库加载规则，对 HTTP 响应进行多维度匹配
匹配维度：响应头 / HTML 正文 / URL 路径 / Favicon 哈希 / JSON 响应
"""

import hashlib
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.config import settings


class FingerprintEngine:
    """指纹识别引擎"""

    def __init__(self):
        self.fingerprints = []
        self._loaded = False

    def load_fingerprints(self):
        """从 YAML 文件加载指纹库"""
        if self._loaded:
            return

        fp_dir = settings.FINGERPRINT_DIR
        # 也支持从模块同级目录加载
        alt_dir = Path(__file__).resolve().parent / "yaml"

        yaml_files = []
        if fp_dir.exists():
            yaml_files.extend(fp_dir.glob("*.yaml"))
            yaml_files.extend(fp_dir.glob("*.yml"))
        if alt_dir.exists():
            yaml_files.extend(alt_dir.glob("*.yaml"))
            yaml_files.extend(alt_dir.glob("*.yml"))

        for yf in yaml_files:
            try:
                with open(yf, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, list):
                        self.fingerprints.extend(data)
                    elif isinstance(data, dict):
                        self.fingerprints.append(data)
            except Exception as e:
                print(f"  [指纹] 加载 {yf} 失败: {e}")

        self._loaded = True
        print(f"  [指纹] 已加载 {len(self.fingerprints)} 条规则")

    def match(self, url: str, status_code: int, headers: dict,
              body: str = "", favicon_hash: str = None,
              min_confidence: float = 0.3) -> List[Dict]:
        """对单个 Web 资产执行指纹匹配"""
        if not self._loaded:
            self.load_fingerprints()

        results = []
        parsed = urlparse(url)
        path = parsed.path or "/"
        seen = set()

        for fp in self.fingerprints:
            name = fp.get("name", "")
            if not name or name in seen:
                continue

            rules = fp.get("rules", [])
            if not rules:
                continue

            rules_condition = fp.get("condition", "or")
            total_rules = len(rules)
            matched_count = 0
            matched_rules = []

            for rule in rules:
                rule_type = rule.get("type", "")
                pattern = rule.get("pattern", "")
                match_field = rule.get("match", "")

                if self._match_rule(rule_type, pattern, match_field,
                                    url, path, headers, body, favicon_hash):
                    matched_count += 1
                    matched_rules.append(f"{rule_type}:{pattern[:30]}")

            if matched_count == 0:
                continue

            if rules_condition == "and" and matched_count < total_rules:
                continue

            confidence = matched_count / min(total_rules, 4)
            if confidence < min_confidence:
                continue

            seen.add(name)
            results.append({
                "name": name,
                "category": fp.get("category", "unknown"),
                "value": fp.get("value", 2),
                "tags": fp.get("tags", []),
                "confidence": round(confidence, 2),
                "matched_count": f"{matched_count}/{total_rules}",
                "matched_rules": matched_rules,
                "source": "yaml",
            })

        results.sort(key=lambda x: (-x["confidence"], -x["value"]))
        return results

    def _match_rule(self, rule_type: str, pattern: str,
                    match_field: str, url: str, path: str,
                    headers: dict, body: str, favicon_hash: str) -> bool:
        """匹配单条规则"""
        try:
            if rule_type == "header":
                value = headers.get(match_field, "")
                return bool(re.search(pattern, str(value), re.IGNORECASE))

            elif rule_type == "body":
                return bool(re.search(pattern, body, re.IGNORECASE))

            elif rule_type == "url":
                return bool(re.search(pattern, path, re.IGNORECASE))

            elif rule_type == "favicon":
                return favicon_hash == pattern

            elif rule_type == "json":
                return bool(re.search(pattern, body, re.IGNORECASE))

        except re.error:
            pass
        return False

    def calc_favicon_hash(self, favicon_data: bytes) -> Optional[str]:
        """计算 Favicon 的 mmh3 hash (用于匹配)"""
        try:
            import mmh3
            import base64
            b64 = base64.b64encode(favicon_data).decode()
            return str(mmh3.hash(b64))
        except ImportError:
            pass
        return None

    def get_asset_value_label(self, value: int) -> Dict:
        """获取资产价值对应的高亮标签"""
        levels = {
            5: {"label": "严重", "color": "danger", "icon": "🔥"},
            4: {"label": "高危", "color": "warning", "icon": "⚡"},
            3: {"label": "中危", "color": "info", "icon": "📌"},
            2: {"label": "低危", "color": "secondary", "icon": "💡"},
        }
        return levels.get(value, levels[2])
