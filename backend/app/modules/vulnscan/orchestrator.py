"""Sky-Eye 漏洞扫描编排器 v2

增强:
- 自动标签匹配 POC (替代硬编码映射)
- 按资产价值智能分配 POC 优先级
- 支持批量 URL 扫描
"""

import asyncio
from typing import Dict, List

from app.config import settings
from app.modules.fingerprint.engine import FingerprintEngine
from app.modules.fingerprint.hub_adapter import FingerprintHubAdapter
from app.modules.vulnscan.poc_engine import POCEngine


class VulnOrchestrator:
    """漏洞检测编排器 v2"""

    VALUE_LABELS = {
        5: {"label": "严重", "color": "danger", "badge": "bg-danger", "score": 5},
        4: {"label": "高危", "color": "warning", "badge": "bg-warning text-dark", "score": 4},
        3: {"label": "中危", "color": "info", "badge": "bg-info text-dark", "score": 3},
        2: {"label": "低危", "color": "secondary", "badge": "bg-secondary", "score": 2},
    }

    def __init__(self):
        self.fingerprint_engine = FingerprintEngine()
        self.fingerprint_hub = FingerprintHubAdapter()
        self.poc_engine = POCEngine()

        self.fingerprint_engine.load_fingerprints()
        self.fingerprint_hub.load()
        self.poc_engine.load_poc_dir(str(settings.POC_DIR))

    def get_pocs_for_fingerprint(self, fingerprints: List[Dict]) -> List[str]:
        """根据指纹标签自动匹配 POC

        匹配策略:
        1. 指纹 tags 与 POC tags 交集
        2. 指纹 name 包含在 POC id 中
        3. 指纹 category 匹配 POC 的路径目录
        """
        matched_poc_ids = set()

        # 收集所有指纹标签
        fp_tags = set()
        for fp in fingerprints:
            for tag in fp.get("tags", []):
                fp_tags.add(tag.strip().lower())
            if fp.get("name"):
                fp_tags.add(fp.get("name", "").strip().lower())
            if fp.get("category"):
                fp_tags.add(fp.get("category", "").strip().lower())

        for poc_id, poc in self.poc_engine.pocs.items():
            poc_tags = set()
            if isinstance(poc.tags, str):
                poc_tags = set(t.strip().lower() for t in poc.tags.split(","))
            poc_tags.add(poc_id.lower())

            # 交集匹配
            if fp_tags & poc_tags:
                matched_poc_ids.add(poc_id)
                continue

            # name 包含匹配
            for ft in fp_tags:
                if ft and len(ft) > 2 and ft in poc_id.lower():
                    matched_poc_ids.add(poc_id)
                    break

        return list(matched_poc_ids)

    async def scan_url(self, url: str, headers: dict = None,
                       body: str = "", status_code: int = 200) -> Dict:
        """对单个 URL 执行指纹识别 (双引擎)"""
        if headers is None:
            headers = {}

        result = {
            "url": url,
            "fingerprints": [],
            "asset_value": 2,
            "asset_label": self.VALUE_LABELS[2],
            "poc_matches": [],
            "vulnerable_count": 0,
        }

        # 双引擎指纹匹配
        fps_yaml = self.fingerprint_engine.match(url, status_code, headers, body)
        fps_json = self.fingerprint_hub.match(url, status_code, headers, body)
        all_fps = fps_yaml + fps_json

        result["fingerprints"] = all_fps

        if all_fps:
            max_value = max(fp.get("value", 2) for fp in all_fps)
            result["asset_value"] = max_value
            result["asset_label"] = self.VALUE_LABELS.get(max_value, self.VALUE_LABELS[2])

            # 自动匹配 POC
            poc_ids = self.get_pocs_for_fingerprint(all_fps)
            result["poc_matches"] = poc_ids

        return result

    async def scan_url_with_poc(self, url: str, headers: dict = None,
                                 body: str = "", status_code: int = 200,
                                 max_pocs: int = 10) -> Dict:
        """全链路：指纹识别 → POC 匹配 → POC 执行"""
        result = await self.scan_url(url, headers, body, status_code)
        poc_ids = result.get("poc_matches", [])

        if not poc_ids:
            return result

        # 优先执行高危 POC
        priority_pocs = []
        normal_pocs = []
        for pid in poc_ids:
            poc = self.poc_engine.pocs.get(pid)
            if poc and poc.severity in ["critical", "high"]:
                priority_pocs.append(pid)
            else:
                normal_pocs.append(pid)

        pocs_to_run = (priority_pocs + normal_pocs)[:max_pocs]

        poc_results = await self.poc_engine.execute_batch(url, pocs_to_run, concurrency=3)
        result["poc_results"] = poc_results
        result["vulnerable_count"] = sum(1 for p in poc_results if p.get("vulnerable"))

        return result

    async def scan_batch(self, urls: List[str], max_pocs_per_url: int = 5) -> List[Dict]:
        """批量扫描多个 URL (仅指纹+POC匹配，不执行)"""
        results = []
        for url in urls:
            try:
                r = await self.scan_url(url)
                results.append(r)
            except Exception as e:
                results.append({"url": url, "error": str(e)})
        return results

    def get_dangerous_assets(self, fingerprints: List[Dict]) -> List[Dict]:
        """过滤出高危/严重资产"""
        dangerous = []
        for fp in fingerprints:
            if fp.get("value", 2) >= 4:
                label = self.VALUE_LABELS.get(fp["value"], self.VALUE_LABELS[4])
                dangerous.append({**fp, "label_info": label})
        return dangerous

    def get_asset_summary(self, fingerprints: List[Dict]) -> Dict:
        """资产摘要统计"""
        summary = {"total": len(fingerprints), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for fp in fingerprints:
            v = fp.get("value", 2)
            if v == 5:
                summary["critical"] += 1
            elif v == 4:
                summary["high"] += 1
            elif v == 3:
                summary["medium"] += 1
            else:
                summary["low"] += 1
        return summary
