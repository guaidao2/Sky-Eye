"""Recon 编排器 v2 — 完整信息收集+指纹+轻量漏洞检测 Pipeline

支持智能识别 IP/域名，自动分支执行:
- 域名: 全链路 (空间引擎→子域名→CDN穿透→IP解析→端口→Web→指纹→JS→目录→POC)
- IP:   直达链路 (端口扫描→Web探测→指纹→JS→目录→POC)
"""

import datetime
import json
import re
from typing import Dict, List

import httpx
from sqlalchemy.orm import Session

from app.models import (
    Organization, Domain, Subdomain, IPAddress, Port, URL, JSSensitive, Task,
    Fingerprint, Vulnerability,
)
from app.config import settings
from app.modules.recon.subdomain import SubdomainCollector
from app.modules.recon.ip_resolve import IPResolver
from app.modules.recon.port_scan import PortScanner
from app.modules.recon.web_probe import WebProber
from app.modules.recon.js_extract import JSExtractor
from app.modules.recon.space_engine import SpaceEngineCollector
from app.modules.recon.cdn_bypass import CDNBypass
from app.modules.recon.dir_scanner import DirScanner


class ReconOrchestrator:
    """信息收集编排器 v2 — 全链路 Pipeline"""

    def __init__(self):
        self.subdomain_collector = SubdomainCollector()
        self.ip_resolver = IPResolver()
        self.port_scanner = PortScanner()
        self.web_prober = WebProber()
        self.js_extractor = JSExtractor()
        self.space_engine = SpaceEngineCollector()
        self.cdn_bypass = CDNBypass()
        self.dir_scanner = DirScanner()

    @staticmethod
    def _is_ip_address(target: str) -> bool:
        """判断目标是 IP 还是域名"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target.strip()))

    @staticmethod
    def _is_ip_range(target: str) -> bool:
        """判断是否为 IP 段 (e.g. 192.168.1.0/24)"""
        return "/" in target and re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', target.strip())

    def run_pipeline(self, task_id: int, session: Session) -> Dict:
        """执行 Pipeline — 自动识别目标类型分支执行"""
        import asyncio

        task = session.get(Task, task_id)
        if not task:
            return {"error": "task not found"}

        target = task.target.strip()
        org_id = task.org_id
        is_ip = self._is_ip_address(target)

        org = session.get(Organization, org_id)
        if not org:
            return {"error": "organization not found"}

        task.status = "running"
        task.started_at = datetime.datetime.now()
        task.target_type = "ip" if is_ip else "domain"
        session.commit()

        summary = {
            "target_type": task.target_type,
            "subdomains": 0, "ips": 0, "ports": 0, "urls": 0,
            "js_findings": 0, "fingerprints": 0, "vulns": 0,
            "dir_findings": 0, "cdn_bypass_ips": 0,
        }

        try:
            if is_ip:
                self._run_ip_pipeline(task, target, org_id, session, summary)
            else:
                self._run_domain_pipeline(task, target, org_id, session, summary)

            task.status = "completed"
            task.progress = 100
            task.completed_at = datetime.datetime.now()
            task.result_summary = json.dumps(summary, ensure_ascii=False)
            session.commit()
            return {"status": "completed", "summary": summary}

        except Exception as e:
            import traceback
            task.status = "failed"
            task.error = f"{type(e).__name__}: {str(e)[:500]}"
            task.completed_at = datetime.datetime.now()
            session.commit()
            return {"status": "failed", "error": str(e), "traceback": traceback.format_exc()}

    # ═══════════════════════ 域名 Pipeline ═══════════════════════

    def _run_domain_pipeline(self, task, target, org_id, session, summary):
        import asyncio

        # Phase 0: 空间搜索引擎
        task.progress = 5; session.commit()
        space_results = {"subdomains": set(), "ips": set(), "urls": set()}
        try:
            space_results = asyncio.run(self.space_engine.collect_all(target))
            summary["space_engine_sources"] = space_results.get("sources", {})
        except Exception as e:
            print(f"  [SpaceEngine] 跳过: {e}")

        # Phase 1: 子域名收集
        task.progress = 10; session.commit()
        domain_obj = session.query(Domain).filter(
            Domain.org_id == org_id, Domain.domain == target
        ).first()
        if not domain_obj:
            domain_obj = Domain(org_id=org_id, domain=target, source="manual")
            session.add(domain_obj); session.commit()

        subdomain_result = asyncio.run(self.subdomain_collector.collect(target))
        subdomains = list(subdomain_result["subdomains"])
        for sd in space_results.get("subdomains", set()):
            if sd not in subdomains:
                subdomains.append(sd)
        summary["subdomains"] = len(subdomains)

        # Phase 1.2: 子域名智能分类评分
        from app.modules.recon.subdomain_analyzer import SubdomainAnalyzer
        analyzer = SubdomainAnalyzer()
        analyzed = analyzer.analyze_batch(subdomains)
        attack_surface = analyzer.get_attack_surface_summary(analyzed)
        summary["attack_surface"] = attack_surface
        # 更新数据库中的分类和优先级
        for a in analyzed:
            db_sd = session.query(Subdomain).filter(
                Subdomain.domain_id == domain_obj.id, Subdomain.subdomain == a["subdomain"]
            ).first()
            if db_sd:
                db_sd.category = a["category"]
                db_sd.priority = a["priority"]
        session.commit()

        for sd in subdomains:
            if not session.query(Subdomain).filter(
                Subdomain.domain_id == domain_obj.id, Subdomain.subdomain == sd
            ).first():
                # 查找分类信息
                info = next((a for a in analyzed if a["subdomain"] == sd), None)
                session.add(Subdomain(
                    domain_id=domain_obj.id, subdomain=sd, source="auto",
                    category=info["category"] if info else "other",
                    priority=info["priority"] if info else 1,
                ))
        session.commit()

        # Phase 1.5: CDN 穿透
        task.progress = 20; session.commit()
        try:
            cdn_result = asyncio.run(self.cdn_bypass.find_real_ip(target))
            summary["cdn_bypass_ips"] = len(cdn_result.get("real_ips", set()))
            for ip_str in cdn_result.get("real_ips", set()):
                if not session.query(IPAddress).filter(IPAddress.ip == ip_str).first():
                    session.add(IPAddress(ip=ip_str, is_alive=True, is_cdn=False))
            session.commit()
        except Exception as e:
            print(f"  [CDN] 跳过: {e}")

        # Phase 2: IP 解析
        task.progress = 30; session.commit()
        ip_result = asyncio.run(self.ip_resolver.resolve(subdomains[:200]))
        ip_map = {}
        for item in ip_result:
            for ip_str in item.get("ips", []):
                ip_obj = session.query(IPAddress).filter(IPAddress.ip == ip_str).first()
                if not ip_obj:
                    ip_obj = IPAddress(ip=ip_str, is_alive=True, is_cdn=self.cdn_bypass.is_cdn_ip(ip_str))
                    session.add(ip_obj); session.flush()
                ip_map[ip_str] = ip_obj
        for ip_str in space_results.get("ips", set()):
            if ip_str not in ip_map:
                if not session.query(IPAddress).filter(IPAddress.ip == ip_str).first():
                    ip_obj = IPAddress(ip=ip_str, is_alive=True)
                    session.add(ip_obj); session.flush()
                ip_map[ip_str] = ip_obj
        session.commit()
        summary["ips"] = len(ip_map)

        # Phase 3-6: 端口 + Web + 指纹 + JS/目录 + POC（通用）
        self._run_scan_phases(task, target, org_id, session, summary, ip_map, subdomains)
        session.commit()

    # ═══════════════════════ IP Pipeline ═══════════════════════

    def _run_ip_pipeline(self, task, target, org_id, session, summary):
        import asyncio

        # IP 目标：直接入库
        ip_obj = session.query(IPAddress).filter(IPAddress.ip == target).first()
        if not ip_obj:
            ip_obj = IPAddress(ip=target, is_alive=True)
            session.add(ip_obj); session.flush()
        ip_map = {target: ip_obj}
        summary["ips"] = 1

        # 跳过域名阶段，直接进入端口扫描
        task.progress = 20; session.commit()
        print(f"  [Pipeline] IP 模式: {target} — 跳过子域名/CDN/DNS，直接端口扫描")

        self._run_scan_phases(task, target, org_id, session, summary, ip_map, [])
        session.commit()

    # ═══════════════════════ 通用扫描阶段 (Phase 3-6) ═══════════════════════

    def _run_scan_phases(self, task, target, org_id, session, summary, ip_map, subdomains):
        import asyncio

        # Phase 3: 端口扫描
        task.progress = 45; session.commit()
        all_ports = []
        all_targets_for_web = []

        for ip_str, ip_obj in list(ip_map.items())[:30]:
            try:
                open_ports = asyncio.run(self.port_scanner.scan(ip_str, grab_banner=settings.PORT_SCAN_BANNER))
            except Exception:
                continue
            for p in open_ports:
                is_http = p["port"] in [80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 9443, 18080,
                                         3000, 5000, 8081, 8088, 8880, 9000, 9001, 9091, 9200, 9443]
                port_obj = Port(
                    ip_id=ip_obj.id, port=p["port"],
                    protocol=p.get("protocol", "tcp"), state=p.get("state", "open"),
                    service=p.get("service"), banner=p.get("banner", ""),
                    is_http=is_http,
                )
                session.add(port_obj); session.flush()
                all_ports.append(port_obj)
                if is_http:
                    scheme = "https" if p["port"] in [443, 8443, 9443] else "http"
                    all_targets_for_web.append({"host": ip_str, "port": p["port"], "scheme": scheme})
        session.commit()
        summary["ports"] = len(all_ports)

        # Phase 4: Web 存活探测
        task.progress = 60; session.commit()
        web_results = asyncio.run(self.web_prober.probe(all_targets_for_web))
        # 子域名 Web（仅域名模式）
        if subdomains:
            sd_targets = []
            for sd in subdomains[:50]:
                sd_targets.append({"host": sd, "port": 80, "scheme": "http"})
                sd_targets.append({"host": sd, "port": 443, "scheme": "https"})
            sd_web = asyncio.run(self.web_prober.probe(sd_targets))
            web_results += sd_web

        url_count = 0
        url_objects = []
        all_web_results = web_results

        for wr in all_web_results:
            if wr.get("alive"):
                existing = session.query(URL).filter(URL.url == wr["url"]).first()
                if existing:
                    url_objects.append(existing); continue
                url_obj = URL(
                    url=wr["url"], scheme=wr["scheme"], host=wr["host"],
                    port=wr["port"], status_code=wr.get("status_code"),
                    title=wr.get("title"), content_type=wr.get("content_type"),
                    content_length=wr.get("content_length"),
                    tech_stack=wr.get("tech_stack"),
                )
                session.add(url_obj); session.flush()
                url_objects.append(url_obj)
                url_count += 1
        session.commit()
        summary["urls"] = url_count

        # Phase 4.5: 指纹识别
        task.progress = 70; session.commit()
        fp_count = self._run_fingerprint_phase(session, url_objects, all_web_results)
        summary["fingerprints"] = fp_count

        # Phase 5: JS + 目录扫描
        task.progress = 80; session.commit()
        for wr in all_web_results:
            if not wr.get("alive"): continue
            if wr.get("status_code") == 200 and str(wr.get("content_type", "")).startswith("text/html"):
                try:
                    analysis = self._analyze_page_sync(wr["url"])
                    url_obj = session.query(URL).filter(URL.url == wr["url"]).first()
                    if url_obj:
                        for finding in analysis.get("findings", []):
                            session.add(JSSensitive(
                                url_id=url_obj.id, info_type=finding["type"],
                                content=finding["content"],
                                source_url=finding.get("source_url"),
                            ))
                            summary["js_findings"] += 1
                except Exception: pass

            try:
                dir_results = asyncio.run(self.dir_scanner.scan(wr["url"], "all"))
                summary["dir_findings"] += len(dir_results)
                url_obj = session.query(URL).filter(URL.url == wr["url"]).first()
                for dr in dir_results[:20]:
                    if dr.get("priority", 0) >= 5 and url_obj:
                        if not session.query(Vulnerability).filter(
                            Vulnerability.url_id == url_obj.id,
                            Vulnerability.name == f"敏感路径: {dr['url']}",
                        ).first():
                            session.add(Vulnerability(
                                url_id=url_obj.id, org_id=org_id,
                                name=f"敏感路径: {dr['url']}", vuln_type="infoleak",
                                severity="medium" if dr.get("priority", 0) >= 7 else "low",
                                target=dr["url"],
                                description=f"发现敏感路径 {dr['url']}，状态码 {dr.get('status_code')}",
                                evidence=f"Status: {dr.get('status_code')}",
                            ))
                            summary["vulns"] += 1
            except Exception: pass
        session.commit()

        # Phase 6: 自动 POC
        task.progress = 90; session.commit()
        poc_vuln_count = self._run_auto_poc_phase(session, url_objects, org_id)
        summary["vulns"] += poc_vuln_count

    # ═══════════════════════ 子阶段方法 ═══════════════════════

    def _run_fingerprint_phase(self, session: Session, url_objects: List, web_results: List) -> int:
        try:
            from app.modules.fingerprint.engine import FingerprintEngine
            from app.modules.fingerprint.hub_adapter import FingerprintHubAdapter
            engine = FingerprintEngine()
            adapter = FingerprintHubAdapter(); adapter.load()
            count = 0
            for wr in web_results:
                if not wr.get("alive") or wr.get("status_code") not in [200, 301, 302, 403, 401, 500]:
                    continue
                url_str = wr.get("url", "")
                status_code = wr.get("status_code", 0)
                headers = wr.get("headers", {})
                body = ""
                try:
                    resp = httpx.get(url_str, timeout=10, verify=False,
                                     headers={"User-Agent": "Mozilla/5.0"})
                    body = resp.text[:50000]
                except Exception: pass
                fps_yaml = engine.match(url_str, status_code, headers, body)
                fps_json = adapter.match(url_str, status_code, headers, body)
                all_fps = fps_yaml + fps_json
                if not all_fps: continue
                url_obj = session.query(URL).filter(URL.url == url_str).first()
                if not url_obj: continue
                for fp in all_fps:
                    session.add(Fingerprint(
                        url_id=url_obj.id, name=fp.get("name", "Unknown"),
                        category=fp.get("category", "unknown"),
                        value_level=fp.get("value", 2),
                        tags=",".join(fp.get("tags", [])),
                        matched_rules=json.dumps(fp.get("matched_rules", []), ensure_ascii=False),
                    ))
                    count += 1
            session.commit(); return count
        except Exception as e:
            print(f"  [指纹] 阶段失败: {e}"); return 0

    def _run_auto_poc_phase(self, session: Session, url_objects: List, org_id: int) -> int:
        count = 0
        try:
            from app.modules.vulnscan.poc_engine import POCEngine
            poc_engine = POCEngine()
            poc_engine.load_poc_dir(str(settings.POC_DIR))
            if not poc_engine.pocs: return 0

            import asyncio
            for url_obj in url_objects[:10]:
                fps = session.query(Fingerprint).filter(Fingerprint.url_id == url_obj.id).all()
                if not fps: continue
                fp_tags = set()
                for fp in fps:
                    if fp.tags:
                        fp_tags.update(t.strip().lower() for t in fp.tags.split(","))
                    if fp.name: fp_tags.add(fp.name.lower())

                matched_pocs = []
                for poc_id, poc in poc_engine.pocs.items():
                    poc_tags = set(t.strip().lower() for t in (poc.tags if isinstance(poc.tags, str) else "").split(","))
                    if fp_tags & poc_tags or any(tag in poc_id.lower() for tag in fp_tags if len(tag) > 2):
                        matched_pocs.append(poc_id)

                if not matched_pocs: continue
                priority = [p for p in matched_pocs if poc_engine.pocs[p].severity in ("critical", "high")]
                pocs_to_run = (priority or matched_pocs)[:5]
                try:
                    results = asyncio.run(poc_engine.execute_batch(url_obj.url, pocs_to_run, concurrency=3))
                    for pr in results:
                        if pr.get("vulnerable"):
                            if not session.query(Vulnerability).filter(
                                Vulnerability.url_id == url_obj.id,
                                Vulnerability.poc_id == pr.get("poc_id"),
                            ).first():
                                session.add(Vulnerability(
                                    url_id=url_obj.id, org_id=org_id,
                                    name=pr.get("name", "POC"), vuln_type="other",
                                    severity=pr.get("severity", "info"),
                                    target=url_obj.url, poc_id=pr.get("poc_id"),
                                    evidence=json.dumps(pr.get("matched", [])[:500], ensure_ascii=False),
                                ))
                                count += 1
                except Exception as e:
                    print(f"  [POC] {url_obj.url}: {e}")
            session.commit()
        except Exception as e:
            print(f"  [POC] 阶段失败: {e}")
        return count

    def _analyze_page_sync(self, url: str) -> Dict:
        import asyncio
        try:
            resp = httpx.get(url, timeout=15, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                return asyncio.run(self.js_extractor.analyze_page(url, resp.text))
        except Exception: pass
        return {"url": url, "findings": [], "js_files": []}

    def _map_severity_to_type(self, severity: str) -> str:
        return {"critical": "rce", "high": "sqli", "medium": "unauth", "low": "infoleak"}.get(severity, "infoleak")
