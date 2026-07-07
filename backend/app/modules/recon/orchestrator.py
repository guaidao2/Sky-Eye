"""Recon 编排器 v2 — 完整信息收集+指纹+轻量漏洞检测 Pipeline"""

import datetime
import socket
import json
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

    def run_pipeline(self, task_id: int, session: Session) -> Dict:
        """执行完整信息收集 + 指纹 Pipeline"""
        import asyncio

        task = session.get(Task, task_id)
        if not task:
            return {"error": "task not found"}

        target = task.target
        org_id = task.org_id

        org = session.get(Organization, org_id)
        if not org:
            return {"error": "organization not found"}

        task.status = "running"
        task.started_at = datetime.datetime.now()
        session.commit()

        summary = {
            "subdomains": 0, "ips": 0, "ports": 0, "urls": 0,
            "js_findings": 0, "fingerprints": 0, "vulns": 0,
            "dir_findings": 0, "cdn_bypass_ips": 0,
        }

        try:
            # ═══ Phase 0: 空间搜索引擎回填 ═══
            task.progress = 5
            session.commit()
            space_results = {"subdomains": set(), "ips": set(), "urls": set()}
            try:
                space_results = asyncio.run(self.space_engine.collect_all(target))
                summary["space_engine_sources"] = space_results.get("sources", {})
            except Exception as e:
                print(f"  [SpaceEngine] 跳过: {e}")

            # ═══ Phase 1: 子域名收集 ═══
            task.progress = 10
            session.commit()

            domain_obj = session.query(Domain).filter(
                Domain.org_id == org_id, Domain.domain == target
            ).first()
            if not domain_obj:
                domain_obj = Domain(org_id=org_id, domain=target, source="manual")
                session.add(domain_obj)
                session.commit()

            subdomain_result = asyncio.run(self.subdomain_collector.collect(target))
            subdomains = list(subdomain_result["subdomains"])
            # 合并空间搜索引擎的子域名
            for sd in space_results.get("subdomains", set()):
                if sd not in subdomains:
                    subdomains.append(sd)
            summary["subdomains"] = len(subdomains)

            for sd in subdomains:
                existing = session.query(Subdomain).filter(
                    Subdomain.domain_id == domain_obj.id,
                    Subdomain.subdomain == sd,
                ).first()
                if not existing:
                    sub = Subdomain(domain_id=domain_obj.id, subdomain=sd, source="auto")
                    session.add(sub)
            session.commit()

            # ═══ Phase 1.5: CDN 穿透 ═══
            task.progress = 20
            session.commit()
            try:
                cdn_result = asyncio.run(self.cdn_bypass.find_real_ip(target))
                summary["cdn_bypass_ips"] = len(cdn_result.get("real_ips", set()))
                for ip_str in cdn_result.get("real_ips", set()):
                    ip_obj = session.query(IPAddress).filter(IPAddress.ip == ip_str).first()
                    if not ip_obj:
                        ip_obj = IPAddress(ip=ip_str, is_alive=True, is_cdn=False)
                        session.add(ip_obj)
                        session.flush()
            except Exception as e:
                print(f"  [CDN] 跳过: {e}")
            session.commit()

            # ═══ Phase 2: IP 解析 ═══
            task.progress = 30
            session.commit()

            all_hosts = subdomains[:200]  # 限制批量解析数量
            ip_result = asyncio.run(self.ip_resolver.resolve(all_hosts))
            ip_map = {}

            for item in ip_result:
                for ip_str in item.get("ips", []):
                    ip_obj = session.query(IPAddress).filter(IPAddress.ip == ip_str).first()
                    if not ip_obj:
                        is_cdn_ip = self.cdn_bypass.is_cdn_ip(ip_str)
                        ip_obj = IPAddress(ip=ip_str, is_alive=True, is_cdn=is_cdn_ip)
                        session.add(ip_obj)
                        session.flush()
                    ip_map[ip_str] = ip_obj

            # 添加空间搜索引擎 IP
            for ip_str in space_results.get("ips", set()):
                if ip_str not in ip_map:
                    ip_obj = session.query(IPAddress).filter(IPAddress.ip == ip_str).first()
                    if not ip_obj:
                        ip_obj = IPAddress(ip=ip_str, is_alive=True)
                        session.add(ip_obj)
                        session.flush()
                    ip_map[ip_str] = ip_obj
            session.commit()
            summary["ips"] = len(ip_map)

            # ═══ Phase 3: 端口扫描 ═══
            task.progress = 45
            session.commit()

            all_ports = []
            all_targets_for_web = []
            ip_list = list(ip_map.items())[:30]  # 限制 IP 数

            for ip_str, ip_obj in ip_list:
                try:
                    open_ports = asyncio.run(self.port_scanner.scan(ip_str, grab_banner=settings.PORT_SCAN_BANNER))
                except Exception:
                    continue
                for p in open_ports:
                    port_obj = Port(
                        ip_id=ip_obj.id,
                        port=p["port"],
                        protocol=p.get("protocol", "tcp"),
                        state=p.get("state", "open"),
                        service=p.get("service"),
                        banner=p.get("banner", ""),
                        is_http=(p["port"] in [80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 9443, 18080]),
                    )
                    session.add(port_obj)
                    session.flush()
                    all_ports.append(port_obj)

                    if port_obj.is_http:
                        scheme = "https" if p["port"] in [443, 8443, 9443] else "http"
                        all_targets_for_web.append({
                            "host": ip_str,
                            "port": p["port"],
                            "scheme": scheme,
                        })
            session.commit()
            summary["ports"] = len(all_ports)

            # ═══ Phase 4: Web 存活探测 ═══
            task.progress = 60
            session.commit()

            web_results = asyncio.run(self.web_prober.probe(all_targets_for_web))

            # 子域名 Web 探测
            subdomain_targets = []
            for sd in subdomains[:50]:
                subdomain_targets.append({"host": sd, "port": 80, "scheme": "http"})
                subdomain_targets.append({"host": sd, "port": 443, "scheme": "https"})
            subdomain_web_results = asyncio.run(self.web_prober.probe(subdomain_targets))
            all_web_results = web_results + subdomain_web_results

            url_count = 0
            url_objects = []

            for wr in all_web_results:
                if wr.get("alive"):
                    # 去重检查
                    existing = session.query(URL).filter(URL.url == wr["url"]).first()
                    if existing:
                        url_objects.append(existing)
                        continue

                    url_obj = URL(
                        url=wr["url"],
                        scheme=wr["scheme"],
                        host=wr["host"],
                        port=wr["port"],
                        status_code=wr.get("status_code"),
                        title=wr.get("title"),
                        content_type=wr.get("content_type"),
                        content_length=wr.get("content_length"),
                        tech_stack=wr.get("tech_stack"),
                    )
                    session.add(url_obj)
                    session.flush()
                    url_objects.append(url_obj)
                    url_count += 1
            session.commit()
            summary["urls"] = url_count

            # ═══ Phase 4.5: 指纹识别 ═══
            task.progress = 70
            session.commit()
            fp_count = self._run_fingerprint_phase(session, url_objects, all_web_results)
            summary["fingerprints"] = fp_count

            # ═══ Phase 5: JS 分析 + 目录扫描 ═══
            task.progress = 80
            session.commit()

            for wr in all_web_results:
                if not wr.get("alive"):
                    continue
                if wr.get("status_code") == 200 and str(wr.get("content_type", "")).startswith("text/html"):
                    try:
                        analysis = self._analyze_page_sync(wr["url"])
                        url_obj = session.query(URL).filter(URL.url == wr["url"]).first()
                        if url_obj:
                            for finding in analysis.get("findings", []):
                                js_sensitive = JSSensitive(
                                    url_id=url_obj.id,
                                    info_type=finding["type"],
                                    content=finding["content"],
                                    source_url=finding.get("source_url"),
                                )
                                session.add(js_sensitive)
                                summary["js_findings"] += 1
                    except Exception:
                        pass

                # 目录扫描（对每个存活 Web）
                try:
                    dir_results = asyncio.run(self.dir_scanner.scan(wr["url"], "all"))
                    summary["dir_findings"] += len(dir_results)
                    # 将高优先级的目录发现存为漏洞记录
                    url_obj = session.query(URL).filter(URL.url == wr["url"]).first()
                    for dr in dir_results[:20]:  # 只保存前20个最重要的
                        if dr.get("priority", 0) >= 5 and url_obj:
                            existing_vuln = session.query(Vulnerability).filter(
                                Vulnerability.url_id == url_obj.id,
                                Vulnerability.name == f"敏感路径: {dr['url']}",
                            ).first()
                            if not existing_vuln:
                                vuln = Vulnerability(
                                    url_id=url_obj.id,
                                    org_id=org_id,
                                    name=f"敏感路径: {dr['url']}",
                                    vuln_type="infoleak",
                                    severity="medium" if dr.get("priority", 0) >= 7 else "low",
                                    target=dr["url"],
                                    description=f"发现敏感路径 {dr['url']}，状态码 {dr.get('status_code')}，"
                                                f"分类: {dr.get('category')}",
                                    evidence=f"Status: {dr.get('status_code')}, Length: {dr.get('content_length')}",
                                )
                                session.add(vuln)
                                summary["vulns"] += 1
                except Exception:
                    pass
            session.commit()

            # ═══ Phase 6: 自动 POC 匹配 ═══
            task.progress = 90
            session.commit()
            poc_vuln_count = self._run_auto_poc_phase(session, url_objects, org_id)
            summary["vulns"] += poc_vuln_count

            # ═══ 完成 ═══
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

    def _run_fingerprint_phase(self, session: Session, url_objects: List, web_results: List) -> int:
        """Phase 4.5: 指纹识别"""
        try:
            from app.modules.fingerprint.engine import FingerprintEngine
            from app.modules.fingerprint.hub_adapter import FingerprintHubAdapter

            engine = FingerprintEngine()
            adapter = FingerprintHubAdapter()
            adapter.load()

            count = 0
            for wr in web_results:
                if not wr.get("alive") or wr.get("status_code") not in [200, 301, 302, 403, 401, 500]:
                    continue

                url_str = wr.get("url", "")
                status_code = wr.get("status_code", 0)
                headers = wr.get("headers", {})
                body = ""
                # Try to get body from the probe result
                try:
                    resp = httpx.get(url_str, timeout=10, verify=False,
                                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                                            "AppleWebKit/537.36 Chrome/120.0.0.0"})
                    body = resp.text[:50000]
                except Exception:
                    pass

                # 双引擎匹配
                fps_yaml = engine.match(url_str, status_code, headers, body)
                fps_json = adapter.match(url_str, status_code, headers, body)

                all_fps = fps_yaml + fps_json
                if not all_fps:
                    continue

                url_obj = session.query(URL).filter(URL.url == url_str).first()
                if not url_obj:
                    continue

                for fp in all_fps:
                    fp_record = Fingerprint(
                        url_id=url_obj.id,
                        name=fp.get("name", "Unknown"),
                        category=fp.get("category", "unknown"),
                        value_level=fp.get("value", 2),
                        tags=",".join(fp.get("tags", [])),
                        matched_rules=json.dumps(fp.get("matched_rules", []), ensure_ascii=False),
                        confidence=fp.get("confidence", 1.0),
                    )
                    session.add(fp_record)
                    count += 1
            session.commit()
            return count
        except Exception as e:
            print(f"  [指纹] 阶段失败: {e}")
            return 0

    def _run_auto_poc_phase(self, session: Session, url_objects: List, org_id: int) -> int:
        """Phase 6: 根据指纹自动匹配并执行 POC"""
        count = 0
        try:
            from app.modules.vulnscan.poc_engine import POCEngine
            from app.modules.vulnscan.orchestrator import VulnOrchestrator

            poc_engine = POCEngine()
            poc_engine.load_poc_dir(str(settings.POC_DIR))

            if not poc_engine.pocs:
                return 0

            vuln_orch = VulnOrchestrator()
            # 注入已加载的 POC 引擎
            vuln_orch.poc_engine = poc_engine
            vuln_orch.fingerprint_engine.load_fingerprints()

            for url_obj in url_objects[:20]:  # 限制 POC 执行数量，避免时间过长
                fps = session.query(Fingerprint).filter(Fingerprint.url_id == url_obj.id).all()
                if not fps:
                    continue

                fp_tags = set()
                for fp in fps:
                    if fp.tags:
                        for t in fp.tags.split(","):
                            fp_tags.add(t.strip().lower())
                    if fp.name:
                        fp_tags.add(fp.name.lower())

                # 标签→POC 匹配（改为自动匹配）
                matched_pocs = []
                for poc_id, poc in poc_engine.pocs.items():
                    poc_tags = set(t.strip().lower() for t in (poc.tags if isinstance(poc.tags, str) else []))
                    if fp_tags & poc_tags or any(tag in poc_id.lower() for tag in fp_tags):
                        matched_pocs.append(poc_id)

                if not matched_pocs:
                    continue

                # 对匹配到的 POC 进行高价值检测
                import asyncio
                priority_pocs = [pid for pid in matched_pocs if
                                 poc_engine.pocs[pid].severity in ["critical", "high"]]
                pocs_to_run = priority_pocs[:5] if priority_pocs else matched_pocs[:5]

                try:
                    poc_results = asyncio.run(poc_engine.execute_batch(url_obj.url, pocs_to_run, concurrency=3))
                    for pr in poc_results:
                        if pr.get("vulnerable"):
                            existing = session.query(Vulnerability).filter(
                                Vulnerability.url_id == url_obj.id,
                                Vulnerability.poc_id == pr.get("poc_id"),
                            ).first()
                            if not existing:
                                vuln = Vulnerability(
                                    url_id=url_obj.id,
                                    org_id=org_id,
                                    name=pr.get("name", "POC检测"),
                                    vuln_type=self._map_severity_to_type(pr.get("severity", "info")),
                                    severity=pr.get("severity", "info"),
                                    target=url_obj.url,
                                    description=pr.get("description", ""),
                                    poc_id=pr.get("poc_id"),
                                    evidence=json.dumps(pr.get("matched", [])[:500], ensure_ascii=False),
                                )
                                session.add(vuln)
                                count += 1
                except Exception as e:
                    print(f"  [POC] {url_obj.url} 执行失败: {e}")

            session.commit()
        except Exception as e:
            print(f"  [POC] 阶段失败: {e}")
        return count

    def _map_severity_to_type(self, severity: str) -> str:
        """严重度→漏洞类型映射"""
        mapping = {
            "critical": "rce",
            "high": "sqli",
            "medium": "unauth",
            "low": "infoleak",
        }
        return mapping.get(severity, "infoleak")

    def _analyze_page_sync(self, url: str) -> Dict:
        """同步分析页面 JS"""
        import asyncio
        try:
            resp = httpx.get(url, timeout=15, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                                    "AppleWebKit/537.36 Chrome/120.0.0.0"})
            if resp.status_code == 200:
                return asyncio.run(self.js_extractor.analyze_page(url, resp.text))
        except Exception:
            pass
        return {"url": url, "findings": [], "js_files": []}
