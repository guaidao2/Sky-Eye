"""Sky-Eye API 路由 v2"""

import datetime
import json
import threading
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import (
    Organization, Domain, Subdomain, IPAddress, Port, URL, JSSensitive, Task,
    Fingerprint, Vulnerability,
)
from app.schemas import (
    OrganizationCreate, OrganizationResponse,
    DomainResponse, SubdomainResponse,
    IPResponse, PortResponse, URLResponse,
    JSSensitiveResponse,
    TaskCreate, TaskResponse,
    AssetOverview,
    FingerprintResponse, VulnerabilityCreate, VulnerabilityResponse, VulnerabilityUpdate,
    ScanRequest, DirScanRequest, WeakPassRequest, ReportRequest, ReportResponse,
)
from app.config import settings

router = APIRouter()

# ═══════════════════════════════════════
# 资产概览
# ═══════════════════════════════════════

@router.get("/overview", response_model=AssetOverview)
def get_overview(db: Session = Depends(get_db)):
    counts = {}
    for model, name in [
        (Organization, "organizations"),
        (Domain, "domains"),
        (Subdomain, "subdomains"),
        (IPAddress, "ips"),
        (Port, "ports"),
        (URL, "urls"),
        (JSSensitive, "js_sensitives"),
        (Task, "tasks"),
    ]:
        counts[name] = db.query(func.count(model.id)).scalar() or 0
    return AssetOverview(**counts)


# ═══════════════════════════════════════
# 组织管理
# ═══════════════════════════════════════

@router.get("/organizations", response_model=List[OrganizationResponse])
def list_organizations(db: Session = Depends(get_db)):
    return db.query(Organization).order_by(Organization.created_at.desc()).all()


@router.post("/organizations", response_model=OrganizationResponse)
def create_organization(data: OrganizationCreate, db: Session = Depends(get_db)):
    org = Organization(**data.model_dump())
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
def get_organization(org_id: int, db: Session = Depends(get_db)):
    org = db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="组织不存在")
    return org


@router.delete("/organizations/{org_id}")
def delete_organization(org_id: int, db: Session = Depends(get_db)):
    org = db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="组织不存在")
    db.delete(org)
    db.commit()
    return {"message": "删除成功"}


# ═══════════════════════════════════════
# 域名资产
# ═══════════════════════════════════════

@router.get("/organizations/{org_id}/domains", response_model=List[DomainResponse])
def list_domains(org_id: int, db: Session = Depends(get_db)):
    return db.query(Domain).filter(Domain.org_id == org_id).order_by(Domain.first_seen.desc()).all()


@router.get("/organizations/{org_id}/subdomains", response_model=List[SubdomainResponse])
def list_subdomains(org_id: int, db: Session = Depends(get_db)):
    return (
        db.query(Subdomain)
        .join(Domain, Subdomain.domain_id == Domain.id)
        .filter(Domain.org_id == org_id)
        .order_by(Subdomain.first_seen.desc())
        .limit(500)
        .all()
    )


# ═══════════════════════════════════════
# IP 资产
# ═══════════════════════════════════════

@router.get("/ips", response_model=List[IPResponse])
def list_ips(db: Session = Depends(get_db)):
    return db.query(IPAddress).order_by(IPAddress.first_seen.desc()).limit(500).all()


@router.get("/ips/{ip_id}/ports", response_model=List[PortResponse])
def list_ports(ip_id: int, db: Session = Depends(get_db)):
    return db.query(Port).filter(Port.ip_id == ip_id).order_by(Port.port).all()


# ═══════════════════════════════════════
# URL 资产
# ═══════════════════════════════════════

@router.get("/urls", response_model=List[URLResponse])
def list_urls(
    org_id: int = Query(None),
    status_code: int = Query(None),
    search: str = Query(""),
    limit: int = Query(500),
    db: Session = Depends(get_db),
):
    q = db.query(URL)
    if org_id:
        q = q.join(Domain, URL.host == Domain.domain).filter(Domain.org_id == org_id)
    if status_code:
        q = q.filter(URL.status_code == status_code)
    if search:
        q = q.filter(URL.url.contains(search) | URL.title.contains(search))
    return q.order_by(URL.first_seen.desc()).limit(limit).all()


@router.get("/urls/{url_id}/js", response_model=List[JSSensitiveResponse])
def list_js_sensitives(url_id: int, db: Session = Depends(get_db)):
    return db.query(JSSensitive).filter(JSSensitive.url_id == url_id).all()


# ═══════════════════════════════════════
# 指纹
# ═══════════════════════════════════════

@router.get("/fingerprints", response_model=List[FingerprintResponse])
def list_fingerprints(
    org_id: int = Query(None),
    category: str = Query(""),
    db: Session = Depends(get_db),
):
    q = db.query(Fingerprint)
    if org_id:
        q = q.join(URL, Fingerprint.url_id == URL.id).filter(URL.url.contains(
            db.query(Domain.domain).filter(Domain.org_id == org_id).first()
        ))
    if category:
        q = q.filter(Fingerprint.category == category)
    return q.order_by(Fingerprint.value_level.desc()).limit(500).all()


@router.get("/urls/{url_id}/fingerprints", response_model=List[FingerprintResponse])
def list_url_fingerprints(url_id: int, db: Session = Depends(get_db)):
    return db.query(Fingerprint).filter(Fingerprint.url_id == url_id).all()


# ═══════════════════════════════════════
# 漏洞管理
# ═══════════════════════════════════════

@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    org_id: int = Query(None),
    severity: str = Query(""),
    status: str = Query(""),
    db: Session = Depends(get_db),
):
    q = db.query(Vulnerability)
    if org_id:
        q = q.filter(Vulnerability.org_id == org_id)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if status:
        q = q.filter(Vulnerability.status == status)
    return q.order_by(Vulnerability.found_at.desc()).limit(500).all()


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return vuln


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability(vuln_id: int, data: VulnerabilityUpdate, db: Session = Depends(get_db)):
    vuln = db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(vuln, k, v)
    db.commit()
    db.refresh(vuln)
    return vuln


@router.delete("/vulnerabilities/{vuln_id}")
def delete_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    db.delete(vuln)
    db.commit()
    return {"message": "删除成功"}


# ═══════════════════════════════════════
# 任务管理 (增强)
# ═══════════════════════════════════════

# 后台任务追踪
_task_threads: dict = {}

@router.get("/tasks", response_model=List[TaskResponse])
def list_tasks(db: Session = Depends(get_db)):
    return db.query(Task).order_by(Task.created_at.desc()).limit(100).all()


@router.post("/tasks", response_model=TaskResponse)
def create_task(data: TaskCreate, db: Session = Depends(get_db)):
    task = Task(
        org_id=data.org_id,
        name=data.name,
        task_type=data.task_type,
        target=data.target,
        config=data.config,
        status="pending",
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    if data.task_type in ("recon", "vulnscan"):
        task_id = task.id
        thread = threading.Thread(
            target=_run_recon_sync, args=(task_id,), daemon=True
        )
        thread.start()
        _task_threads[task_id] = thread

    return task


@router.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task


@router.get("/tasks/{task_id}/live")
def get_task_live(task_id: int, db: Session = Depends(get_db)):
    """获取任务实时资产详情（仅返回该任务目标的资产）"""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    org_id = task.org_id
    target = task.target
    result = {"task_id": task_id, "status": task.status, "progress": task.progress, "target": target}

    # 找到该任务对应的主域名记录
    domain_obj = db.query(Domain).filter(
        Domain.org_id == org_id, Domain.domain == target
    ).first()

    # 仅查询该域名下的子域名
    if domain_obj:
        subs = db.query(Subdomain).filter(Subdomain.domain_id == domain_obj.id)\
            .order_by(Subdomain.priority.desc(), Subdomain.first_seen.desc()).limit(100).all()
    else:
        subs = []
    result["subdomains"] = [
        {"subdomain": s.subdomain, "ip": s.ip, "category": s.category or "other",
         "priority": s.priority or 1, "source": s.source}
        for s in subs
    ]

    # IP + 端口（仅该域名的子域名解析出的 IP）
    subdomain_ips = {s.ip for s in subs if s.ip}
    ip_list = []
    if subdomain_ips:
        db_ips = db.query(IPAddress).filter(IPAddress.ip.in_(subdomain_ips)).all()
        ip_map = {ip.ip: ip for ip in db_ips}
        for ip_str in subdomain_ips:
            ip_obj = ip_map.get(ip_str)
            if ip_obj:
                ports = db.query(Port).filter(Port.ip_id == ip_obj.id).order_by(Port.port).all()
                ip_list.append({
                    "ip": ip_str, "is_cdn": ip_obj.is_cdn, "country": ip_obj.country,
                    "ports": [{"port": p.port, "service": p.service, "banner": (p.banner or "")[:100]} for p in ports[:20]]
                })
    result["ips"] = ip_list[:30]

    # URL（仅该域名相关）
    if subs:
        subdomain_set = {s.subdomain for s in subs}
        urls = db.query(URL).order_by(URL.first_seen.desc()).limit(200).all()
        result["urls"] = [
            {"url": u.url, "status_code": u.status_code, "title": u.title, "tech_stack": u.tech_stack}
            for u in urls if u.host in subdomain_set or u.host.endswith("." + target)
        ][:30]
    else:
        result["urls"] = []

    # 指纹（仅该域名的 URL）
    if result["urls"]:
        url_set = {u["url"] for u in result["urls"]}
        fps = db.query(Fingerprint).order_by(Fingerprint.value_level.desc()).limit(200).all()
        url_objs = db.query(URL).filter(URL.url.in_(url_set)).all()
        url_id_map = {uo.id: uo.url for uo in url_objs}
        result["fingerprints"] = [
            {"name": f.name, "category": f.category, "value": f.value_level, "url": url_id_map.get(f.url_id, "")}
            for f in fps if f.url_id in url_id_map
        ][:30]
    else:
        result["fingerprints"] = []

    # 漏洞（仅该 org）
    vulns = db.query(Vulnerability).filter(Vulnerability.org_id == org_id)\
        .order_by(Vulnerability.severity.desc()).limit(50).all()
    result["vulnerabilities"] = [
        {"name": v.name, "severity": v.severity, "type": v.vuln_type, "target": v.target}
        for v in vulns
    ]

    # 统计
    result["counts"] = {
        "subdomains": len(subs), "ips": len(result["ips"]), "urls": len(result["urls"]),
        "fingerprints": len(result["fingerprints"]), "vulnerabilities": len(vulns),
    }

    return result


@router.put("/tasks/{task_id}/cancel")
def cancel_task(task_id: int, db: Session = Depends(get_db)):
    """取消正在运行的任务"""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="任务不在可取消状态")
    task.status = "failed"
    task.error = "用户取消"
    task.completed_at = datetime.datetime.now()
    db.commit()
    return {"message": "任务已取消"}


@router.delete("/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    """删除任务记录"""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status == "running":
        raise HTTPException(status_code=400, detail="运行中的任务无法删除，请先取消")
    db.delete(task)
    db.commit()
    return {"message": "已删除"}


@router.put("/tasks/{task_id}/retry")
def retry_task(task_id: int, db: Session = Depends(get_db)):
    """重试失败的任务"""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    new_task = Task(
        org_id=task.org_id, name=task.name + " (重试)",
        task_type=task.task_type, target=task.target,
        config=task.config, status="pending",
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    # 启动后台执行
    if new_task.task_type in ("recon", "vulnscan"):
        import threading
        t = threading.Thread(target=_run_recon_sync, args=(new_task.id,), daemon=True)
        t.start()
        _task_threads[new_task.id] = t
    return new_task


def _run_recon_sync(task_id: int):
    db = SessionLocal()
    try:
        from app.modules.recon.orchestrator import ReconOrchestrator
        orchestrator = ReconOrchestrator()
        orchestrator.run_pipeline(task_id, db)
    finally:
        db.close()
        _task_threads.pop(task_id, None)


# ═══════════════════════════════════════
# POC 引擎缓存（避免每次请求重新加载 3173 POCs）
# ═══════════════════════════════════════

_poc_engine_cache = None

def _get_poc_engine():
    global _poc_engine_cache
    if _poc_engine_cache is None:
        from app.modules.vulnscan.poc_engine import POCEngine
        _poc_engine_cache = POCEngine()
        _poc_engine_cache.load_poc_dir(str(settings.POC_DIR))
    return _poc_engine_cache


# ═══════════════════════════════════════
# 扫描接口
# ═══════════════════════════════════════

@router.post("/scan/fingerprint")
async def scan_fingerprint(data: ScanRequest):
    from app.modules.vulnscan.orchestrator import VulnOrchestrator
    orch = VulnOrchestrator()
    result = await orch.scan_url(data.url, headers=data.headers, body=data.body)
    return result


@router.post("/scan/full")
async def scan_full(data: ScanRequest):
    from app.modules.vulnscan.orchestrator import VulnOrchestrator
    orch = VulnOrchestrator()
    result = await orch.scan_url_with_poc(data.url, headers=data.headers, body=data.body)
    return result


@router.post("/scan/weakpass")
async def scan_weakpass(data: WeakPassRequest):
    from app.modules.vulnscan.weak_password import WeakPasswordChecker
    checker = WeakPasswordChecker()
    results = await checker.check(data.target, data.service)
    return {"target": data.target, "service": data.service, "results": results}


@router.post("/scan/unauth")
async def scan_unauth(data: ScanRequest):
    from app.modules.vulnscan.unauthorized import UnauthorizedChecker
    checker = UnauthorizedChecker()
    results = await checker.check(data.url)
    return {"url": data.url, "findings": results}


@router.post("/scan/dir")
async def scan_dir(data: DirScanRequest):
    from app.modules.recon.dir_scanner import DirScanner
    scanner = DirScanner()
    results = await scanner.scan(data.url, data.wordlist_type)
    return {"url": data.url, "findings": results}


# ═══════════════════════════════════════
# POC 管理
# ═══════════════════════════════════════

@router.get("/pocs")
async def list_pocs(
    tag: str = Query(""),
    severity: str = Query(""),
    search: str = Query(""),
    limit: int = Query(200),
):
    engine = _get_poc_engine()
    pocs = []
    for poc in engine.pocs.values():
        if tag and tag not in str(poc.tags):
            continue
        if severity and poc.severity != severity:
            continue
        if search and search.lower() not in poc.id.lower() and search.lower() not in poc.name.lower():
            continue
        pocs.append({
            "id": poc.id, "name": poc.name, "severity": poc.severity,
            "description": (poc.description or "")[:200], "tags": poc.tags,
            "requests_count": len(poc.requests),
        })
    pocs.sort(key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(p["severity"], 5))
    return pocs[:limit]


@router.get("/pocs/{poc_id}")
async def get_poc_detail(poc_id: str):
    engine = _get_poc_engine()
    poc = engine.pocs.get(poc_id)
    if not poc:
        raise HTTPException(status_code=404, detail="POC 不存在")
    return {
        "id": poc.id, "name": poc.name, "author": poc.author,
        "severity": poc.severity, "description": poc.description,
        "reference": poc.reference, "tags": poc.tags,
        "matchers_condition": poc.matchers_condition,
        "requests": [
            {"method": r.get("method"), "path": r.get("path"),
             "matchers": r.get("matchers", [])[:5], "headers": dict(list(r.get("headers", {}).items())[:5])}
            for r in poc.requests
        ],
    }


@router.post("/pocs/{poc_id}/execute")
async def execute_poc(poc_id: str, data: ScanRequest):
    engine = _get_poc_engine()
    result = await engine.execute(data.url, poc_id)
    return result


# ═══════════════════════════════════════
# 报告生成
# ═══════════════════════════════════════

@router.post("/report")
def generate_report(data: ReportRequest, db: Session = Depends(get_db)):
    """生成 SRC 格式漏洞报告"""
    org = db.get(Organization, data.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="组织不存在")

    vulns = db.query(Vulnerability).filter(
        Vulnerability.org_id == data.org_id
    ).order_by(Vulnerability.severity.desc()).all()

    if not vulns:
        raise HTTPException(status_code=404, detail="该组织无漏洞记录")

    lines = []
    lines.append(f"# Sky-Eye 漏洞扫描报告")
    lines.append(f"")
    lines.append(f"**目标组织:** {org.name}")
    lines.append(f"**生成时间:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**漏洞总数:** {len(vulns)}")
    lines.append(f"")

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
    lines.append(f"## 漏洞统计")
    lines.append(f"| 严重度 | 数量 |")
    lines.append(f"|--------|------|")
    for sev, cnt in sev_counts.items():
        if cnt > 0:
            lines.append(f"| {sev} | {cnt} |")
    lines.append(f"")

    for i, v in enumerate(vulns, 1):
        lines.append(f"---")
        lines.append(f"### {i}. {v.name}")
        lines.append(f"")
        lines.append(f"| 属性 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| **漏洞ID** | {v.id} |")
        lines.append(f"| **类型** | {v.vuln_type} |")
        lines.append(f"| **严重度** | {v.severity} |")
        lines.append(f"| **状态** | {v.status} |")
        lines.append(f"| **目标** | {v.target or 'N/A'} |")
        if v.src_platform:
            lines.append(f"| **SRC平台** | {v.src_platform} |")
        if v.bounty:
            lines.append(f"| **赏金** | {v.bounty} |")
        lines.append(f"")
        if v.description:
            lines.append(f"**描述:** {v.description}")
            lines.append(f"")
        if data.include_evidence and v.evidence:
            lines.append(f"**证据:**")
            lines.append(f"```")
            lines.append(f"{v.evidence[:2000]}")
            lines.append(f"```")
            lines.append(f"")
        if data.include_poc and v.poc_id:
            lines.append(f"**POC:** `{v.poc_id}`")
            lines.append(f"")

    content = "\n".join(lines)
    return {"org_id": data.org_id, "format": data.format, "content": content, "vuln_count": len(vulns)}


# ═══════════════════════════════════════
# 统计接口
# ═══════════════════════════════════════

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    return {
        "organizations": db.query(func.count(Organization.id)).scalar() or 0,
        "domains": db.query(func.count(Domain.id)).scalar() or 0,
        "subdomains": db.query(func.count(Subdomain.id)).scalar() or 0,
        "ips": db.query(func.count(IPAddress.id)).scalar() or 0,
        "ports": db.query(func.count(Port.id)).scalar() or 0,
        "urls": db.query(func.count(URL.id)).scalar() or 0,
        "js_sensitives": db.query(func.count(JSSensitive.id)).scalar() or 0,
        "fingerprints": db.query(func.count(Fingerprint.id)).scalar() or 0,
        "vulnerabilities": db.query(func.count(Vulnerability.id)).scalar() or 0,
        "tasks": db.query(func.count(Task.id)).scalar() or 0,
        "vulns_by_severity": dict(
            db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity).all()
        ),
    }
