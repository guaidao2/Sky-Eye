"""Sky-Eye CLI v3"""

import asyncio, json, time
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from app.config import settings
from app.database import init_db, SessionLocal

cli = typer.Typer(name="sky-eye", help="Sky-Eye 资产挖掘与打点系统", add_completion=False)
console = Console()

CAT_COLORS = {"admin":"red","auth":"red","devops":"yellow","api":"blue","dev":"yellow",
              "vpn":"magenta","db":"yellow","monitor":"cyan","oa":"green","pay":"green"}
CAT_NAMES = {"admin":"管理后台","auth":"认证","devops":"DevOps","api":"API","dev":"开发测试",
             "vpn":"VPN","db":"数据库","monitor":"监控","oa":"OA","pay":"支付",
             "mail":"邮件","files":"文件","other":"其他"}


@cli.command()
def version():
    """显示版本信息"""
    console.print(f"Sky-Eye v{settings.APP_VERSION}")
    console.print(f"  DB: {settings.DATABASE_URL}")


@cli.command()
def server(
    host: str = typer.Option("127.0.0.1", "--host", "-H"),
    port: int = typer.Option(8000, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload"),
):
    """启动 Web 管理面板"""
    import uvicorn
    console.print(f"[bold green]Sky-Eye Server[/] http://{host}:{port}")
    console.print(f"  API: http://{host}:{port}/docs")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload)


@cli.command()
def recon(
    target: str = typer.Argument(..., help="目标域名或IP（自动识别）"),
    org: str = typer.Option("", "--org", "-o", help="组织名称"),
    output: str = typer.Option("", "--output", "--out", help="导出JSON结果"),
):
    """全链路信息收集: 子域名->IP->端口->指纹->POC->报告"""
    init_db(); db = SessionLocal()
    try:
        from app.models import Organization, Task
        from app.modules.recon.orchestrator import ReconOrchestrator

        is_ip = ReconOrchestrator._is_ip_address(target)
        mode = "IP" if is_ip else "域名"
        console.print(f"\n[bold cyan]Recon[/] 目标: [bold yellow]{target}[/] ({mode})")

        org_name = org or target
        org_obj = db.query(Organization).filter(Organization.name == org_name).first()
        if not org_obj:
            org_obj = Organization(name=org_name); db.add(org_obj); db.commit(); db.refresh(org_obj)

        task = Task(org_id=org_obj.id, name=f"Recon: {target}", task_type="recon",
                     target=target, target_type="ip" if is_ip else "domain", status="pending")
        db.add(task); db.commit()
        task_id = task.id

        orchestrator = ReconOrchestrator()
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console) as progress:
            p = progress.add_task(f"[cyan]{target}[/] 扫描中...", total=100)
            result = orchestrator.run_pipeline(task_id, db)
            while True:
                db.expire_all(); t = db.query(Task).get(task_id)
                if not t: break
                progress.update(p, completed=t.progress, description=f"[cyan]{target}[/] {mode} {t.progress}%")
                if t.status in ("completed", "failed"): break
                time.sleep(1)
            progress.update(p, completed=100)

        console.print()
        s = result.get("summary", {})
        if result.get("status") == "completed":
            table = Table(title="资产汇总", title_style="bold green")
            table.add_column("类型", style="cyan"); table.add_column("数量", style="bold yellow", justify="right")
            for k, v in [("子域名","subdomains"),("IP","ips"),("端口","ports"),("URL","urls"),
                         ("指纹","fingerprints"),("漏洞","vulns"),("JS信息","js_findings"),("目录发现","dir_findings")]:
                table.add_row(k, str(s.get(v, 0)))
            if s.get("cdn_bypass_ips"): table.add_row("CDN穿透IP", str(s["cdn_bypass_ips"]))
            console.print(table)

            attack = s.get("attack_surface", {})
            if attack.get("high_value"):
                console.print()
                console.print(Panel.fit(
                    f"[bold]攻击面速览 ({attack['high_value_count']}/{attack['total']})[/]\n" +
                    "\n".join(f"  [{CAT_COLORS.get(h['category'],'white')}]P{h['priority']} [{h['category']:8s}][/] {h['subdomain']} ({CAT_NAMES.get(h['category'],h['category'])})"
                              for h in attack["high_value"][:20]),
                    title="高价值子域名", border_style="red"))

            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2, default=str)
                console.print(f"\n  结果已保存: {output}")
        else:
            console.print(f"[red]失败: {result.get('error', '未知')}[/]")
    finally:
        db.close()


@cli.command()
def brute(
    domain: str = typer.Argument(..., help="目标域名"),
    org: str = typer.Option("", "--org", "-o", help="组织名称"),
    wordlist: str = typer.Option("", "--wordlist", "-w", help="自定义字典文件路径"),
    threads: int = typer.Option(50, "--threads", "-t", help="并发数"),
):
    """子域名爆破 + 自动指纹识别（只做爆破和指纹，不做后续扫描）"""
    init_db(); db = SessionLocal()
    try:
        from app.models import Organization, Domain, Subdomain, Task
        from app.modules.recon.subdomain import SubdomainCollector
        from app.modules.recon.subdomain_analyzer import SubdomainAnalyzer
        from app.modules.recon.web_probe import WebProber

        console.print(f"\n[bold cyan]Subdomain Brute[/] 目标: [bold yellow]{domain}[/]")

        org_name = org or domain
        org_obj = db.query(Organization).filter(Organization.name == org_name).first()
        if not org_obj:
            org_obj = Organization(name=org_name); db.add(org_obj); db.commit(); db.refresh(org_obj)

        domain_obj = db.query(Domain).filter(Domain.org_id == org_obj.id, Domain.domain == domain).first()
        if not domain_obj:
            domain_obj = Domain(org_id=org_obj.id, domain=domain, source="manual")
            db.add(domain_obj); db.commit()

        # 子域名收集
        collector = SubdomainCollector()
        if wordlist:
            # 自定义字典
            old_load = collector._load_wordlist
            collector._load_wordlist = lambda: [l.strip() for l in open(wordlist, encoding='utf-8') if l.strip() and not l.startswith('#')]
            console.print(f"  字典: {wordlist}")
        else:
            console.print(f"  字典: 内置 {len(collector._load_wordlist())} 词")
        console.print("  DNS爆破中...")
        raw_subs = asyncio.run(collector.collect(domain, brute=True))
        if not raw_subs:
            console.print("[yellow]收集失败[/]"); return
        subdomains = list(raw_subs.get("subdomains", []))
        console.print(f"  发现: {len(subdomains)} 个子域名")

        if not subdomains:
            console.print("[yellow]未发现子域名[/]")
            return

        # 保存到数据库
        for sd in subdomains:
            if not db.query(Subdomain).filter(Subdomain.domain_id == domain_obj.id, Subdomain.subdomain == sd).first():
                db.add(Subdomain(domain_id=domain_obj.id, subdomain=sd, source="dns_brute"))
        db.commit()

        # 智能分类评分
        analyzer = SubdomainAnalyzer()
        analyzed = analyzer.analyze_batch(subdomains)
        surface = analyzer.get_attack_surface_summary(analyzed)
        for a in analyzed:
            sd = db.query(Subdomain).filter(Subdomain.domain_id == domain_obj.id, Subdomain.subdomain == a["subdomain"]).first()
            if sd:
                sd.category = a["category"]; sd.priority = a["priority"]
        db.commit()

        # 显示分类结果
        console.print()
        high = surface.get("high_value", [])[:20]
        if high:
            console.print(f"[bold]高价值子域名 ({surface['high_value_count']}/{surface['total']})[/]")
            for h in high:
                cat = h["category"]; color = CAT_COLORS.get(cat, "white")
                console.print(f"  [{color}]P{h['priority']} [{cat:8s}][/] {h['subdomain']} ({CAT_NAMES.get(cat,cat)})")

        # 自动指纹识别 — 对每个子域名做快速 Web 探测
        console.print(f"\n[bold cyan]自动指纹识别[/]")
        prober = WebProber()
        targets = []
        for sd in subdomains[:100]:
            targets.append({"host": sd, "port": 80, "scheme": "http"})
            targets.append({"host": sd, "port": 443, "scheme": "https"})

        console.print(f"探测 {len(targets)} 个端点...")
        web_results = asyncio.run(prober.probe(targets))

        alive = [w for w in web_results if w.get("alive")]
        console.print(f"  存活: {len(alive)}")

        if alive:
            from app.modules.fingerprint.engine import FingerprintEngine
            from app.modules.fingerprint.hub_adapter import FingerprintHubAdapter
            engine = FingerprintEngine(); engine.load_fingerprints()
            hub = FingerprintHubAdapter(); hub.load()

            fp_table = Table(title="指纹识别结果")
            fp_table.add_column("子域名", style="cyan"); fp_table.add_column("产品", style="green")
            fp_table.add_column("分类", style="yellow"); fp_table.add_column("置信度")

            total_fps = 0
            for wr in alive[:30]:
                url = wr["url"]
                try:
                    import httpx
                    r = httpx.get(url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                    body = r.text[:50000]
                    fps_y = engine.match(url, r.status_code, dict(r.headers), body, min_confidence=0.3)
                    fps_h = hub.match(url, r.status_code, dict(r.headers), body, min_confidence=0.3)
                    all_fps = fps_y + fps_h
                    if all_fps:
                        best = sorted(all_fps, key=lambda x: -x.get("confidence",0))[0]
                        fp_table.add_row(wr["host"], best["name"], best.get("category",""),
                                        f"{best.get('confidence',0):.0%}")
                        total_fps += 1
                except Exception:
                    pass

            if total_fps:
                console.print(fp_table)
            else:
                console.print("  [yellow]未识别到指纹[/]")

        console.print(f"\n[green]完成[/] — 查看: [bold]http://127.0.0.1:8000/assets[/]")
    finally:
        db.close()


@cli.command()
def fingerprint(
    url: str = typer.Argument(..., help="目标URL"),
    min_conf: float = typer.Option(0.3, "--min-confidence", "-c", help="最低置信度 0-1"),
):
    """对单个 URL 执行指纹识别"""
    console.print(f"[bold cyan]Fingerprint[/] {url}")
    async def _run():
        import httpx, re
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as c:
                r = await c.get(url, follow_redirects=True)
                st, tl, sv = r.status_code, '', r.headers.get('server','')
                m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I)
                if m: tl = m.group(1).strip()[:100]
                body = r.text[:50000]
        except httpx.ConnectError: console.print('[red]无法连接[/]'); return None
        except httpx.TimeoutException: console.print('[red]超时[/]'); return None
        except Exception as e: console.print(f'[red]请求失败: {type(e).__name__}[/]'); return None
        from app.modules.vulnscan.orchestrator import VulnOrchestrator
        orch = VulnOrchestrator()
        res = await orch.scan_url(url, headers=dict(r.headers), body=body, status_code=st)
        return (st, tl, sv, res)
    data = asyncio.run(_run())
    if not data: return
    status, title, server, result = data

    console.print(f"  {status} | {title or '(无标题)'} | Server: {server or '(无)'}")
    fps = sorted(
        [f for f in result.get("fingerprints", []) if f.get("confidence", 1) >= min_conf],
        key=lambda x: -x.get("confidence", 0))
    if fps:
        table = Table(title=f"指纹 (conf>={min_conf})")
        table.add_column("产品", style="cyan"); table.add_column("置信度"); table.add_column("分类"); table.add_column("价值")
        for f in fps:
            c = f.get("confidence", 1); cs = "green" if c >= 0.8 else ("yellow" if c >= 0.5 else "red")
            table.add_row(f["name"], f"[{cs}]{c:.0%}[/]", f.get("category",""), f"P{f.get('value',2)}")
        console.print(table)
    else:
        console.print(f"[yellow]未识别到指纹[/] (阈值: {min_conf})")


@cli.command()
def vulnscan(
    url: str = typer.Argument(..., help="目标URL"),
    all_pocs: bool = typer.Option(False, "--all", "-a", help="全量POC模式"),
    max_pocs: int = typer.Option(50, "--max", "-m", help="最大POC数量"),
):
    """漏洞检测: 指纹+POC+未授权. --all 跑全量POC"""
    console.print(f"[bold cyan]VulnScan[/] {url}")
    async def _run():
        import httpx, re
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as c:
                r = await c.get(url, follow_redirects=True)
                st, tl, sv = r.status_code, '', r.headers.get('server','')
                m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I)
                if m: tl = m.group(1).strip()[:100]
                body = r.text[:50000]
        except Exception as e: console.print(f'[red]请求失败: {type(e).__name__}[/]'); return None
        from app.modules.vulnscan.orchestrator import VulnOrchestrator
        orch = VulnOrchestrator()
        res = await orch.scan_url_with_poc(url, headers=dict(r.headers), body=body, status_code=st,
                                            all_pocs=all_pocs, max_pocs=max_pocs)
        return (st, tl, sv, res)
    data = asyncio.run(_run())
    if not data: return
    status, title, server, result = data
    console.print(f"  {status} | {title or '(无标题)'} | Server: {server or '(无)'}")
    console.print(f"  模式: {'全量POC' if all_pocs else '指纹匹配'} | POC上限: {max_pocs}")
    fps = result.get("fingerprints", [])
    vulns = [p for p in result.get("poc_results", []) if p.get("vulnerable")]
    console.print(f"  指纹: {len(fps)} | POC匹配: {len(result.get('poc_matches',[]))} | 漏洞: {len(vulns)}")
    if vulns:
        table = Table(title="发现漏洞")
        table.add_column("名称", style="red"); table.add_column("严重度"); table.add_column("匹配")
        for v in vulns:
            sc = {"critical":"red","high":"yellow","medium":"cyan"}.get(v.get("severity",""),"white")
            table.add_row(v.get("name",""), f"[{sc}]{v.get('severity','')}[/]", ", ".join(v.get("matched",[])[:3]))
        console.print(table)
    if not vulns:
        console.print("[green]未发现漏洞[/]")


@cli.command()
def scan(
    target: str = typer.Argument(..., help="目标IP或域名"),
    ports: str = typer.Option("", "--ports", "-p", help="端口范围: 80,443 或 1-1000"),
):
    """端口扫描 + Banner"""
    console.print(f"[bold cyan]PortScan[/] {target}")
    async def _run():
        from app.modules.recon.port_scan import PortScanner
        s = PortScanner()
        pl = None
        if ports:
            if "-" in ports: a,b = ports.split("-"); pl = list(range(int(a), int(b)+1))
            else: pl = [int(p) for p in ports.split(",")]
        return await s.scan(target, ports=pl, grab_banner=True)
    result = asyncio.run(_run())
    if result:
        table = Table(title=f"{target} 开放端口"); table.add_column("端口"); table.add_column("服务"); table.add_column("Banner", max_width=60)
        for p in result: table.add_row(str(p["port"]), p.get("service","?"), (p.get("banner","") or "")[:60])
        console.print(table)
    else: console.print("[yellow]未发现开放端口[/]")


@cli.command()
def weakpass(
    target: str = typer.Argument(..., help="host:port"),
    service: str = typer.Option("redis", "--service", "-s", help="redis/mysql/ssh/ftp/tomcat/jenkins/wordpress"),
):
    """弱口令检测"""
    console.print(f"[bold cyan]WeakPass[/] {target} ({service})")
    async def _run():
        from app.modules.vulnscan.weak_password import WeakPasswordChecker
        return await WeakPasswordChecker().check(target, service)
    results = asyncio.run(_run())
    if results:
        table = Table(title="发现弱口令"); table.add_column("用户名"); table.add_column("密码", style="red"); table.add_column("证据")
        for r in results: table.add_row(r["username"], r["password"], r.get("evidence","")[:80])
        console.print(table)
    else: console.print("[green]未发现弱口令[/]")


@cli.command()
def unauth(url: str = typer.Argument(..., help="目标URL")):
    """未授权访问检测"""
    console.print(f"[bold cyan]Unauth[/] {url}")
    async def _run():
        from app.modules.vulnscan.unauthorized import UnauthorizedChecker
        return await UnauthorizedChecker().check(url)
    results = asyncio.run(_run())
    if results:
        table = Table(title="未授权访问"); table.add_column("名称"); table.add_column("路径"); table.add_column("严重度")
        for r in results:
            sc = {"critical":"red","high":"yellow","medium":"cyan"}.get(r.get("severity",""),"white")
            table.add_row(r["name"], r["path"], f"[{sc}]{r['severity']}[/]")
        console.print(table)
    else: console.print("[green]未发现未授权访问[/]")


@cli.command()
def list(
    org: str = typer.Option("", "--org", "-o", help="组织名称过滤"),
    type: str = typer.Option("subdomains", "--type", "-t", help="subdomains/ips/urls/vulns"),
    limit: int = typer.Option(50, "--limit", "-n"),
):
    """列出已收集的资产"""
    init_db(); db = SessionLocal()
    try:
        from app.models import Organization, Domain, Subdomain, IPAddress, URL, Vulnerability
        if type == "subdomains":
            q = db.query(Subdomain).order_by(Subdomain.priority.desc()).limit(limit)
            if org: q = q.join(Domain).join(Organization).filter(Organization.name.contains(org))
            subs = q.all()
            if subs:
                table = Table(title="子域名"); table.add_column("子域名"); table.add_column("IP"); table.add_column("分类"); table.add_column("优先级")
                for s in subs:
                    cc = CAT_COLORS.get(s.category,"white") if s.category else "white"
                    table.add_row(s.subdomain, s.ip or "-", f"[{cc}]{s.category or 'other'}[/]", f"P{s.priority or 1}")
                console.print(table)
            else: console.print("[yellow]无数据[/]")
        elif type == "ips":
            ips = db.query(IPAddress).order_by(IPAddress.first_seen.desc()).limit(limit).all()
            if ips:
                table = Table(title="IP"); table.add_column("IP"); table.add_column("CDN"); table.add_column("位置")
                for ip in ips: table.add_row(ip.ip, "Y" if ip.is_cdn else "N", f"{ip.country or ''} {ip.province or ''}")
                console.print(table)
            else: console.print("[yellow]无数据[/]")
        elif type == "urls":
            urls = db.query(URL).order_by(URL.first_seen.desc()).limit(limit).all()
            if urls:
                table = Table(title="URL"); table.add_column("URL"); table.add_column("状态"); table.add_column("标题")
                for u in urls: table.add_row(u.url[:80], str(u.status_code or "-"), (u.title or "")[:40])
                console.print(table)
            else: console.print("[yellow]无数据[/]")
        elif type == "vulns":
            vulns = db.query(Vulnerability).order_by(Vulnerability.severity.desc()).limit(limit).all()
            if vulns:
                table = Table(title="漏洞"); table.add_column("名称"); table.add_column("严重度"); table.add_column("类型")
                for v in vulns:
                    sc = {"critical":"red","high":"yellow","medium":"cyan","low":"dim"}.get(v.severity,"white")
                    table.add_row(v.name[:50], f"[{sc}]{v.severity}[/]", v.vuln_type)
                console.print(table)
            else: console.print("[yellow]无漏洞[/]")
    finally: db.close()


@cli.command()
def report(
    org: str = typer.Argument(..., help="组织名称"),
    output: str = typer.Option("", "--output", "--out", "-o", help="输出文件"),
):
    """生成 SRC 格式漏洞报告"""
    init_db(); db = SessionLocal()
    try:
        from app.models import Organization, Vulnerability
        org_obj = db.query(Organization).filter(Organization.name == org).first()
        if not org_obj: console.print(f"[red]组织不存在: {org}[/]"); return
        vulns = db.query(Vulnerability).filter(Vulnerability.org_id == org_obj.id).order_by(Vulnerability.severity.desc()).all()
        if not vulns: console.print("[yellow]该组织暂无漏洞[/]"); return
        lines = [f"# Sky-Eye 漏洞报告 -- {org}", "",
                 f"生成时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
                 f"漏洞总数: {len(vulns)}", ""]
        for i, v in enumerate(vulns, 1):
            lines.append(f"## {i}. {v.name}")
            lines.append(f"- 严重度: {v.severity}  |  类型: {v.vuln_type}  |  状态: {v.status}")
            if v.target: lines.append(f"- 目标: {v.target}")
            if v.description: lines.append(f"- 描述: {v.description}")
            if v.evidence: lines.append(f"- 证据: `{v.evidence[:200]}`")
            if v.poc_id: lines.append(f"- POC: `{v.poc_id}`"); lines.append("")
        content = "\n".join(lines)
        if output:
            with open(output, "w", encoding="utf-8") as f: f.write(content)
            console.print(f"[green]报告已保存: {output}[/]")
        else: console.print(content)
    finally: db.close()


if __name__ == "__main__":
    cli()
