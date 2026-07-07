"""Sky-Eye CLI 命令行入口 v2"""

import asyncio
import json
import sys
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.layout import Layout

from app.config import settings
from app.database import init_db, SessionLocal

cli = typer.Typer(name="sky-eye", help="Sky-Eye 资产挖掘与打点系统", add_completion=False)
console = Console()


@cli.command()
def version():
    """显示版本信息"""
    console.print(f"[bold cyan]Sky-Eye[/] v{settings.APP_VERSION}")
    console.print(f"  DB: {settings.DATABASE_URL}")
    console.print(f"  POC: {settings.POC_DIR}")


@cli.command()
def server(
    host: str = typer.Option("127.0.0.1", "--host", "-H"),
    port: int = typer.Option(8000, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload"),
):
    """启动 Web 管理面板"""
    import uvicorn
    console.print(f"[bold green]🚀 Sky-Eye Server[/] http://{host}:{port}")
    console.print(f"  API 文档: http://{host}:{port}/docs")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload)


@cli.command()
def recon(
    target: str = typer.Argument(..., help="目标域名或IP（自动识别）"),
    org: str = typer.Option("", "--org", "-o", help="组织名称"),
    output: str = typer.Option("", "--output", "--out", help="导出JSON结果"),
):
    """全链路信息收集（子域名→IP→端口→指纹→POC→报告）"""
    init_db()
    db = SessionLocal()
    try:
        from app.models import Organization, Task
        from app.modules.recon.orchestrator import ReconOrchestrator
        from app.modules.recon.subdomain_analyzer import SubdomainAnalyzer

        is_ip = ReconOrchestrator._is_ip_address(target)
        mode = "IP 模式" if is_ip else "域名模式"
        console.print(f"\n[bold cyan]🛰️  Sky-Eye Recon[/] 目标: [bold yellow]{target}[/] ({mode})")

        org_name = org or target
        org_obj = db.query(Organization).filter(Organization.name == org_name).first()
        if not org_obj:
            org_obj = Organization(name=org_name)
            db.add(org_obj); db.commit(); db.refresh(org_obj)

        task = Task(org_id=org_obj.id, name=f"Recon: {target}", task_type="recon",
                     target=target, target_type="ip" if is_ip else "domain", status="pending")
        db.add(task); db.commit()
        task_id = task.id

        orchestrator = ReconOrchestrator()

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            p = progress.add_task(f"[cyan]扫描 {target}...", total=100)
            result = orchestrator.run_pipeline(task_id, db)

            # 轮询进度
            import time
            while True:
                db.expire_all()
                t = db.query(Task).get(task_id)
                if not t: break
                progress.update(p, completed=t.progress,
                                description=f"[cyan]{target}[/] [{'IP' if is_ip else '域名'}] {t.progress}%")
                if t.status in ("completed", "failed"): break
                time.sleep(1)
            progress.update(p, completed=100)

        console.print()
        s = result.get("summary", {})
        if result.get("status") == "completed":
            # 资产汇总表
            table = Table(title="📊 资产汇总", title_style="bold green")
            table.add_column("资产类型", style="cyan"); table.add_column("数量", style="bold yellow", justify="right")
            table.add_row("子域名", str(s.get("subdomains", 0)))
            table.add_row("IP地址", str(s.get("ips", 0)))
            table.add_row("开放端口", str(s.get("ports", 0)))
            table.add_row("存活URL", str(s.get("urls", 0)))
            table.add_row("指纹识别", str(s.get("fingerprints", 0)))
            table.add_row("漏洞发现", str(s.get("vulns", 0)))
            table.add_row("JS敏感信息", str(s.get("js_findings", 0)))
            table.add_row("目录发现", str(s.get("dir_findings", 0)))
            if s.get("cdn_bypass_ips"): table.add_row("CDN穿透IP", str(s["cdn_bypass_ips"]))
            console.print(table)

            # 攻击面 — 高价值子域名
            attack = s.get("attack_surface", {})
            if attack.get("high_value"):
                console.print()
                cat_colors = {"admin":"red","auth":"red","devops":"yellow","api":"blue","dev":"yellow",
                              "vpn":"magenta","db":"yellow","monitor":"cyan","oa":"green","pay":"green"}
                cat_names = {"admin":"管理后台","auth":"认证","devops":"DevOps","api":"API","dev":"开发测试",
                             "vpn":"VPN","db":"数据库","monitor":"监控","oa":"OA","pay":"支付",
                             "mail":"邮件","files":"文件","other":"其他"}
                console.print(Panel.fit(
                    f"[bold]🎯 高价值子域名 ({attack['high_value_count']}/{attack['total']})[/]\n" +
                    "\n".join(f"  [{cat_colors.get(h['category'],'white')}]P{h['priority']} [{h['category']:8s}][/] {h['subdomain']} ({cat_names.get(h['category'],h['category'])})"
                              for h in attack["high_value"][:20]),
                    title="攻击面速览", border_style="red"
                ))

            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2, default=str)
                console.print(f"\n  📄 结果已保存: {output}")

        else:
            console.print(f"[red]❌ 失败: {result.get('error', '未知')}[/]")
    finally:
        db.close()


@cli.command()
def fingerprint(
    url: str = typer.Argument(..., help="目标URL"),
    min_conf: float = typer.Option(0.4, "--min-confidence", "-c", help="最低置信度 0-1"),
):
    """对单个 URL 执行指纹识别"""
    console.print(f"[bold cyan]🔍 指纹识别[/] {url}")
    async def _run():
        import httpx, re
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as c:
                r = await c.get(url, follow_redirects=True)
                st, tl, sv = r.status_code, '', r.headers.get('server','')
                m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I)
                if m: tl = m.group(1).strip()[:100]
                body = r.text[:50000]
        except httpx.ConnectError:
            console.print('[red]无法连接目标[/]')
            return None
        except httpx.TimeoutException:
            console.print('[red]请求超时[/]')
            return None
        except Exception as e:
            console.print(f'[red]请求失败: {type(e).__name__}: {e}[/]')
            return None
        from app.modules.vulnscan.orchestrator import VulnOrchestrator
        orch = VulnOrchestrator()
        res = await orch.scan_url(url, headers=dict(r.headers), body=body, status_code=st)
        return (st, tl, sv, res)
    data = asyncio.run(_run())
    if not data: return
    status, title, server, result = data

    console.print(f'  状态: {status} | 标题: {title or "(无)"} | Server: {server or "(无)"}')
    fps = [f for f in result.get("fingerprints", []) if f.get("confidence", 1.0) >= min_conf]
    if fps:
        # 按置信度排序
        fps.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        table = Table(title=f"指纹识别结果 (最低置信度: {min_conf})")
        table.add_column("产品", style="cyan"); table.add_column("置信度", style="green")
        table.add_column("分类", style="yellow"); table.add_column("价值", style="red"); table.add_column("标签")
        for f in fps:
            conf = f.get("confidence", 1.0)
            conf_style = "green" if conf >= 0.8 else ("yellow" if conf >= 0.5 else "red")
            table.add_row(f["name"], f"[{conf_style}]{conf:.0%}[/]", f.get("category",""),
                          f"P{f.get('value',2)}", ",".join(f.get("tags",[]))[:50])
        console.print(table)
    else:
        console.print(f"[yellow]未识别到指纹[/] [dim](置信度阈值: {min_conf}, 可降低 --min-confidence 重试)[/]")


@cli.command()
def vulnscan(
    url: str = typer.Argument(..., help="目标URL"),
):
    """对单个 URL 执行完整漏洞检测（指纹+POC+未授权）"""
    console.print(f"[bold cyan]🧪 漏洞检测[/] {url}")
    async def _run():
        import httpx, re
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as c:
                r = await c.get(url, follow_redirects=True)
                st, tl, sv = r.status_code, '', r.headers.get('server','')
                m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I)
                if m: tl = m.group(1).strip()[:100]
                body = r.text[:50000]
        except Exception as e:
            console.print(f'[red]请求失败: {type(e).__name__}[/]')
            return None
        from app.modules.vulnscan.orchestrator import VulnOrchestrator
        orch = VulnOrchestrator()
        res = await orch.scan_url_with_poc(url, headers=dict(r.headers), body=body, status_code=st)
        return (st, tl, sv, res)
    data = asyncio.run(_run())
    if not data: return
    status, title, server, result = data

    console.print(f"  状态: {status} | 标题: {title or '(无)'} | Server: {server or '(无)'}")
    fps = result.get("fingerprints", [])
    pocs = result.get("poc_results", [])
    vulns = [p for p in pocs if p.get("vulnerable")]

    console.print(f"  指纹: {len(fps)} 条  |  POC匹配: {len(result.get('poc_matches',[]))}  |  漏洞: {len(vulns)}")
    if vulns:
        table = Table(title="⚠️ 发现漏洞")
        table.add_column("名称", style="red"); table.add_column("严重度"); table.add_column("匹配")
        for v in vulns:
            sev_color = {"critical":"red","high":"yellow","medium":"cyan"}.get(v.get("severity",""),"white")
            table.add_row(v.get("name",""), f"[{sev_color}]{v.get('severity','')}[/]",
                          ", ".join(v.get("matched",[])[:3]))
        console.print(table)
    if not vulns:
        console.print("[green]未发现漏洞[/]")


@cli.command()
def scan(
    target: str = typer.Argument(..., help="目标IP或域名"),
    ports: str = typer.Option("", "--ports", "-p", help="端口范围, e.g. 80,443,8080 或 1-1000"),
):
    """快速端口扫描"""
    console.print(f"[bold cyan]🔎 端口扫描[/] {target}")
    async def _run():
        from app.modules.recon.port_scan import PortScanner
        scanner = PortScanner()
        port_list = None
        if ports:
            if "-" in ports:
                s, e = ports.split("-"); port_list = list(range(int(s), int(e)+1))
            else:
                port_list = [int(p) for p in ports.split(",")]
        return await scanner.scan(target, ports=port_list, grab_banner=True)

    result = asyncio.run(_run())
    if result:
        table = Table(title=f"{target} 开放端口")
        table.add_column("端口", style="cyan"); table.add_column("服务", style="yellow")
        table.add_column("Banner", style="dim", max_width=60)
        for p in result:
            table.add_row(str(p["port"]), p.get("service","?"), (p.get("banner","") or "")[:60])
        console.print(table)
    else:
        console.print("[yellow]未发现开放端口[/]")


@cli.command()
def weakpass(
    target: str = typer.Argument(..., help="host:port"),
    service: str = typer.Option("redis", "--service", "-s", help="服务类型: redis/mysql/ssh/ftp/tomcat/jenkins/wordpress"),
):
    """弱口令检测"""
    console.print(f"[bold cyan]🔑 弱口令检测[/] {target} ({service})")
    async def _run():
        from app.modules.vulnscan.weak_password import WeakPasswordChecker
        checker = WeakPasswordChecker()
        return await checker.check(target, service)
    results = asyncio.run(_run())
    if results:
        table = Table(title=f"⚠️ 发现弱口令")
        table.add_column("用户名"); table.add_column("密码", style="red"); table.add_column("证据")
        for r in results:
            table.add_row(r["username"], r["password"], r.get("evidence","")[:80])
        console.print(table)
    else:
        console.print("[green]未发现弱口令[/]")


@cli.command()
def unauth(url: str = typer.Argument(..., help="目标URL")):
    """未授权访问检测"""
    console.print(f"[bold cyan]🚪 未授权检测[/] {url}")
    async def _run():
        from app.modules.vulnscan.unauthorized import UnauthorizedChecker
        checker = UnauthorizedChecker()
        return await checker.check(url)
    results = asyncio.run(_run())
    if results:
        table = Table(title="⚠️ 未授权访问")
        table.add_column("名称"); table.add_column("路径"); table.add_column("严重度"); table.add_column("证据")
        for r in results:
            sev_c = {"critical":"red","high":"yellow","medium":"cyan"}.get(r.get("severity",""),"white")
            table.add_row(r["name"], r["path"], f"[{sev_c}]{r['severity']}[/]", r.get("evidence","")[:60])
        console.print(table)
    else:
        console.print("[green]未发现未授权访问[/]")


@cli.command()
def list(
    org: str = typer.Option("", "--org", "-o", help="组织名称过滤"),
    type: str = typer.Option("subdomains", "--type", "-t", help="资产类型: subdomains/ips/urls/vulns"),
    limit: int = typer.Option(50, "--limit", "-n"),
):
    """列出数据库中已收集的资产"""
    init_db()
    db = SessionLocal()
    try:
        from app.models import Organization, Domain, Subdomain, IPAddress, URL, Vulnerability
        if type == "subdomains":
            q = db.query(Subdomain).order_by(Subdomain.priority.desc()).limit(limit)
            if org:
                q = q.join(Domain).join(Organization).filter(Organization.name.contains(org))
            subs = q.all()
            if subs:
                table = Table(title="子域名列表")
                table.add_column("子域名"); table.add_column("IP"); table.add_column("分类"); table.add_column("优先级")
                for s in subs:
                    cat_c = {"admin":"red","auth":"red","devops":"yellow","api":"blue","dev":"yellow"}.get(s.category,"white")
                    table.add_row(s.subdomain, s.ip or "-", f"[{cat_c}]{s.category or 'other'}[/]", f"P{s.priority or 1}")
                console.print(table)
            else: console.print("[yellow]无数据[/]")
        elif type == "ips":
            ips = db.query(IPAddress).order_by(IPAddress.first_seen.desc()).limit(limit).all()
            if ips:
                table = Table(title="IP列表"); table.add_column("IP"); table.add_column("CDN"); table.add_column("位置")
                for ip in ips:
                    table.add_row(ip.ip, "是" if ip.is_cdn else "否", f"{ip.country or ''} {ip.province or ''}")
                console.print(table)
            else: console.print("[yellow]无数据[/]")
        elif type == "urls":
            urls = db.query(URL).order_by(URL.first_seen.desc()).limit(limit).all()
            if urls:
                table = Table(title="存活URL"); table.add_column("URL"); table.add_column("状态"); table.add_column("标题")
                for u in urls:
                    table.add_row(u.url[:80], str(u.status_code or "-"), (u.title or "")[:40])
                console.print(table)
            else: console.print("[yellow]无数据[/]")
        elif type == "vulns":
            vulns = db.query(Vulnerability).order_by(Vulnerability.severity.desc()).limit(limit).all()
            if vulns:
                table = Table(title="漏洞列表"); table.add_column("名称"); table.add_column("严重度"); table.add_column("类型")
                for v in vulns:
                    sev_c = {"critical":"red","high":"yellow","medium":"cyan","low":"dim"}.get(v.severity,"white")
                    table.add_row(v.name[:50], f"[{sev_c}]{v.severity}[/]", v.vuln_type)
                console.print(table)
            else: console.print("[yellow]无漏洞[/]")
    finally:
        db.close()


@cli.command()
def report(
    org: str = typer.Argument(..., help="组织名称"),
    output: str = typer.Option("", "--output", "--out", "-o", help="输出文件"),
):
    """生成 SRC 格式漏洞报告"""
    init_db()
    db = SessionLocal()
    try:
        from app.models import Organization, Vulnerability
        org_obj = db.query(Organization).filter(Organization.name == org).first()
        if not org_obj:
            console.print(f"[red]组织不存在: {org}[/]"); return
        vulns = db.query(Vulnerability).filter(Vulnerability.org_id == org_obj.id)\
            .order_by(Vulnerability.severity.desc()).all()
        if not vulns:
            console.print("[yellow]该组织暂无漏洞[/]"); return

        lines = [f"# Sky-Eye 漏洞报告 — {org}", "",
                 f"**生成时间:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
                 f"**漏洞总数:** {len(vulns)}", ""]
        for i, v in enumerate(vulns, 1):
            lines.append(f"## {i}. {v.name}")
            lines.append(f"- **严重度:** {v.severity}  |  **类型:** {v.vuln_type}  |  **状态:** {v.status}")
            if v.target: lines.append(f"- **目标:** {v.target}")
            if v.description: lines.append(f"- **描述:** {v.description}")
            if v.evidence: lines.append(f"- **证据:** `{v.evidence[:200]}`")
            if v.poc_id: lines.append(f"- **POC:** `{v.poc_id}`")
            lines.append("")

        content = "\n".join(lines)
        if output:
            with open(output, "w", encoding="utf-8") as f: f.write(content)
            console.print(f"[green]✅ 报告已保存: {output}[/]")
        else:
            console.print(content)
    finally:
        db.close()


if __name__ == "__main__":
    cli()
