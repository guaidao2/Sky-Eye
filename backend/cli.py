"""Sky-Eye CLI 命令行入口"""

import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from app.config import settings
from app.database import init_db, SessionLocal

cli = typer.Typer(
    name="sky-eye",
    help="Sky-Eye 资产挖掘与打点系统",
    add_completion=False,
)
console = Console()


@cli.command()
def version():
    """显示版本信息"""
    console.print(f"[bold cyan]Sky-Eye[/] v{settings.APP_VERSION}")
    console.print(f"  DB: {settings.DATABASE_URL}")


@cli.command()
def server(
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="监听地址"),
    port: int = typer.Option(8000, "--port", "-p", help="监听端口"),
    reload: bool = typer.Option(False, "--reload", help="热重载"),
):
    """启动 Web 服务"""
    import uvicorn
    console.print(f"[bold green]🚀 Sky-Eye Server[/] 启动于 http://{host}:{port}")
    console.print(f"  API 文档: http://{host}:{port}/docs")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@cli.command()
def recon(
    domain: str = typer.Argument(..., help="目标域名"),
    org: str = typer.Option("", "--org", "-o", help="所属组织名称"),
    output: str = typer.Option("", "--output", "--out", help="输出结果到文件"),
):
    """执行信息收集（域名→子域名→IP→端口→Web）"""
    console.print(f"[bold cyan]🔍 Sky-Eye Recon[/] 目标: {domain}")

    init_db()
    db = SessionLocal()

    try:
        from app.models import Organization, Task

        # 创建或获取组织
        org_name = org or domain
        org_obj = db.query(Organization).filter(Organization.name == org_name).first()
        if not org_obj:
            org_obj = Organization(name=org_name)
            db.add(org_obj)
            db.commit()
            db.refresh(org_obj)

        # 创建任务
        task = Task(
            org_id=org_obj.id,
            name=f"Recon: {domain}",
            task_type="recon",
            target=domain,
            status="pending",
        )
        db.add(task)
        db.commit()
        task_id = task.id

        from app.modules.recon.orchestrator import ReconOrchestrator
        orchestrator = ReconOrchestrator()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="正在收集资产...", total=None)
            result = orchestrator.run_pipeline(task_id, db)

        console.print(f"\n[bold green]✅ 信息收集完成![/]")

        if "summary" in result:
            s = result["summary"]
            table = Table(title="资产汇总")
            table.add_column("资产类型", style="cyan")
            table.add_column("数量", style="bold yellow")
            table.add_row("子域名", str(s.get("subdomains", 0)))
            table.add_row("IP地址", str(s.get("ips", 0)))
            table.add_row("开放端口", str(s.get("ports", 0)))
            table.add_row("存活URL", str(s.get("urls", 0)))
            table.add_row("JS发现", str(s.get("js_findings", 0)))
            console.print(table)

            if output:
                import json
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2, default=str)
                console.print(f"  结果已保存: {output}")

            console.print(f"\n打开 Web 界面查看详情: [underline]http://127.0.0.1:8000[/]")
        else:
            console.print(f"[red]❌ 执行失败: {result.get('error', '未知错误')}[/]")
    finally:
        db.close()


@cli.command()
def scan(
    target: str = typer.Argument(..., help="目标域名或IP"),
):
    """快速端口扫描"""
    console.print(f"[bold cyan]🔎 端口扫描[/] 目标: {target}")

    async def _run():
        from app.modules.recon.port_scan import PortScanner
        scanner = PortScanner()
        return await scanner.scan(target)

    result = asyncio.run(_run())

    if result:
        table = Table(title=f"{target} 开放端口")
        table.add_column("端口", style="cyan")
        table.add_column("状态", style="green")
        table.add_column("猜测服务", style="yellow")
        for p in result:
            table.add_row(str(p["port"]), p["state"], p.get("service", ""))
        console.print(table)
    else:
        console.print("[yellow]未发现开放端口[/]")


if __name__ == "__main__":
    cli()
