# Sky-Eye v0.2 — 资产挖掘与打点系统

SRC 漏洞挖掘全链路平台：信息收集 → 指纹识别 → 漏洞检测 → 弱口令/未授权 → 报告。

## Project

- **Stack:** Python 3.11+ · FastAPI · SQLAlchemy 2.0 (sync) · SQLite · Jinja2 · Typer CLI
- **Entry points:** 项目根目录 `sky-eye.py`（一键启动）→ 内部调用 `backend/cli.py`；`backend/app/main.py` (FastAPI app)
- **Database:** SQLite at `backend/sky_eye.db`, auto-created on first run
- **Config:** `backend/app/config.py` (reads `backend/.env`), supports Fofa/Hunter/Quake/Shodan API keys + proxy
- **Version:** 0.2.0 (31 API routes, 4 Web pages, 7-phase Recon Pipeline)

## Commands

```bash
# 在项目根目录下运行
pip install -r backend/requirements.txt
python sky-eye.py server                          # 启动 Web UI → http://127.0.0.1:8000
python sky-eye.py server -p 8080 -H 0.0.0.0      # 自定义端口/地址
python sky-eye.py recon example.com               # CLI 一键信息收集
python sky-eye.py scan 192.168.1.1                # 快速端口扫描
```

No formal test/lint commands yet.

## Architecture

```
backend/app/
├── main.py              FastAPI app, 4 page routes (dashboard/assets/tasks/vulns)
├── cli.py               Typer CLI
├── config.py            Pydantic Settings (30+ options: APIs, proxy, WAF evasion, cron)
├── database.py          SQLAlchemy sync engine, get_db, init_db (10 tables)
├── api/__init__.py      REST router /api/v1 — 31 endpoints (orgs/assets/scan/report/stats)
├── models/              Organization, Domain, Subdomain, IPAddress, Port, URL,
│                        JSSensitive, Task, Fingerprint, Vulnerability
├── schemas/             Pydantic Create/Response/Update schemas + ScanRequest/DirScanRequest etc.
├── modules/
│   ├── recon/
│   │   ├── orchestrator.py  v2 7-phase Pipeline (space_engine→subdomain→CDN→IP→port→web→fingerprint→JS→dir→POC)
│   │   ├── space_engine.py  Fofa/Hunter/Quake API integration
│   │   ├── cdn_bypass.py    5-method CDN bypass (DNS history, SSL SAN, MX, subdomain compare, cert transparency)
│   │   ├── dir_scanner.py   4-category 95+ path scanner (backup/unauth/admin/source_leak)
│   │   ├── subdomain.py     crt.sh + SecurityTrails + DNS brute + built-in 200-word dict
│   │   ├── port_scan.py     TCP Connect scanner w/ banner grabbing + 300+ port service map
│   │   ├── web_probe.py     HTTP/HTTPS alive probe + title/tech detection
│   │   ├── ip_resolve.py    DNS → IP + ASN via ipinfo.io
│   │   └── js_extract.py    JS URL extraction + 6-type sensitive info regex (API keys/cloud keys/passwords...)
│   ├── fingerprint/
│   │   ├── engine.py        YAML fingerprint rules → multi-dimension match (header/body/url/favicon)
│   │   └── hub_adapter.py   FingerprintHub JSON adapter (3290 rules from web_fingerprint_v4.json)
│   └── vulnscan/
│       ├── orchestrator.py  v2 auto-tag POC matching (intersection-based, not hardcoded)
│       ├── poc_engine.py    v2 Nuclei executor: {{BaseURL}}, raw HTTP, multi-step, AND/OR matchers, WAF evasion
│       ├── poc_parser.py    v2 YAML parser: raw format, Host override, negative matchers, matchers-condition
│       ├── weak_password.py 9-service checker (SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Tomcat/Jenkins/WordPress)
│       └── unauthorized.py  60+ unauth path checker (Actuator/Swagger/Druid/Nacos/Docker/K8s/ES)
├── templates/           Jinja2: dashboard.html, assets.html, tasks.html, vulns.html
└── static/              CSS/JS
```

**Pipeline flow (v2):** ReconOrchestrator.run_pipeline() runs sequentially in a background thread:
Phase 0 (space engine) → 1 (subdomain) → 1.5 (CDN bypass) → 2 (IP resolve) → 3 (port+banner) → 4 (web probe) → 4.5 (fingerprint) → 5 (JS+dir scan+vuln auto-create) → 6 (auto POC matching).

## Conventions

- **Models:** SQLAlchemy `Column()` style. Every model has `__repr__`. In `backend/app/models/`.
- **Schemas:** Pydantic v2 with `from_attributes = True`. Naming: `*Create` (input), `*Response` (output), `*Update` (partial).
- **Modules:** Class per responsibility (e.g., `PortScanner`, `FingerprintEngine`, `WeakPasswordChecker`). No base class.
- **Async:** `httpx.AsyncClient` for HTTP. Sync orchestrator wraps async via `asyncio.run()`.
- **DB:** `get_db()` dependency for FastAPI routes. CLI uses `SessionLocal()` + `close()` in `finally`.
- **Config:** All through `app.config.settings`. No hardcoded paths.
- **POC format:** Nuclei YAML v2 subset — raw HTTP, {{BaseURL}}, AND/OR matchers, negative matching.
- **Fingerprint format:** YAML (FingerprintEngine) + JSON (FingerprintHub 3290 rules).

## Notes

- POC engine loads 3173 POCs from `pocs/` directory (oa/cms/enterprise/framework/middleware/device)
- Space engine queries Fofa/Hunter/Quake only when API keys are configured in `.env`
- Exploit module is gated behind `ENABLE_EXPLOIT=False` (safety default)
- Weak password checker does basic connectivity checks; full auth testing needs paramiko/pymysql optional deps
- dictionaries/passwords/ and dictionaries/subdomains/ are currently empty — populate for production use
