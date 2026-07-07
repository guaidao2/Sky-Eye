<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.0-blue" alt="version">
  <img src="https://img.shields.io/badge/python-3.11+-green" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-orange" alt="license">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="platform">
</p>

<p align="center">
  <h1 align="center">🛰️ Sky-Eye</h1>
  <p align="center"><b>全链路资产挖掘与漏洞打点系统</b></p>
  <p align="center">输入域名或 IP → 自动识别 → 子域名收集 → 智能分类 → 指纹识别 → POC 检测 → SRC 报告</p>
</p>

---

## ✨ 特性

- 🔍 **全链路 Pipeline** — 输入域名，自动走完 8 个阶段：空间搜索引擎 → 子域名 → 智能分类评分 → CDN 穿透 → IP/端口/Banner → Web 存活 → 双引擎指纹 → JS/目录 → POC 匹配。输入 IP 自动跳过域名阶段直达端口扫描
- 🎯 **子域名智能分类** — 16 条规则自动标记：管理后台(P5)/认证(P5)/DevOps(P5)/API(P4)/开发测试(P4)/VPN/数据库/监控/OA 等 12 类，渗透测试视角优先排序
- 📡 **实时资产展示** — 扫描过程中仪表盘 4 张卡片实时刷新：子域名列表、IP/端口详情、存活 URL、漏洞发现，跟 ARL 灯塔一样的效果
- 🎯 **双引擎指纹识别** — 自研 YAML 引擎 + FingerprintHub 3290+ 规则，覆盖 OA/CMS/框架/中间件/WAF/安全设备
- 🧪 **3173+ POC** — 兼容 Nuclei YAML 格式，支持 `{{BaseURL}}`、raw HTTP、多步链式、AND/OR 匹配器
- 🔑 **弱口令检测** — 9 种服务（SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Tomcat/Jenkins/WordPress）
- 🚪 **未授权检测** — 60+ 敏感端点（Actuator/Swagger/Druid/Nacos/Docker/K8s/ES/云元数据）
- 🕵️ **CDN 穿透** — 5 种技术（DNS 历史/SSL SAN/MX 记录/子域名对比/证书透明度）
- 📡 **空间搜索引擎** — Fofa / Hunter / Quake API 一键回填资产
- 📂 **目录扫描** — 4 类 95+ 敏感路径（备份文件/未授权接口/管理后台/源码泄露）
- 🛡️ **WAF 规避** — 随机 UA 池、X-Forwarded-For 伪造、请求延迟抖动
- 📝 **SRC 报告** — 一键生成 Markdown 格式漏洞报告，适配补天/漏洞盒子
- 🌐 **Web 管理面板** — 仪表盘(实时资产+攻击面速览) / 资产管理(CRUD+分类过滤) / 任务管理(实时进度+取消重试) / 漏洞管理(筛选+报告)

## 📦 快速开始

### 环境要求

- Python 3.11+
- pip

### 安装

```bash
git clone https://github.com/guaidao2/Sky-Eye.git
cd Sky-Eye
pip install -r backend/requirements.txt
```

### 启动

```bash
# Web 管理面板（推荐）
python sky-eye.py server

# 命令行一键信息收集
python sky-eye.py recon baidu.com

# 快速端口扫描
python sky-eye.py scan 192.168.1.1
```

浏览器打开 `http://127.0.0.1:8000`，输入域名点击"开始扫描"，实时看到资产逐个出现。

### 配置第三方 API（可选）

复制 `backend/.env.example` 为 `backend/.env` 并填入：

```env
# 空间搜索引擎（配置后自动回填资产）
FOFA_EMAIL=your_email
FOFA_KEY=your_fofa_key
HUNTER_API_KEY=your_hunter_key
QUAKE_TOKEN=your_quake_token

# CDN 穿透
SECURITYTRAILS_API_KEY=your_st_key

# HTTP 代理（调试用）
HTTP_PROXY=http://127.0.0.1:8080
```

---

## 🏗️ 架构

```
输入域名/IP → 自动识别类型
  │
  ├─ 域名模式:
  │   ├─ Phase 0   空间搜索引擎回填 (Fofa / Hunter / Quake)
  │   ├─ Phase 1   子域名收集 (crt.sh + SecurityTrails + DNS 爆破)
  │   ├─ Phase 1.2 子域名智能分类评分 (12类/P1-P5)
  │   ├─ Phase 1.5 CDN 穿透 (5 种技术)
  │   ├─ Phase 2   IP 解析 + ASN 查询
  │   ├─ Phase 3   端口扫描 + Banner 抓取 (300+ 端口)
  │   ├─ Phase 4   Web 存活探测 + 技术栈识别
  │   ├─ Phase 4.5 双引擎指纹识别 (YAML + FingerprintHub 3290)
  │   ├─ Phase 5   JS 敏感信息 + 目录扫描 (95+ 路径)
  │   └─ Phase 6   自动 POC 匹配 (标签交集 → 3173 POCs)
  │
  └─ IP 模式: 直达 Phase 3 端口扫描（跳过子域名/CDN/DNS）
                    │
                    ▼
              漏洞报告 (Markdown / SRC 格式)
```

```
sky-eye/
├── sky-eye.py                 # 🚀 一键启动入口
├── README.md
├── backend/
│   ├── cli.py                 # Typer CLI
│   ├── requirements.txt       # 依赖列表
│   ├── .env.example           # 环境配置模板
│   └── app/
│       ├── main.py            # FastAPI 应用 + 页面路由
│       ├── config.py          # 30+ 配置项
│       ├── database.py        # SQLAlchemy + 自动迁移
│       ├── api/__init__.py    # 33 个 REST 端点
│       ├── models/            # 10 张数据表
│       ├── schemas/           # Pydantic 校验
│       ├── modules/
│       │   ├── recon/         # 信息收集 (8 个子模块)
│       │   ├── fingerprint/   # 指纹识别 (双引擎)
│       │   └── vulnscan/      # 漏洞检测 (5 个子模块)
│       ├── templates/         # Jinja2 页面 (4 页)
│       └── static/            # CSS/JS
├── pocs/                      # 3173+ Nuclei POC
├── fingerprints/              # FingerprintHub 指纹库
├── dictionaries/              # 字典文件
└── reports/                   # 报告输出
```

## 🖥️ Web 面板

| 页面 | 路径 | 功能 |
|------|------|------|
| **仪表盘** | `/` | 实时资产卡片(子域名/IP/URL/漏洞) + 攻击面速览 + 快速开始 + 最近任务(智能刷新) |
| **资产管理** | `/assets` | 组织 CRUD + 子域名(分类/优先级过滤) + IP/端口 + URL + 指纹 四个 Tab |
| **任务管理** | `/tasks` | 状态/类型过滤 + 实时进度 + 详情弹窗 + 取消/重试/删除 |
| **漏洞管理** | `/vulns` | 严重度/状态/组织筛选 + 报告下载 |

## 🔌 API 端点（33 个）

| 分类 | 端点 | 方法 |
|------|------|------|
| 资产 | `/overview` `/stats` `/ips` `/urls` `/organizations` | GET/POST/DELETE |
| 扫描 | `/scan/fingerprint` `/scan/full` `/scan/weakpass` `/scan/unauth` `/scan/dir` | POST |
| POC | `/pocs` `/pocs/{id}` `/pocs/{id}/execute` | GET/POST |
| 漏洞 | `/vulnerabilities` `/vulnerabilities/{id}` | GET/PUT/DELETE |
| 指纹 | `/fingerprints` `/urls/{id}/fingerprints` | GET |
| 任务 | `/tasks` `/tasks/{id}` `/tasks/{id}/cancel` `/tasks/{id}/retry` `/tasks/{id}/live` | GET/POST/PUT/DELETE |
| 报告 | `/report` | POST |

## 🎯 适用场景

- **SRC 漏洞挖掘** — 资产发现 → 指纹 → POC → 报告一条龙
- **攻防演练** — 红队快速打点，蓝队资产梳理
- **安全测试** — 自动化信息收集与漏洞验证

## 📋 路线图

- [x] 信息收集引擎（子域名/IP/端口/Web/JS）
- [x] 智能 IP/域名识别 + 分支 Pipeline
- [x] 子域名智能分类评分（12类 P1-P5）
- [x] 实时资产展示（ARL 风格 4 卡片）
- [x] 双引擎指纹识别（YAML + FingerprintHub 3290）
- [x] POC 引擎 v2（{{BaseURL}} + WAF 规避）
- [x] 弱口令检测（9 种服务）
- [x] 未授权检测（60+ 端点）
- [x] 空间搜索引擎集成（Fofa/Hunter/Quake）
- [x] CDN 穿透（5 种技术）
- [x] 目录扫描 + JS 敏感信息
- [x] SRC 报告生成
- [x] Web 管理面板（4 页完整 CRUD）
- [ ] 定时巡检 + 资产变更监控
- [ ] 多用户认证
- [ ] Celery 任务队列
- [ ] PostgreSQL 支持
- [ ] Vue3 前端重构

## 🙏 参考项目

本项目在开发过程中参考了以下优秀开源项目的设计与思路：

| 项目 | 说明 | 参考内容 |
|------|------|---------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ProjectDiscovery | POC 模板格式、匹配器设计、YAML 解析 |
| [FingerprintHub](https://github.com/0x727/FingerprintHub) | 0x727 团队 | Web 指纹规则库（`web_fingerprint_v4.json` 3290+ 条） |
| [ARL](https://github.com/TophantTechnology/ARL) | 斗象科技 | 资产侦察灯塔，实时资产展示 + Pipeline 思路 |
| [Fscan](https://github.com/shadow1ng/fscan) | shadow1ng | 内网综合扫描，端口扫描与服务识别 |
| [ksubdomain](https://github.com/knownsec/ksubdomain) | 知道创宇 | 无状态子域名爆破思路 |
| [Httpx](https://github.com/projectdiscovery/httpx) | ProjectDiscovery | Web 存活探测与指纹识别 |
| [EHole](https://github.com/EdgeSecurityTeam/EHole) | 棱角安全团队 | 指纹识别引擎设计 |

## 🤝 贡献

欢迎提交 Issue 和 PR。

## 📄 许可

MIT License

---

<p align="center">
  <b>玄幕安全团队 · guaidao2 开发</b>
</p>
