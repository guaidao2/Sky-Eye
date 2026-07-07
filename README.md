<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0-blue" alt="version">
  <img src="https://img.shields.io/badge/python-3.11+-green" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-orange" alt="license">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="platform">
</p>

<p align="center">
  <h1 align="center">🛰️ Sky-Eye</h1>
  <p align="center"><b>全链路资产挖掘与漏洞打点系统</b></p>
  <p align="center">从信息收集 → 指纹识别 → 漏洞检测 → 弱口令/未授权 → SRC 报告，一站式完成</p>
</p>

---

## ✨ 特性

- 🔍 **全链路 Pipeline** — 输入域名，自动走完 7 个阶段：空间搜索引擎回填 → 子域名 → CDN 穿透 → IP/端口/Banner → Web 存活 → 指纹识别 → JS/目录扫描 → POC 匹配
- 🎯 **双引擎指纹识别** — 自研 YAML 引擎 + FingerprintHub 3290+ 规则，覆盖 OA/CMS/框架/中间件/WAF/安全设备
- 🧪 **3173+ POC** — 兼容 Nuclei YAML 格式，支持 `{{BaseURL}}`、raw HTTP、多步链式、AND/OR 匹配器
- 🔑 **弱口令检测** — 9 种服务（SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Tomcat/Jenkins/WordPress）
- 🚪 **未授权检测** — 60+ 敏感端点（Actuator/Swagger/Druid/Nacos/Docker/K8s/ES/云元数据）
- 🕵️ **CDN 穿透** — 5 种技术（DNS 历史/SSL SAN/MX 记录/子域名对比/证书透明度）
- 📡 **空间搜索引擎** — Fofa / Hunter / Quake API 一键回填资产
- 📂 **目录扫描** — 4 类 95+ 敏感路径（备份文件/未授权接口/管理后台/源码泄露）
- 🛡️ **WAF 规避** — 随机 UA 池、X-Forwarded-For 伪造、请求延迟抖动
- 📝 **SRC 报告** — 一键生成 Markdown 格式漏洞报告，适配补天/漏洞盒子
- 🌐 **Web 管理面板** — 仪表盘 / 资产地图 / 任务管理 / 漏洞管理

## 📦 快速开始

### 环境要求

- Python 3.11+
- pip

### 安装

```bash
git clone https://github.com/your-org/sky-eye.git
cd sky-eye
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

浏览器打开 `http://127.0.0.1:8000` 进入管理面板。

### 配置第三方 API（可选）

编辑 `backend/.env`：

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
输入域名
  │
  ├─ Phase 0  空间搜索引擎回填 (Fofa / Hunter / Quake)
  ├─ Phase 1  子域名收集 (crt.sh + SecurityTrails + DNS 爆破)
  ├─ Phase 1.5 CDN 穿透 (5 种技术)
  ├─ Phase 2  IP 解析 + ASN 查询
  ├─ Phase 3  端口扫描 + Banner 抓取 (300+ 端口)
  ├─ Phase 4  Web 存活探测 + 技术栈识别
  ├─ Phase 4.5 双引擎指纹识别 (YAML + FingerprintHub)
  ├─ Phase 5  JS 敏感信息 + 目录扫描
  └─ Phase 6  自动 POC 匹配 (标签交集 → 3173 POCs)
                    │
                    ▼
              漏洞报告 (Markdown / SRC 格式)
```

```
sky-eye/
├── sky-eye.py                 # 🚀 一键启动入口
├── backend/
│   ├── cli.py                 # Typer CLI
│   ├── requirements.txt       # 依赖列表
│   ├── .env                   # 环境配置
│   ├── sky_eye.db             # SQLite 数据库
│   └── app/
│       ├── main.py            # FastAPI 应用
│       ├── config.py          # 配置中心
│       ├── database.py        # 数据库层
│       ├── api/               # 31 个 REST 端点
│       ├── models/            # 10 张数据表
│       ├── schemas/           # Pydantic 校验
│       ├── modules/
│       │   ├── recon/         # 信息收集引擎
│       │   ├── fingerprint/   # 指纹识别引擎
│       │   └── vulnscan/      # 漏洞检测引擎
│       ├── templates/         # Jinja2 页面
│       └── static/            # CSS/JS
├── pocs/                      # 3173+ Nuclei POC
├── fingerprints/              # FingerprintHub 指纹库
├── dictionaries/              # 字典文件
└── reports/                   # 报告输出
```

## 🖥️ Web 面板

| 页面 | 功能 |
|------|------|
| **仪表盘** `/` | 资产统计、漏洞分布、快速开始、最近任务 |
| **资产地图** `/assets` | 组织/域名/IP/端口/URL 层级展示 |
| **任务管理** `/tasks` | 创建/查看/取消扫描任务 |
| **漏洞管理** `/vulns` | 漏洞筛选(严重度/状态/组织)、详情、报告下载 |

## 🔌 API 端点（31 个）

| 分类 | 端点 | 方法 |
|------|------|------|
| 资产 | `/overview` `/stats` `/ips` `/urls` `/organizations` | GET/POST |
| 扫描 | `/scan/fingerprint` `/scan/full` `/scan/weakpass` `/scan/unauth` `/scan/dir` | POST |
| POC | `/pocs` `/pocs/{id}` `/pocs/{id}/execute` | GET/POST |
| 漏洞 | `/vulnerabilities` `/vulnerabilities/{id}` | GET/PUT/DELETE |
| 指纹 | `/fingerprints` `/urls/{id}/fingerprints` | GET |
| 任务 | `/tasks` `/tasks/{id}` `/tasks/{id}/cancel` | GET/POST/PUT |
| 报告 | `/report` | POST |

## 🎯 适用场景

- **SRC 漏洞挖掘** — 资产发现 → 指纹 → POC → 报告一条龙
- **攻防演练** — 红队快速打点，蓝队资产梳理
- **安全测试** — 自动化信息收集与漏洞验证
- **持续监控** — 资产变更追踪（规划中）

## 📋 路线图

- [x] 信息收集引擎（子域名/IP/端口/Web/JS）
- [x] 双引擎指纹识别（YAML + FingerprintHub）
- [x] POC 引擎 v2（Nuclei 兼容 + WAF 规避）
- [x] 弱口令检测（9 种服务）
- [x] 未授权检测（60+ 端点）
- [x] 空间搜索引擎集成（Fofa/Hunter/Quake）
- [x] CDN 穿透（5 种技术）
- [x] 目录扫描 + JS 敏感信息
- [x] SRC 报告生成
- [x] Web 管理面板
- [ ] 定时巡检 + 资产变更监控
- [ ] 多用户认证
- [ ] Celery 任务队列
- [ ] PostgreSQL 支持
- [ ] Vue3 前端重构

## 🤝 贡献

欢迎提交 Issue 和 PR。

## 📄 许可

MIT License

---

<p align="center">
  <b>玄幕安全团队 · guaidao2 开发</b>
</p>
