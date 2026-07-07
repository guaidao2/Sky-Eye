"""Sky-Eye Pydantic 校验模型"""

import datetime
from pydantic import BaseModel, Field


# ── 组织 ──

class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    industry: str | None = None
    icp: str | None = None
    description: str | None = None
    tags: str | None = None
    scope_in: str | None = None
    scope_out: str | None = None


class OrganizationResponse(BaseModel):
    id: int
    name: str
    industry: str | None = None
    icp: str | None = None
    description: str | None = None
    tags: str | None = None
    scope_in: str | None = None
    scope_out: str | None = None
    created_at: datetime.datetime | None = None

    class Config:
        from_attributes = True


# ── 域名 ──

class DomainResponse(BaseModel):
    id: int
    org_id: int
    domain: str
    source: str | None = None
    first_seen: datetime.datetime | None = None

    class Config:
        from_attributes = True


class SubdomainResponse(BaseModel):
    id: int
    subdomain: str
    ip: str | None = None
    cname: str | None = None
    status: str | None = None
    source: str | None = None

    class Config:
        from_attributes = True


# ── IP ──

class IPResponse(BaseModel):
    id: int
    ip: str
    asn: str | None = None
    asn_org: str | None = None
    cidr: str | None = None
    is_cdn: bool | None = False
    country: str | None = None
    province: str | None = None
    city: str | None = None

    class Config:
        from_attributes = True


# ── 端口 ──

class PortResponse(BaseModel):
    id: int
    port: int
    protocol: str | None = "tcp"
    service: str | None = None
    banner: str | None = None
    is_http: bool | None = False
    state: str = "open"

    class Config:
        from_attributes = True


# ── URL ──

class URLResponse(BaseModel):
    id: int
    url: str
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    tech_stack: str | None = None

    class Config:
        from_attributes = True


# ── 任务 ──

class TaskCreate(BaseModel):
    org_id: int
    name: str = Field(..., min_length=1, max_length=255)
    task_type: str = Field(..., pattern="^(recon|fingerprint|vulnscan)$")
    target: str = Field(..., min_length=1)
    config: str | None = None


class TaskResponse(BaseModel):
    id: int
    org_id: int
    name: str
    task_type: str
    target: str
    target_type: str | None = "domain"
    status: str
    progress: int
    result_summary: str | None = None
    error: str | None = None
    created_at: datetime.datetime | None = None
    started_at: datetime.datetime | None = None
    completed_at: datetime.datetime | None = None

    class Config:
        from_attributes = True


# ── JS敏感信息 ──

class JSSensitiveResponse(BaseModel):
    id: int
    info_type: str
    content: str
    source_url: str | None = None

    class Config:
        from_attributes = True


# ── 资产概览 ──

class AssetOverview(BaseModel):
    total_organizations: int = 0
    total_domains: int = 0
    total_subdomains: int = 0
    total_ips: int = 0
    total_ports: int = 0
    total_urls: int = 0
    total_js_sensitives: int = 0
    total_tasks: int = 0


# ── 指纹 ──

class FingerprintResponse(BaseModel):
    id: int
    url_id: int | None = None
    port_id: int | None = None
    name: str
    category: str | None = None
    version: str | None = None
    vendor: str | None = None
    confidence: float | None = 1.0
    value_level: int = 2
    tags: str | None = None
    matched_rules: str | None = None

    class Config:
        from_attributes = True


# ── 漏洞 ──

class VulnerabilityCreate(BaseModel):
    url_id: int | None = None
    port_id: int | None = None
    org_id: int | None = None
    name: str
    vuln_type: str
    severity: str = "info"
    target: str | None = None
    description: str | None = None
    poc_id: str | None = None
    evidence: str | None = None


class VulnerabilityResponse(BaseModel):
    id: int
    url_id: int | None = None
    port_id: int | None = None
    org_id: int | None = None
    name: str
    vuln_type: str
    severity: str
    cvss_score: float | None = None
    target: str | None = None
    description: str | None = None
    poc_id: str | None = None
    evidence: str | None = None
    status: str
    src_platform: str | None = None
    src_id: str | None = None
    bounty: str | None = None
    found_at: datetime.datetime | None = None
    submitted_at: datetime.datetime | None = None

    class Config:
        from_attributes = True


class VulnerabilityUpdate(BaseModel):
    status: str | None = None
    src_platform: str | None = None
    src_id: str | None = None
    bounty: str | None = None
    severity: str | None = None


# ── 扫描请求 ──

class ScanRequest(BaseModel):
    url: str
    headers: dict = {}
    body: str = ""


class DirScanRequest(BaseModel):
    url: str
    wordlist_type: str = "common"


class WeakPassRequest(BaseModel):
    target: str
    service: str


# ── 报告 ──

class ReportRequest(BaseModel):
    org_id: int
    format: str = "markdown"
    include_poc: bool = True
    include_evidence: bool = True


class ReportResponse(BaseModel):
    id: int
    org_id: int
    format: str
    content: str
    generated_at: datetime.datetime | None = None
