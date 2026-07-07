"""Sky-Eye 模型注册"""

from app.database import Base

# 导入所有模型确保注册
from app.models.organization import Organization
from app.models.domain import Domain, Subdomain
from app.models.ip_address import IPAddress
from app.models.domain_ip import domain_ip_association
from app.models.port import Port
from app.models.url import URL
from app.models.js_sensitive import JSSensitive
from app.models.task import Task
from app.models.fingerprint import Fingerprint
from app.models.vulnerability import Vulnerability

__all__ = [
    "Base",
    "Organization",
    "Domain",
    "Subdomain",
    "IPAddress",
    "domain_ip_association",
    "Port",
    "URL",
    "JSSensitive",
    "Task",
    "Fingerprint",
    "Vulnerability",
]
