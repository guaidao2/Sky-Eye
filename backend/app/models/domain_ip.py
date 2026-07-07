"""Sky-Eye 域名/IP 关联表"""

from sqlalchemy import Table, Column, Integer, ForeignKey
from app.database import Base

domain_ip_association = Table(
    "domain_ip_association",
    Base.metadata,
    Column("domain_id", Integer, ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True),
    Column("ip_id", Integer, ForeignKey("ip_addresses.id", ondelete="CASCADE"), primary_key=True),
)
