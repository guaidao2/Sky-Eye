"""Sky-Eye 域名模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, func, Column
from sqlalchemy.orm import relationship

from app.database import Base


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False, comment="域名")
    source = Column(String(50), nullable=True, comment="发现来源")
    first_seen = Column(DateTime, server_default=func.now(), comment="首次发现")
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now(), comment="最后发现")

    # 关系
    organization = relationship("Organization", back_populates="domains")

    def __repr__(self):
        return f"<Domain(id={self.id}, domain='{self.domain}')>"


class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), index=True, nullable=False)
    subdomain = Column(String(255), index=True, nullable=False, comment="子域名")
    ip = Column(String(45), nullable=True, comment="解析IP")
    cname = Column(String(255), nullable=True, comment="CNAME记录")
    status = Column(String(20), default="unknown", comment="状态")
    source = Column(String(50), nullable=True, comment="发现来源")
    first_seen = Column(DateTime, server_default=func.now(), comment="首次发现")
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now(), comment="最后发现")

    domain = relationship("Domain")

    def __repr__(self):
        return f"<Subdomain(id={self.id}, subdomain='{self.subdomain}')>"
