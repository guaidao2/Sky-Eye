"""Sky-Eye IP地址模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, Boolean, func, Column, Text
from sqlalchemy.orm import relationship

from app.database import Base


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), unique=True, index=True, nullable=False, comment="IP地址")
    asn = Column(String(50), nullable=True, comment="ASN编号")
    asn_org = Column(String(255), nullable=True, comment="ASN所属组织")
    cidr = Column(String(50), nullable=True, comment="CIDR网段")
    country = Column(String(100), nullable=True, comment="国家")
    province = Column(String(100), nullable=True, comment="省份")
    city = Column(String(100), nullable=True, comment="城市")
    is_cdn = Column(Boolean, default=False, comment="是否CDN")
    is_alive = Column(Boolean, default=None, comment="是否存活")
    first_seen = Column(DateTime, server_default=func.now(), comment="首次发现")
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now(), comment="最后发现")

    # 关系
    ports = relationship("Port", back_populates="ip_address", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<IPAddress(id={self.id}, ip='{self.ip}')>"
