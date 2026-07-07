"""Sky-Eye 端口模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Boolean, func, Column
from sqlalchemy.orm import relationship

from app.database import Base


class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_id = Column(Integer, ForeignKey("ip_addresses.id", ondelete="CASCADE"), index=True, nullable=False)
    port = Column(Integer, nullable=False, comment="端口号")
    protocol = Column(String(20), default="tcp", comment="协议")
    service = Column(String(100), nullable=True, comment="服务名称")
    banner = Column(Text, nullable=True, comment="Banner信息")
    is_http = Column(Boolean, default=False, comment="是否为HTTP服务")
    state = Column(String(20), default="open", comment="端口状态")
    first_seen = Column(DateTime, server_default=func.now(), comment="首次发现")
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now(), comment="最后发现")

    # 关系
    ip_address = relationship("IPAddress", back_populates="ports")
    urls = relationship("URL", back_populates="port", cascade="all, delete-orphan")
    fingerprints = relationship("Fingerprint", back_populates="port", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="port", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Port(id={self.id}, {self.ip_id}:{self.port}/{self.protocol})>"
