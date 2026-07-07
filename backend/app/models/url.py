"""Sky-Eye URL 模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, func, Column
from sqlalchemy.orm import relationship

from app.database import Base


class URL(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    port_id = Column(Integer, ForeignKey("ports.id", ondelete="SET NULL"), index=True, nullable=True)
    url = Column(String(2048), nullable=False, comment="完整URL")
    scheme = Column(String(10), default="http", comment="协议")
    host = Column(String(255), nullable=False, comment="主机名")
    port = Column(Integer, default=80, comment="端口")
    path = Column(String(1024), nullable=True, comment="路径")
    status_code = Column(Integer, nullable=True, comment="HTTP状态码")
    title = Column(String(500), nullable=True, comment="页面标题")
    content_type = Column(String(100), nullable=True, comment="Content-Type")
    content_length = Column(Integer, nullable=True, comment="响应体大小")
    tech_stack = Column(String(500), nullable=True, comment="技术栈")
    screenshot = Column(String(500), nullable=True, comment="截图路径")
    first_seen = Column(DateTime, server_default=func.now(), comment="首次发现")
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now(), comment="最后发现")

    # 关系
    port = relationship("Port", back_populates="urls")
    js_sensitives = relationship("JSSensitive", back_populates="url", cascade="all, delete-orphan")
    fingerprints = relationship("Fingerprint", back_populates="url", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<URL(id={self.id}, url='{self.url}')>"
