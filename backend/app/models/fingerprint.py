"""Sky-Eye 指纹识别结果模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Float, func, Column
from sqlalchemy.orm import relationship

from app.database import Base


class Fingerprint(Base):
    __tablename__ = "fingerprints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id", ondelete="CASCADE"), index=True, nullable=True, comment="关联URL")
    port_id = Column(Integer, ForeignKey("ports.id", ondelete="CASCADE"), index=True, nullable=True, comment="关联端口")
    name = Column(String(255), nullable=False, comment="产品/组件名称")
    category = Column(String(100), nullable=True, comment="分类: oa/cms/framework/middleware/device/waf")
    version = Column(String(100), nullable=True, comment="版本号")
    vendor = Column(String(255), nullable=True, comment="厂商")
    confidence = Column(Float, default=1.0, comment="置信度 0-1")
    value_level = Column(Integer, default=2, comment="资产价值: 1-5")
    matched_rules = Column(Text, nullable=True, comment="命中的规则详情(JSON)")
    tags = Column(String(500), nullable=True, comment="标签，逗号分隔")
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now())

    url = relationship("URL", back_populates="fingerprints")
    port = relationship("Port", back_populates="fingerprints")

    def __repr__(self):
        return f"<Fingerprint(id={self.id}, name='{self.name}', cat='{self.category}')>"
