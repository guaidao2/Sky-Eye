"""Sky-Eye 组织模型"""

import datetime
from sqlalchemy import String, Text, DateTime, func, Column, Integer
from sqlalchemy.orm import relationship

from app.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), index=True, nullable=False, comment="组织名称")
    industry = Column(String(100), nullable=True, comment="所属行业")
    icp = Column(String(100), nullable=True, comment="ICP备案号")
    description = Column(Text, nullable=True, comment="备注描述")
    tags = Column(String(500), nullable=True, comment="标签, 逗号分隔")
    scope_in = Column(Text, nullable=True, comment="测试范围(白名单域名/网段), 换行分隔")
    scope_out = Column(Text, nullable=True, comment="排除范围(黑名单), 换行分隔")
    created_at = Column(DateTime, server_default=func.now(), comment="创建时间")
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), comment="更新时间")

    # 关系
    domains = relationship("Domain", back_populates="organization", cascade="all, delete-orphan")
    tasks = relationship("Task", back_populates="organization", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}')>"
