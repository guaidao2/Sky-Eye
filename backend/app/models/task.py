"""Sky-Eye 任务模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, func, Column
from sqlalchemy.orm import relationship

from app.database import Base


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name = Column(String(255), nullable=False, comment="任务名称")
    task_type = Column(String(50), nullable=False, comment="任务类型: recon/fingerprint/vulnscan")
    target = Column(String(500), nullable=False, comment="目标: 域名/IP")
    status = Column(String(20), default="pending", comment="状态: pending/running/completed/failed")
    config = Column(Text, nullable=True, comment="任务配置JSON")
    progress = Column(Integer, default=0, comment="进度0-100")
    result_summary = Column(Text, nullable=True, comment="结果摘要")
    error = Column(Text, nullable=True, comment="错误信息")
    started_at = Column(DateTime, nullable=True, comment="开始时间")
    completed_at = Column(DateTime, nullable=True, comment="完成时间")
    created_at = Column(DateTime, server_default=func.now(), comment="创建时间")

    # 关系
    organization = relationship("Organization", back_populates="tasks")

    def __repr__(self):
        return f"<Task(id={self.id}, name='{self.name}', status='{self.status}')>"
