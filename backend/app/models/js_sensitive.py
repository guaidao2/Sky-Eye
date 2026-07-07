"""Sky-Eye JS敏感信息模型"""

import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, func, Column
from sqlalchemy.orm import relationship

from app.database import Base


class JSSensitive(Base):
    __tablename__ = "js_sensitives"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id", ondelete="CASCADE"), index=True, nullable=False)
    info_type = Column(String(50), nullable=False, comment="信息类型: api_key/endpoint/ip/secret/comment")
    content = Column(Text, nullable=False, comment="发现的敏感信息")
    source_url = Column(String(2048), nullable=True, comment="来源JS文件URL")
    first_seen = Column(DateTime, server_default=func.now(), comment="首次发现")

    # 关系
    url = relationship("URL", back_populates="js_sensitives")

    def __repr__(self):
        return f"<JSSensitive(id={self.id}, type='{self.info_type}')>"
