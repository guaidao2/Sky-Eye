"""Sky-Eye 数据库连接配置（同步 SQLite）"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

# 同步 SQLite 引擎
engine = create_engine(
    settings.DATABASE_URL.replace("+aiosqlite", ""),  # sqlite:///./sky_eye.db
    echo=settings.DEBUG,
    connect_args={"check_same_thread": False},  # FastAPI 多线程需要
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI 依赖注入：获取数据库会话（同步）"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """初始化数据库表（同步）"""
    from app.models import (  # noqa: F401
        organization,
        domain,
        ip_address,
        port,
        url,
        task,
        js_sensitive,
        fingerprint,
        vulnerability,
    )
    Base.metadata.create_all(bind=engine)
