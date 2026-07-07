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
    """初始化数据库表（同步），兼容旧表自动补列"""
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

    # 兼容旧数据库：补全新增列
    _migrate_columns()


def _migrate_columns():
    """SQLite 兼容：检测并补全新版新增的列"""
    import sqlite3
    from pathlib import Path
    try:
        db_path = Path(settings.DATABASE_URL.replace("sqlite:///", ""))
        if not db_path.is_absolute():
            db_path = settings.BASE_DIR / "backend" / db_path
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # organizations 表
        cursor.execute("PRAGMA table_info(organizations)")
        org_cols = [row[1] for row in cursor.fetchall()]
        for col_name, col_type in [("scope_in", "TEXT"), ("scope_out", "TEXT")]:
            if col_name not in org_cols:
                cursor.execute(f"ALTER TABLE organizations ADD COLUMN {col_name} {col_type}")
                print(f"  [DB] 已补全列: organizations.{col_name}")

        conn.commit()
        conn.close()
    except Exception as e:
        pass  # 静默跳过，通常是新数据库不需要迁移
