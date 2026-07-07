"""Sky-Eye 配置模块"""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "Sky-Eye"
    APP_VERSION: str = "0.2.0"
    DEBUG: bool = True

    # 数据库
    DATABASE_URL: str = "sqlite:///./sky_eye.db"

    # 服务端口
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    API_PREFIX: str = "/api/v1"

    # Recon 模块配置
    SUBDOMAIN_TIMEOUT: int = 30
    PORT_SCAN_TIMEOUT: int = 10
    PORT_SCAN_CONCURRENT: int = 200
    PORT_SCAN_BANNER: bool = True  # 是否抓取 Banner
    WEB_PROBE_TIMEOUT: int = 15
    WEB_PROBE_CONCURRENT: int = 50
    DIR_SCAN_CONCURRENT: int = 30

    # 漏洞扫描配置
    POC_TIMEOUT: int = 15
    POC_CONCURRENT: int = 5
    WEAK_PASSWORD_TIMEOUT: int = 10
    WEAK_PASSWORD_CONCURRENT: int = 10
    WAF_EVASION: bool = True  # 是否启用WAF规避
    ENABLE_EXPLOIT: bool = False  # Exploit 默认关闭

    # 代理配置
    HTTP_PROXY: str = ""
    SOCKS5_PROXY: str = ""

    # 第三方 API Key（用户自行配置）
    FOFA_EMAIL: str = ""
    FOFA_KEY: str = ""
    HUNTER_API_KEY: str = ""
    QUAKE_TOKEN: str = ""
    SECURITYTRAILS_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # 定时巡检
    CRON_ENABLED: bool = False
    CRON_INTERVAL_HOURS: int = 24

    # 路径
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DICT_DIR: Path = BASE_DIR / "dictionaries"
    POC_DIR: Path = BASE_DIR / "pocs"
    FINGERPRINT_DIR: Path = BASE_DIR / "fingerprints"
    REPORT_DIR: Path = BASE_DIR / "reports"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
