"""Sky-Eye 启动入口 — 项目根目录直接运行

用法:
    python sky-eye.py                  # 启动 Web 服务 (默认 127.0.0.1:8000)
    python sky-eye.py -p 8080          # 指定端口
    python sky-eye.py -H 0.0.0.0       # 监听所有地址
    python sky-eye.py recon baidu.com  # CLI 信息收集模式
    python sky-eye.py scan 1.2.3.4     # 快速端口扫描
"""

import sys
import os
from pathlib import Path

# 将 backend 目录加入路径并切换工作目录
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

if __name__ == "__main__":
    from cli import cli  # cli.py 在 backend/ 根目录
    cli()
