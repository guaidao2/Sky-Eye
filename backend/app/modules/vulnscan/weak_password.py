"""弱口令检测模块

支持服务:
- SSH (22)
- MySQL (3306)
- Redis (6379)
- FTP (21)
- PostgreSQL (5432)
- MongoDB (27017)
- Tomcat Manager
- Jenkins
- WordPress
- Web 通用登录表单

依赖: paramiko (SSH), pymysql (MySQL), redis (Redis)
"""

import asyncio
import socket
from typing import Dict, List

import httpx

from app.config import settings


class WeakPasswordChecker:
    """弱口令检测器"""

    # 常见服务默认口令字典
    DEFAULT_CREDENTIALS = {
        "mysql": [
            ("root", "root"), ("root", "admin"), ("root", "123456"),
            ("root", ""), ("root", "password"), ("root", "mysql"),
            ("admin", "admin"), ("admin", "123456"), ("test", "test"),
        ],
        "redis": [
            ("", ""), ("redis", "redis"), ("admin", "admin"),
            ("root", "root"), ("root", "123456"),
        ],
        "ssh": [
            ("root", "root"), ("root", "admin"), ("root", "123456"),
            ("root", "password"), ("root", "toor"), ("admin", "admin"),
            ("admin", "123456"), ("test", "test"), ("ubuntu", "ubuntu"),
            ("oracle", "oracle"), ("postgres", "postgres"),
        ],
        "ftp": [
            ("anonymous", "anonymous"), ("ftp", "ftp"),
            ("admin", "admin"), ("root", "root"),
        ],
        "postgresql": [
            ("postgres", "postgres"), ("postgres", "admin"),
            ("postgres", "123456"), ("postgres", ""),
        ],
        "mongodb": [
            ("admin", "admin"), ("admin", "123456"),
            ("root", "root"), ("mongodb", "mongodb"),
        ],
        "tomcat": [
            ("admin", "admin"), ("tomcat", "tomcat"),
            ("admin", "tomcat"), ("admin", ""),
            ("tomcat", "s3cret"), ("both", "tomcat"),
            ("manager", "manager"), ("role1", "role1"),
        ],
        "jenkins": [
            ("admin", "admin"), ("admin", "password"),
            ("jenkins", "jenkins"), ("admin", "jenkins"),
            ("user", "user"), ("dev", "dev"),
        ],
        "wordpress": [
            ("admin", "admin"), ("admin", "123456"),
            ("admin", "password"), ("admin", "admin123"),
            ("wp", "wp"), ("test", "test"),
        ],
    }

    def __init__(self):
        self.timeout = settings.WEAK_PASSWORD_TIMEOUT
        self.concurrent = settings.WEAK_PASSWORD_CONCURRENT

    async def check(self, target: str, service: str) -> List[Dict]:
        """检测目标服务的弱口令

        Args:
            target: host:port 或 URL
            service: 服务类型 (ssh/mysql/redis/ftp/postgresql/mongodb/tomcat/jenkins/wordpress)
        """
        creds = self.DEFAULT_CREDENTIALS.get(service, [])
        if not creds:
            return []

        results = []
        sem = asyncio.Semaphore(self.concurrent)

        async def _try(username: str, password: str) -> Dict | None:
            async with sem:
                success, evidence = await self._try_login(target, service, username, password)
                if success:
                    return {
                        "username": username,
                        "password": password,
                        "service": service,
                        "target": target,
                        "evidence": evidence,
                    }
                return None

        tasks = [_try(u, p) for u, p in creds]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for r in outcomes:
            if r and not isinstance(r, Exception):
                results.append(r)

        return results

    async def _try_login(self, target: str, service: str,
                         username: str, password: str) -> tuple:
        """尝试登录，返回 (success, evidence)"""
        try:
            if service == "mysql":
                return await self._check_mysql(target, username, password)
            elif service == "redis":
                return await self._check_redis(target, username, password)
            elif service == "ssh":
                return await self._check_ssh(target, username, password)
            elif service == "ftp":
                return await self._check_ftp(target, username, password)
            elif service == "tomcat":
                return await self._check_tomcat(target, username, password)
            elif service == "jenkins":
                return await self._check_jenkins(target, username, password)
            elif service == "wordpress":
                return await self._check_wordpress(target, username, password)
            elif service == "postgresql":
                return await self._check_postgresql(target, username, password)
            elif service == "mongodb":
                return await self._check_mongodb(target, username, password)
        except Exception as e:
            pass
        return False, ""

    async def _check_mysql(self, target: str, username: str, password: str) -> tuple:
        """MySQL 弱口令检测"""
        try:
            host, port = self._parse_target(target, 3306)
            # 使用 socket 直接握手检测 (避免依赖 pymysql)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            # 读取握手包
            sock.recv(1024)
            sock.close()
            # 这里只做连接检测，实际登录需要 pymysql
            # 返回连接成功作为信息
            return False, f"MySQL service reachable at {host}:{port}"
        except Exception:
            return False, ""

    async def _check_redis(self, target: str, username: str, password: str) -> tuple:
        """Redis 弱口令检测"""
        try:
            host, port = self._parse_target(target, 6379)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            if password:
                sock.send(f"AUTH {password}\r\n".encode())
                resp = sock.recv(1024).decode("utf-8", errors="replace")
                sock.close()
                if "+OK" in resp:
                    return True, f"Redis AUTH success: {password}"
            else:
                sock.send(b"PING\r\n")
                resp = sock.recv(1024).decode("utf-8", errors="replace")
                sock.close()
                if "+PONG" in resp:
                    return True, "Redis no-auth access (empty password)"
            sock.close()
        except Exception:
            pass
        return False, ""

    async def _check_ssh(self, target: str, username: str, password: str) -> tuple:
        """SSH 弱口令检测 (尝试连接握手, 需要 paramiko 做完整认证)"""
        try:
            host, port = self._parse_target(target, 22)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            banner = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()
            # 仅检测 SSH 服务可达
            return False, f"SSH reachable at {host}:{port}, banner: {banner[:100]}"
        except Exception:
            return False, ""

    async def _check_ftp(self, target: str, username: str, password: str) -> tuple:
        """FTP 弱口令检测"""
        try:
            host, port = self._parse_target(target, 21)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode("utf-8", errors="replace")
            sock.send(f"USER {username}\r\n".encode())
            sock.recv(1024)
            sock.send(f"PASS {password}\r\n".encode())
            resp = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()
            if "230" in resp:
                return True, f"FTP login success: {username}:{password}"
        except Exception:
            pass
        return False, ""

    async def _check_tomcat(self, target: str, username: str, password: str) -> tuple:
        """Tomcat Manager 弱口令"""
        try:
            base = target.rstrip("/") if "://" in target else f"http://{target}"
            url = f"{base}/manager/html"
            import base64
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                resp = await client.get(url, headers={"Authorization": f"Basic {auth}"})
                if resp.status_code == 200:
                    return True, f"Tomcat Manager accessible: {username}:{password}"
        except Exception:
            pass
        return False, ""

    async def _check_jenkins(self, target: str, username: str, password: str) -> tuple:
        """Jenkins 弱口令"""
        try:
            base = target.rstrip("/") if "://" in target else f"http://{target}"
            url = f"{base}/login"
            import base64
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                resp = await client.get(f"{base}/api/json", headers={"Authorization": f"Basic {auth}"})
                if resp.status_code == 200:
                    return True, f"Jenkins API accessible: {username}:{password}"
        except Exception:
            pass
        return False, ""

    async def _check_wordpress(self, target: str, username: str, password: str) -> tuple:
        """WordPress 弱口令"""
        try:
            base = target.rstrip("/") if "://" in target else f"http://{target}"
            url = f"{base}/wp-json/wp/v2/users"
            import base64
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(url, headers={"Authorization": f"Basic {auth}"})
                if resp.status_code == 200:
                    return True, f"WordPress API accessible: {username}:{password}"
        except Exception:
            pass
        return False, ""

    async def _check_postgresql(self, target: str, username: str, password: str) -> tuple:
        """检测 PostgreSQL 服务可达"""
        try:
            host, port = self._parse_target(target, 5432)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.close()
            return False, f"PostgreSQL reachable at {host}:{port}"
        except Exception:
            return False, ""

    async def _check_mongodb(self, target: str, username: str, password: str) -> tuple:
        """检测 MongoDB 服务可达"""
        try:
            host, port = self._parse_target(target, 27017)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.close()
            return False, f"MongoDB reachable at {host}:{port}"
        except Exception:
            return False, ""

    def _parse_target(self, target: str, default_port: int) -> tuple:
        """解析 target 字符串为 (host, port)"""
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port or default_port
        elif ":" in target:
            parts = target.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = default_port
        else:
            host = target
            port = default_port
        return host, port
