"""端口扫描模块

基于 TCP Connect 的轻量端口扫描器
兼容 masscan/nmap 结果导入
"""

import asyncio
import socket
from typing import List, Set, Dict

from app.config import settings


class PortScanner:
    """端口扫描器 — TCP Connect 扫描"""

    # 常用 TOP 100 端口
    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443,
        445, 465, 500, 502, 512, 513, 514, 523, 524, 548, 554, 587, 623,
        636, 646, 808, 873, 902, 993, 995, 998, 1050, 1080, 1099, 1100,
        1102, 1158, 1352, 1433, 1434, 1521, 1723, 1776, 2049, 2100, 2121,
        2181, 2202, 2251, 2222, 2375, 2376, 2443, 2601, 2604, 3128, 3306,
        3307, 3310, 3389, 3443, 3478, 3541, 3632, 3689, 3690, 3899, 4000,
        4001, 4040, 4044, 4224, 4243, 4321, 4343, 4443, 4500, 4560, 4567,
        4643, 4848, 5000, 5001, 5003, 5005, 5006, 5007, 5008, 5009, 5432,
        5555, 5560, 5632, 5666, 5667, 5800, 5900, 5901, 5902, 5903, 5984,
        5985, 5986, 6000, 6001, 6002, 6003, 6379, 6443, 6480, 6543, 6580,
        6664, 6665, 6666, 6667, 6668, 6669, 7001, 7002, 7070, 7071, 7080,
        7081, 7171, 7396, 7443, 7547, 7676, 7777, 7778, 8000, 8001, 8002,
        8003, 8004, 8005, 8006, 8008, 8009, 8010, 8011, 8020, 8042, 8051,
        8060, 8069, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
        8088, 8089, 8090, 8091, 8092, 8093, 8096, 8098, 8099, 8100, 8118,
        8123, 8161, 8172, 8200, 8222, 8243, 8280, 8281, 8332, 8333, 8383,
        8403, 8404, 8443, 8444, 8500, 8530, 8531, 8600, 8649, 8787, 8800,
        8811, 8834, 8835, 8848, 8866, 8879, 8880, 8881, 8882, 8883, 8888,
        8889, 8890, 8899, 8983, 8998, 9000, 9001, 9002, 9003, 9004, 9005,
        9006, 9007, 9008, 9009, 9010, 9042, 9043, 9050, 9060, 9080, 9090,
        9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9101,
        9102, 9103, 9120, 9191, 9200, 9300, 9418, 9443, 9444, 9500, 9530,
        9600, 9675, 9800, 9876, 9898, 9900, 9981, 9988, 9990, 9991, 9999,
        10000, 10001, 10009, 10010, 10050, 10051, 10080, 10082, 10101,
        10250, 10255, 10443, 10566, 10666, 11000, 11111, 11211, 12000,
        12017, 12121, 12345, 12378, 12443, 14000, 14443, 15000, 15151,
        15201, 15672, 16010, 16030, 16379, 16509, 16686, 17000, 17171,
        18080, 18081, 18082, 18090, 18091, 18120, 18686, 19080, 19101,
        19283, 19300, 19350, 20000, 20001, 20080, 20101, 20828, 21025,
        21379, 21443, 22222, 23456, 24444, 25565, 25672, 26080, 26257,
        27017, 27018, 27019, 27715, 28000, 28017, 28443, 29170, 30000,
        30704, 31111, 31337, 32400, 32764, 32771, 32801, 34443, 34567,
        35500, 36666, 37444, 37777, 37778, 38443, 38888, 39001, 39500,
        40000, 40101, 41080, 41111, 41617, 41717, 42443, 43000, 44333,
        44433, 44443, 44777, 45000, 45001, 45333, 45443, 45555, 45678,
        46666, 47777, 48080, 48888, 49001, 49152, 50000, 50001, 50070,
        50075, 50090, 50091, 50101, 50222, 50443, 51111, 51443, 52001,
        52444, 53333, 54001, 54443, 55555, 55580, 56001, 56733, 56789,
        57001, 57777, 58080, 58081, 58888, 59001, 60000, 60001, 60020,
        60030, 61000, 61613, 61616, 62001, 62078, 63001, 63333, 64001,
        64443, 65001, 65002, 65500, 65501, 65535,
    ]

    def __init__(self, timeout: int = None, concurrent: int = None):
        self.timeout = timeout or settings.PORT_SCAN_TIMEOUT
        self.concurrent = concurrent or settings.PORT_SCAN_CONCURRENT

    async def scan(self, host: str, ports: List[int] = None, grab_banner: bool = True) -> List[Dict]:
        """扫描指定主机的端口列表"""
        if ports is None:
            ports = self.TOP_PORTS

        open_ports = []
        sem = asyncio.Semaphore(self.concurrent)

        async def _check(port: int) -> Dict | None:
            async with sem:
                is_open = await self._check_port(host, port)
                if not is_open:
                    return None
                service = self.detect_service(host, port)
                banner = ""
                if grab_banner:
                    banner = await self._grab_banner(host, port)
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "host": host,
                    "service": service,
                    "banner": banner,
                }

        tasks = [_check(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                open_ports.append(result)

        return open_ports

    async def _check_port(self, host: str, port: int) -> bool:
        """TCP Connect 端口检查"""
        try:
            _, _, _, _, sockaddr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex(sockaddr)
            sock.close()
            return result == 0
        except Exception:
            return False

    async def detect_service(self, host: str, port: int) -> str | None:
        """简单的服务识别（基于端口号）"""
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 81: "http", 110: "pop3", 111: "rpcbind",
            135: "msrpc", 139: "netbios-ssn", 143: "imap",
            389: "ldap", 443: "https", 445: "microsoft-ds",
            465: "smtps", 500: "ike", 502: "modbus", 512: "exec",
            513: "login", 514: "shell", 523: "ibm-db2",
            524: "ncp", 548: "afp", 554: "rtsp", 587: "submission",
            623: "ipmi", 631: "ipp", 636: "ldaps", 646: "ldp",
            873: "rsync", 902: "vmware-auth", 993: "imaps",
            995: "pop3s", 1080: "socks5", 1099: "rmi",
            1433: "mssql", 1521: "oracle", 1723: "pptp",
            2049: "nfs", 2181: "zookeeper", 2375: "docker",
            2376: "docker-tls", 3128: "squid-proxy",
            3306: "mysql", 3389: "rdp", 3632: "distcc",
            3690: "svn", 4000: "icq", 4040: "yocto-http",
            4224: "cds", 4443: "upnp", 4500: "ipsec-nat-t",
            4560: "default", 4567: "sinatra", 4848: "glassfish",
            5000: "upnp", 5001: "commplex-link", 5432: "postgresql",
            5555: "adb", 5632: "pcanywhere", 5666: "nrpe",
            5800: "vnc-http", 5900: "vnc", 5984: "couchdb",
            5985: "winrm-http", 5986: "winrm-https",
            6379: "redis", 6443: "kubernetes", 6580: "c99",
            7001: "weblogic", 7070: "realserver", 7071: "oracle-http",
            7080: "empowerid", 7171: "mongodb-v1", 7396: "kubelet",
            7443: "oracle-https", 7547: "cwmp", 7676: "imq",
            7777: "oracle-ws", 8000: "http-alt", 8080: "http-alt",
            8081: "http-alt", 8088: "http-alt", 8161: "activemq",
            8200: "http", 8243: "https", 8280: "http",
            8332: "bitcoin", 8333: "bitcoin", 8443: "https-alt",
            8444: "bitcoin", 8500: "http", 8530: "http",
            8531: "https", 8649: "ganglia", 8787: "http",
            8834: "nessus", 8848: "nacos", 8880: "cddbp",
            8888: "http", 8983: "solr", 8998: "http",
            9000: "http", 9001: "tor-orport", 9042: "cassandra",
            9043: "websphere", 9060: "websphere", 9090: "http",
            9091: "http", 9092: "kafka", 9093: "kafka",
            9094: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
            9300: "elasticsearch", 9418: "git", 9443: "https",
            9500: "http", 9600: "http", 9876: "http",
            9898: "http", 9990: "jboss", 9999: "http",
            10000: "webmin", 10050: "zabbix-agent",
            10051: "zabbix-trapper", 11000: "http",
            11211: "memcached", 12000: "http", 12345: "netbus",
            15672: "rabbitmq", 16010: "hbase", 16379: "redis",
            16509: "libvirt", 16686: "jaeger", 18080: "http",
            20000: "http", 22222: "http", 25565: "minecraft",
            25672: "rabbitmq", 27017: "mongodb", 27018: "mongodb",
            27019: "mongodb", 28017: "mongodb-http",
            30000: "http", 31337: "back-orifice", 32400: "plex",
            32764: "backdoor", 50070: "hadoop-namenode",
            50075: "hadoop-datanode", 60020: "hadoop-region",
            60030: "hadoop-region", 61616: "activemq",
        }
        return common_services.get(port)

    async def _grab_banner(self, host: str, port: int) -> str:
        """抓取端口 Banner"""
        try:
            _, _, _, _, sockaddr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(sockaddr)
            sock.settimeout(3)
            try:
                if port in [80, 8080, 8000, 443, 8443]:
                    sock.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = sock.recv(1024)
                sock.close()
                banner = data.decode("utf-8", errors="replace").strip()
                banner = banner.replace("\r\n", " | ").replace("\n", " | ")
                return banner[:500]
            except Exception:
                sock.close()
                return ""
        except Exception:
            return ""
