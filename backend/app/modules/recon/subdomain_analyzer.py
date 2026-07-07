"""子域名智能分析器 — 渗透测试 / Bug Bounty 视角

对子域名进行自动分类评分，帮助攻击者快速定位高价值目标。
分类逻辑基于实战经验：管理后台 > 开发测试环境 > API > VPN > OSS 等
"""

import re
from typing import Dict, List, Tuple


class SubdomainAnalyzer:
    """子域名智能分类与评分"""

    # 分类规则: (正则, 分类, 优先级1-5, 说明)
    RULES = [
        # ═══ 优先级5: 管理后台/认证 ═══
        (r'^(admin|manage|manager|system|console|control)', 'admin', 5, '管理后台'),
        (r'^(sso|auth|login|oauth|passport|account|idp)', 'auth', 5, '统一认证'),
        (r'^(jenkins|gitlab|jira|confluence|wiki|nacos)', 'devops', 5, 'DevOps平台'),
        # ═══ 优先级4: 开发/测试/API ═══
        (r'^(api|openapi|graphql|rest|ws|soap|grpc)', 'api', 4, 'API接口'),
        (r'^(dev|test|uat|staging|beta|pre|preprod|qa|demo|debug)', 'dev', 4, '开发/测试环境'),
        (r'^(vpn|proxy|gateway|tunnel|relay)', 'vpn', 4, 'VPN/代理'),
        (r'^(code|git|svn|repo|registry|nexus|docker)', 'devops', 4, '代码/镜像仓库'),
        (r'^(backup|bak|old|old2|back|archive)', 'dev', 4, '备份/旧系统'),
        # ═══ 优先级3: 监控/数据库/邮件 ═══
        (r'^(grafana|kibana|prometheus|zabbix|nagios|monitor|alert|status)', 'monitor', 3, '监控系统'),
        (r'^(db|database|mysql|redis|mongo|es|elastic|solr|rabbitmq|kafka)', 'db', 3, '数据库/中间件'),
        (r'^(mail|webmail|smtp|pop3|imap|email|mx|exmail)', 'mail', 3, '邮件系统'),
        (r'^(pay|payment|order|trade|billing|wallet|account)', 'pay', 3, '支付/交易'),
        # ═══ 优先级3: 文件/上传 ═══
        (r'^(upload|download|file|files|static|assets|img|cdn|oss|cos|pan|disk)', 'files', 3, '文件/静态资源'),
        # ═══ 优先级2: OA/HR/ERP ═══
        (r'^(oa|erp|crm|hr|finance|boss|mis|workflow|bpm)', 'oa', 2, 'OA/企业系统'),
        (r'^(phone|mobile|m|app|wap|h5|wechat|wx|alipay|mini)', 'mobile', 2, '移动端'),
        (r'^(help|support|service|ticket|feedback|survey)', 'service', 2, '客服/帮助'),
        (r'^(blog|news|bbs|forum|video|live|edu|learn|school)', 'media', 2, '内容/媒体'),
        # ═══ 优先级2: 云/CDN ═══
        (r'^(cloud|yun|open|public|portal|www\d*)$', 'cloud', 2, '云/开放平台'),
        # ═══ 优先级1: CDN/默认 ═══
        (r'^(cdn\d*|static\d*|img\d*|css\d*|js\d*|ww w\d*)$', 'cdn', 1, 'CDN/静态'),
    ]

    # 特殊高价值关键词（只要子域名包含就加分）
    BOOST_KEYWORDS = [
        'admin', 'manage', 'system', 'console', 'dashboard',
        'api', 'dev', 'test', 'staging', 'uat',
        'jenkins', 'gitlab', 'nacos', 'swagger', 'actuator',
        'upload', 'backup', 'db', 'database', 'old',
        'vpn', 'proxy', 'gateway', 'sso', 'auth',
        'oa', 'erp', 'crm', 'finance',
    ]

    def analyze(self, subdomain: str) -> Dict:
        """分析单个子域名

        Returns:
            {subdomain, category, priority, label, tags}
        """
        name = subdomain.lower().strip()
        # 去除父域名，只取子域名前缀
        prefix = name.split('.')[0] if '.' in name else name

        for pattern, category, priority, label in self.RULES:
            if re.match(pattern, prefix):
                # 检查 boost 关键词
                boost = sum(1 for kw in self.BOOST_KEYWORDS if kw in name)
                final_priority = min(5, priority + boost)
                return {
                    "subdomain": subdomain,
                    "category": category,
                    "priority": final_priority,
                    "label": label,
                    "prefix": prefix,
                }

        # 默认分类
        boost = sum(1 for kw in self.BOOST_KEYWORDS if kw in name)
        return {
            "subdomain": subdomain,
            "category": "other",
            "priority": min(5, 1 + boost),
            "label": "其他",
            "prefix": prefix,
        }

    def analyze_batch(self, subdomains: List[str]) -> List[Dict]:
        """批量分析并排序（高优先级在前）"""
        results = [self.analyze(sd) for sd in subdomains]
        results.sort(key=lambda x: (-x["priority"], x["subdomain"]))
        return results

    def get_attack_surface_summary(self, results: List[Dict]) -> Dict:
        """生成攻击面摘要"""
        cats = {}
        high_value = []
        for r in results:
            cat = r["category"]
            cats[cat] = cats.get(cat, 0) + 1
            if r["priority"] >= 4:
                high_value.append(r)

        return {
            "total": len(results),
            "high_value_count": len(high_value),
            "high_value": high_value[:30],
            "by_category": cats,
            "top_targets": [
                r for r in results
                if r["priority"] >= 4 and r["category"] in ("admin", "auth", "devops", "api", "dev")
            ][:15],
        }
