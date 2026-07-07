"""Nuclei 模板集成工具

从 _nuclei_tmpl2 目录复制相关 POC 到 pocs/ 目录
按资产分类组织：oa/cms/framework/middleware/device
"""
import os, shutil, glob, yaml, re, json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
NUCLEI_DIR = BASE / "_nuclei_tmpl2"
POC_DIR = BASE / "pocs"

# 分类关键词映射
CATEGORY_TAGS = {
    "oa": ["seeyon", "weaver", "ecology", "tongda", "landray", "yonyou", "kingdee",
           "oa", "office", "e-office", "e-cology", "nc-cloud", "ufida"],
    "cms": ["wordpress", "dedecms", "empirecms", "phpcms", "discuz", "joomla",
            "drupal", "magento", "shopify", "opencart", "cms", "metinfo"],
    "framework": ["thinkphp", "laravel", "spring", "shiro", "struts", "fastjson",
                  "jackson", "log4j", "yii", "dubbo", "flask", "django"],
    "middleware": ["tomcat", "nginx", "jenkins", "nacos", "redis", "elasticsearch",
                   "rabbitmq", "activemq", "zookeeper", "kafka", "apache", "iis"],
    "device": ["sangfor", "fortinet", "fortigate", "huawei", "h3c", "topsec",
               "nsfocus", "paloalto", "cisco", "vpn", "firewall", "router"],
    "enterprise": ["gitlab", "jira", "confluence", "sonarqube", "nexus", "harbor",
                   "grafana", "kibana", "jenkins", "jumpserver"],
}

def classify(path: str) -> str:
    """根据路径分类"""
    p = path.lower()
    for category, tags in CATEGORY_TAGS.items():
        for tag in tags:
            if tag in p:
                return category
    return "other"

def copy_cves():
    """复制相关 CVE 模板"""
    count = 0
    for root, dirs, files in os.walk(str(NUCLEI_DIR / "http" / "cves")):
        for f in files:
            if not f.endswith(".yaml"):
                continue
            src = Path(root) / f
            cat = classify(src.name)
            if cat == "other":
                continue
            dst = POC_DIR / cat / ("cve_" + src.name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists():
                shutil.copy2(src, dst)
                count += 1
    return count

def copy_panels():
    """复制暴露面板模板"""
    count = 0
    panels_dir = NUCLEI_DIR / "http" / "exposed-panels"
    if panels_dir.exists():
        for f in panels_dir.glob("*.yaml"):
            cat = classify(f.name)
            if cat == "other":
                cat = "oa"  # panels are usually OA/admin panels
            dst = POC_DIR / cat / ("panel_" + f.name)
            if not dst.exists():
                shutil.copy2(f, dst)
                count += 1
    return count

def copy_technologies():
    """复制技术指纹到 fingerprints 目录（作为 nuclei 格式 POC）"""
    count = 0
    tech_dir = NUCLEI_DIR / "http" / "technologies"
    fp_dir = BASE / "fingerprints" / "nuclei_tech"
    if tech_dir.exists():
        fp_dir.mkdir(parents=True, exist_ok=True)
        for f in tech_dir.glob("*.yaml"):
            dst = fp_dir / f.name
            if not dst.exists():
                shutil.copy2(f, dst)
                count += 1
        # 也处理子目录
        for sub in tech_dir.iterdir():
            if sub.is_dir():
                for f in sub.glob("*.yaml"):
                    dst = fp_dir / f.name
                    if not dst.exists():
                        shutil.copy2(f, dst)
                        count += 1
    return count

def copy_default_logins():
    """复制默认登录检测模板"""
    count = 0
    dl_dir = NUCLEI_DIR / "http" / "default-logins"
    if dl_dir.exists():
        for f in dl_dir.glob("*.yaml"):
            cat = classify(f.name)
            if cat == "other":
                cat = "oa"
            dst = POC_DIR / cat / ("login_" + f.name)
            if not dst.exists():
                shutil.copy2(f, dst)
                count += 1
    return count

def copy_misconfig():
    """复制配置错误检测模板"""
    count = 0
    mc_dir = NUCLEI_DIR / "http" / "misconfiguration"
    if mc_dir.exists():
        for f in mc_dir.glob("*.yaml"):
            cat = classify(f.name)
            if cat == "other":
                continue
            dst = POC_DIR / cat / ("misconfig_" + f.name)
            if not dst.exists():
                shutil.copy2(f, dst)
                count += 1
    return count

def copy_cnvd():
    """复制 CNVD 模板"""
    count = 0
    cnvd_dir = NUCLEI_DIR / "http" / "cnvd"
    if cnvd_dir.exists():
        for f in cnvd_dir.glob("*.yaml"):
            cat = classify(f.name)
            if cat == "other":
                cat = "oa"
            dst = POC_DIR / cat / f.name
            if not dst.exists():
                shutil.copy2(f, dst)
                count += 1
    return count

if __name__ == "__main__":
    if not NUCLEI_DIR.exists():
        print(f"Nuclei templates not found at {NUCLEI_DIR}")
        print("Run: git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git _nuclei_tmpl2")
        exit(1)
    
    print("Integrating Nuclei templates...")
    
    c1 = copy_technologies()
    print(f"  Technologies: {c1}")
    
    c2 = copy_cves()
    print(f"  CVEs: {c2}")
    
    c3 = copy_panels()
    print(f"  Panels: {c3}")
    
    c4 = copy_default_logins()
    print(f"  Default logins: {c4}")
    
    c5 = copy_misconfig()
    print(f"  Misconfigurations: {c5}")
    
    c6 = copy_cnvd()
    print(f"  CNVD: {c6}")
    
    total = c1 + c2 + c3 + c4 + c5 + c6
    print(f"\nTotal integrated: {total} templates")
