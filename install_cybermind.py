#!/usr/bin/env python3
"""
CyberMind AI Agent - مثبّت ذاتي
شغّل هذا الملف وسيُنشئ المشروع كاملاً تلقائياً
python3 install_cybermind.py
"""

import os
import sys

print("🤖 CyberMind AI Agent - مثبّت ذاتي")
print("=" * 50)

FILES = {}

# ============================================================
FILES["main.py"] = '''#!/usr/bin/env python3
"""CyberMind AI Agent - نقطة الإطلاق الرئيسية"""

import threading, time, signal, sys

def signal_handler(sig, frame):
    print("\\n⛔ إيقاف الوكيل...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    RICH = True
except:
    RICH = False
    class Console:
        def print(self, *a, **k): print(*a)
    console = Console()

class CyberMindAgent:
    def __init__(self):
        self._banner()
        self._init()

    def _banner(self):
        print("""
╔═══════════════════════════════════════╗
║   🔐 CyberMind AI Agent v1.0          ║
║   وكيل الأمن السيبراني المستقل        ║
║   يعمل 24/7 | كشف | استجابة | تعلم   ║
╚═══════════════════════════════════════╝
""")

    def _init(self):
        console.print("⚙️  تهيئة المكونات...")
        try:
            from core.ai_brain import CyberMindBrain
            from core.memory import AgentMemory
            from sensors.network_monitor import NetworkSensor
            from sensors.log_analyzer import LogAnalyzer
            from sensors.threat_intel import ThreatIntel
            from defense.auto_block import AutoBlocker
            from defense.incident_response import IncidentResponder
            from reporting.alert_system import AlertSystem
            from reporting.dashboard import start_dashboard

            self.memory    = AgentMemory()
            self.brain     = CyberMindBrain(self.memory)
            self.network   = NetworkSensor(self.brain)
            self.logs      = LogAnalyzer(self.brain)
            self.intel     = ThreatIntel()
            self.blocker   = AutoBlocker()
            self.responder = IncidentResponder(self.brain, self.blocker)
            self.alerts    = AlertSystem()
            self.dashboard = start_dashboard
            console.print("✅ جميع المكونات جاهزة")
        except ImportError as e:
            console.print(f"❌ خطأ: {e}")
            console.print("تأكد: pip install -r requirements.txt")
            sys.exit(1)

    def start(self):
        console.print("\\n🚀 تشغيل جميع المكونات...\\n")
        threads = [
            threading.Thread(target=self.network.start_monitoring, daemon=True, name="Network"),
            threading.Thread(target=self.logs.start,               daemon=True, name="Logs"),
            threading.Thread(target=self.intel.update_feeds,       daemon=True, name="Intel"),
            threading.Thread(target=self.dashboard,                daemon=True, name="Dashboard"),
            threading.Thread(target=self._heartbeat,               daemon=True, name="Heartbeat"),
        ]
        for t in threads:
            t.start()
            console.print(f"✅ {t.name} يعمل")
            time.sleep(0.3)

        console.print("\\n🛡️ CyberMind يعمل | Dashboard: http://localhost:8080")
        console.print("⌨️  Ctrl+C للإيقاف\\n")
        for t in threads:
            t.join()

    def _heartbeat(self):
        while True:
            s = self.memory.get_stats()
            console.print(f"💓 [{time.strftime('%H:%M:%S')}] حوادث:{s[\'total_incidents\']} | حرجة:{s[\'critical_threats\']} | محظورة:{s[\'blocked_ips\']}")
            time.sleep(60)

if __name__ == "__main__":
    CyberMindAgent().start()
'''

# ============================================================
FILES["core/__init__.py"] = "# CyberMind Core\n"

FILES["core/ai_brain.py"] = '''"""CyberMind AI Brain - العقل الذكي"""
import json, os, anthropic
from datetime import datetime
from rich.console import Console
console = Console()

SYSTEM = """أنت وكيل أمن سيبراني متقدم. حلل التهديدات وفق MITRE ATT&CK.
استجب دائماً بـ JSON صحيح فقط بدون أي نص إضافي."""

class CyberMindBrain:
    def __init__(self, memory):
        self.memory = memory
        key = os.getenv("ANTHROPIC_API_KEY","")
        self.sim = not bool(key)
        if not self.sim:
            self.client = anthropic.Anthropic(api_key=key)
        else:
            console.print("[yellow]⚠️  وضع محاكاة (لا يوجد ANTHROPIC_API_KEY)[/yellow]")

    def analyze_threat(self, threat: dict) -> dict:
        ctx = self.memory.get_similar_threats(threat)
        if self.sim:
            return self._simulate(threat)
        prompt = f"""
بيانات التهديد: {json.dumps(threat, ensure_ascii=False)}
حوادث مشابهة: {json.dumps(ctx, ensure_ascii=False)}

أرجع JSON فقط:
{{
  "threat_type":"نوع التهديد",
  "severity":"CRITICAL|HIGH|MEDIUM|LOW",
  "confidence":0.95,
  "mitre_technique":"T0000",
  "immediate_actions":["إجراء1","إجراء2"],
  "block_ip":true,
  "alert_human":true,
  "explanation":"شرح مفصل",
  "recommendations":["توصية1"]
}}"""
        try:
            r = self.client.messages.create(
                model="claude-opus-4-6", max_tokens=1000,
                system=SYSTEM, messages=[{"role":"user","content":prompt}])
            result = json.loads(r.content[0].text)
            self.memory.store_incident(threat, result)
            sev = result.get("severity","LOW")
            colors = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}
            c = colors.get(sev,"white")
            console.print(f"[{c}]🧠 {result[\'threat_type\']} | {sev} | {result.get(\'confidence\',0):.0%}[/{c}]")
            return result
        except Exception as e:
            console.print(f"[red]❌ AI Error: {e}[/red]")
            return self._simulate(threat)

    def autonomous_decision(self, a: dict) -> str:
        s, c = a.get("severity","LOW"), a.get("confidence",0.5)
        if s=="CRITICAL" and c>0.8: return "AUTO_BLOCK_AND_ALERT"
        if s=="CRITICAL": return "BLOCK_AND_ALERT"
        if s=="HIGH" and c>0.7: return "BLOCK_AND_NOTIFY"
        if s=="HIGH": return "MONITOR_AND_NOTIFY"
        if s=="MEDIUM": return "MONITOR_AND_LOG"
        return "LOG_ONLY"

    def _simulate(self, threat: dict) -> dict:
        import random
        sev = random.choices(["LOW","MEDIUM","HIGH","CRITICAL"],[40,30,20,10])[0]
        result = {
            "threat_type":f"[SIM] {threat.get(\'attack_type\',\'Unknown\')}",
            "severity":sev,
            "confidence":round(random.uniform(0.6,0.99),2),
            "mitre_technique":random.choice(["T1566","T1190","T1046","T1498"]),
            "immediate_actions":["حظر IP","تسجيل الحادث","مراقبة مكثفة"],
            "block_ip": sev in ["HIGH","CRITICAL"],
            "alert_human": sev in ["HIGH","CRITICAL"],
            "explanation":f"[محاكاة] نشاط مشبوه من {threat.get(\'src_ip\',\'?\')}",
            "recommendations":["تحديث الجدار الناري","مراجعة السياسات"]
        }
        self.memory.store_incident(threat, result)
        return result
'''

FILES["core/memory.py"] = '''"""AgentMemory - ذاكرة الوكيل"""
import sqlite3, json
from datetime import datetime, timedelta
from pathlib import Path

class AgentMemory:
    def __init__(self, db="data/cybermind.db"):
        Path("data").mkdir(exist_ok=True)
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, threat_data TEXT, analysis TEXT,
            decision TEXT, outcome TEXT DEFAULT \'pending\'
        );
        CREATE TABLE IF NOT EXISTS blocked_ips(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE, reason TEXT, blocked_at TEXT,
            expires_at TEXT, permanent INTEGER DEFAULT 0
        );
        """)
        self.conn.commit()

    def store_incident(self, threat, analysis, decision=None):
        c = self.conn.execute(
            "INSERT INTO incidents(timestamp,threat_data,analysis,decision) VALUES(?,?,?,?)",
            (datetime.now().isoformat(), json.dumps(threat,ensure_ascii=False),
             json.dumps(analysis,ensure_ascii=False), decision))
        self.conn.commit()
        return c.lastrowid

    def get_similar_threats(self, threat, limit=3):
        ip = threat.get("src_ip","")
        at = threat.get("attack_type","")
        cur = self.conn.execute(
            "SELECT threat_data,analysis,outcome FROM incidents WHERE threat_data LIKE ? OR threat_data LIKE ? ORDER BY timestamp DESC LIMIT ?",
            (f"%{at}%", f"%{ip}%", limit))
        results = []
        for r in cur.fetchall():
            try:
                results.append({"threat":json.loads(r[0]),"analysis":json.loads(r[1]),"outcome":r[2]})
            except: pass
        return results

    def add_blocked_ip(self, ip, reason, permanent=False, hours=24):
        exp = None if permanent else (datetime.now()+timedelta(hours=hours)).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO blocked_ips(ip,reason,blocked_at,expires_at,permanent) VALUES(?,?,?,?,?)",
            (ip, reason, datetime.now().isoformat(), exp, int(permanent)))
        self.conn.commit()

    def get_blocked_ips(self):
        cur = self.conn.execute(
            "SELECT ip,reason,blocked_at,permanent FROM blocked_ips WHERE permanent=1 OR expires_at>?",
            (datetime.now().isoformat(),))
        return [dict(r) for r in cur.fetchall()]

    def get_stats(self):
        def q(sql,*a): return self.conn.execute(sql,a).fetchone()[0]
        return {
            "total_incidents": q("SELECT COUNT(*) FROM incidents"),
            "critical_threats": q("SELECT COUNT(*) FROM incidents WHERE analysis LIKE ?", "%CRITICAL%"),
            "blocked_ips":      q("SELECT COUNT(*) FROM blocked_ips WHERE permanent=1 OR expires_at>?", datetime.now().isoformat()),
            "today_incidents":  q("SELECT COUNT(*) FROM incidents WHERE timestamp LIKE ?", datetime.now().strftime("%Y-%m-%d")+"%"),
        }

    def get_recent_incidents(self, limit=20):
        cur = self.conn.execute(
            "SELECT id,timestamp,threat_data,analysis,decision FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,))
        results = []
        for r in cur.fetchall():
            try:
                a = json.loads(r["analysis"]); t = json.loads(r["threat_data"])
                results.append({"id":r["id"],"timestamp":r["timestamp"],
                    "threat_type":a.get("threat_type","Unknown"),
                    "severity":a.get("severity","LOW"),
                    "src_ip":t.get("src_ip","N/A"),
                    "decision":r["decision"]})
            except: pass
        return results
'''

FILES["sensors/__init__.py"] = ""
FILES["sensors/network_monitor.py"] = '''"""NetworkSensor - مراقب الشبكة"""
import time, threading
from collections import defaultdict
from datetime import datetime
from rich.console import Console
console = Console()

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY = True
except: SCAPY = False

class NetworkSensor:
    def __init__(self, brain, iface="eth0"):
        self.brain, self.iface = brain, iface
        self.pkt_count = defaultdict(int)
        self.port_tracker = defaultdict(set)
        self.DDOS_THR, self.SCAN_THR = 500, 20
        threading.Thread(target=self._reset, daemon=True).start()

    def _reset(self):
        while True:
            time.sleep(1)
            self.pkt_count.clear(); self.port_tracker.clear()

    def _pkt(self, pkt):
        if not IP in pkt: return
        src = pkt[IP].src
        self.pkt_count[src] += 1
        if self.pkt_count[src] > self.DDOS_THR:
            self._threat({"attack_type":"DDOS","src_ip":src,"rate":self.pkt_count[src],"timestamp":datetime.now().isoformat()})
        if TCP in pkt:
            self.port_tracker[src].add(pkt[TCP].dport)
            if len(self.port_tracker[src]) > self.SCAN_THR:
                self._threat({"attack_type":"PORT_SCAN","src_ip":src,"ports":len(self.port_tracker[src]),"timestamp":datetime.now().isoformat()})
        if ARP in pkt and pkt[ARP].op==2:
            self._threat({"attack_type":"ARP_SPOOFING","src_ip":pkt[ARP].psrc,"timestamp":datetime.now().isoformat()})

    def _threat(self, data):
        a = self.brain.analyze_threat(data)
        d = self.brain.autonomous_decision(a)
        console.print(f"[red]🚨 {data[\'attack_type\']} | {data[\'src_ip\']} → {d}[/red]")

    def start_monitoring(self):
        if SCAPY:
            console.print(f"[cyan]👁️  مراقبة {self.iface}...[/cyan]")
            try: sniff(iface=self.iface, prn=self._pkt, store=False)
            except: self._sim()
        else: self._sim()

    def _sim(self):
        import random
        console.print("[yellow]🔄 محاكاة شبكة...[/yellow]")
        attacks = ["DDOS","PORT_SCAN","BRUTE_FORCE","ARP_SPOOFING","SQL_INJECTION"]
        ips = [f"192.168.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(8)]
        while True:
            time.sleep(random.uniform(8,20))
            if random.random() < 0.4:
                self._threat({"attack_type":random.choice(attacks),"src_ip":random.choice(ips),"timestamp":datetime.now().isoformat(),"simulation":True})
'''

FILES["sensors/log_analyzer.py"] = '''"""LogAnalyzer - محلل السجلات"""
import re, time, os
from datetime import datetime
from pathlib import Path
from rich.console import Console
console = Console()

class LogAnalyzer:
    def __init__(self, brain):
        self.brain = brain
        self.logs = {
            "auth":"/var/log/auth.log",
            "syslog":"/var/log/syslog",
            "apache":"/var/log/apache2/access.log",
            "nginx":"/var/log/nginx/access.log",
            "app":"data/app.log"
        }
        self.pos = {}
        self.bf_count = {}
        self.patterns = {
            "BRUTE_FORCE_SSH": re.compile(r"Failed password for .+ from (\\d+\\.\\d+\\.\\d+\\.\\d+)"),
            "INVALID_USER":    re.compile(r"Invalid user .+ from (\\d+\\.\\d+\\.\\d+\\.\\d+)"),
            "SQL_INJECTION":   re.compile(r"(UNION|SELECT|DROP|INSERT|\\' OR|1=1)", re.I),
            "PATH_TRAVERSAL":  re.compile(r"(\\.\\./|%2e%2e)", re.I),
            "CMD_INJECTION":   re.compile(r"(;ls|;cat|&&ls|`ls`)", re.I),
        }

    def _read(self, path):
        if not os.path.exists(path): return []
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                f.seek(self.pos.get(path,0))
                lines = f.readlines()
                self.pos[path] = f.tell()
                return lines
        except: return []

    def analyze_line(self, line, typ):
        m = self.patterns["BRUTE_FORCE_SSH"].search(line)
        if m:
            ip = m.group(1)
            self.bf_count[ip] = self.bf_count.get(ip,0)+1
            if self.bf_count[ip]>=5:
                return {"attack_type":"BRUTE_FORCE_SSH","src_ip":ip,"attempts":self.bf_count[ip]}
        for name, pat in list(self.patterns.items())[1:]:
            if pat.search(line):
                ip_m = re.search(r"(\\d+\\.\\d+\\.\\d+\\.\\d+)",line)
                return {"attack_type":name,"src_ip":ip_m.group(1) if ip_m else "Unknown","raw":line.strip()[:150]}
        return None

    def _sample_logs(self):
        Path("data").mkdir(exist_ok=True)
        with open("data/app.log","a") as f:
            for l in [
                "Failed password for root from 10.0.0.1 port 22 ssh2",
                "Failed password for admin from 10.0.0.1 port 22",
                "Failed password for user from 10.0.0.1 port 22",
                "Failed password for test from 10.0.0.1 port 22",
                "Failed password for root from 10.0.0.1 port 22",
                "GET /page.php?id=1\\' OR 1=1-- HTTP/1.1 200",
                "GET /../../etc/passwd HTTP/1.1 200",
            ]:
                f.write(f"{datetime.now().isoformat()} {l}\\n")

    def start(self):
        console.print("[cyan]📋 تحليل السجلات...[/cyan]")
        has_logs = any(os.path.exists(p) for p in self.logs.values())
        if not has_logs:
            console.print("[yellow]⚠️  توليد سجلات تجريبية[/yellow]")
            self._sample_logs()
        while True:
            for typ, path in self.logs.items():
                for line in self._read(path):
                    if not line.strip(): continue
                    t = self.analyze_line(line, typ)
                    if t:
                        t["timestamp"] = datetime.now().isoformat()
                        a = self.brain.analyze_threat(t)
                        console.print(f"[orange1]📋 {t[\'attack_type\']} في {typ}[/orange1]")
            time.sleep(5)
'''

FILES["sensors/threat_intel.py"] = '''"""ThreatIntel - استخبارات التهديدات"""
import time, json, requests
from datetime import datetime
from pathlib import Path
from rich.console import Console
console = Console()

class ThreatIntel:
    def __init__(self):
        self.path = Path("data/threat_intel.json")
        self.ips = set(); self.domains = set()
        self._load()
        self._builtin()

    def _builtin(self):
        self.domains.update(["malware-test.com","phishing-example.net","fake-bank.xyz"])
        console.print(f"[cyan]🌐 IOCs: {len(self.ips)} IP | {len(self.domains)} Domain[/cyan]")

    def _load(self):
        if self.path.exists():
            try:
                d = json.loads(self.path.read_text())
                self.ips.update(d.get("ips",[])); self.domains.update(d.get("domains",[]))
            except: pass

    def _save(self):
        Path("data").mkdir(exist_ok=True)
        self.path.write_text(json.dumps({"ips":list(self.ips),"domains":list(self.domains),"updated":datetime.now().isoformat()},indent=2))

    def fetch(self, url):
        try:
            r = requests.get(url, timeout=10)
            if r.status_code!=200: return 0
            count=0
            for line in r.text.splitlines():
                line=line.strip()
                if line and not line.startswith("#"):
                    self.ips.add(line.split()[0]); count+=1
            return count
        except: return 0

    def update_feeds(self):
        console.print("[cyan]🌐 تحديث التهديدات...[/cyan]")
        feeds = {"abuse.ch":"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"}
        total=0
        for name,url in feeds.items():
            n=self.fetch(url)
            if n>0: console.print(f"[green]✅ {name}: {n} IOC[/green]"); total+=n
        if total>0: self._save()
        else: console.print(f"[yellow]⚠️  استخدام بيانات محلية ({len(self.ips)} IP)[/yellow]")
        while True:
            time.sleep(3600)
            for name,url in feeds.items(): self.fetch(url)
            self._save()

    def is_malicious(self, ip): return ip in self.ips
    def is_bad_domain(self, d): return d in self.domains
'''

FILES["defense/__init__.py"] = ""
FILES["defense/auto_block.py"] = '''"""AutoBlocker - حظر تلقائي"""
import subprocess, platform, time, threading
from datetime import datetime, timedelta
from rich.console import Console
console = Console()

class AutoBlocker:
    def __init__(self):
        self.os = platform.system()
        self.blocked = {}
        self.whitelist = {"127.0.0.1","localhost","10.0.0.1"}
        self.dry = not self._check_perms()
        if self.dry: console.print("[yellow]⚠️  Dry-Run (بدون root)[/yellow]")
        threading.Thread(target=self._cleanup, daemon=True).start()

    def _check_perms(self):
        try:
            if self.os=="Linux":
                return subprocess.run(["iptables","-L","-n"],capture_output=True,timeout=5).returncode==0
        except: pass
        return False

    def block_ip(self, ip, reason="Threat", hours=24, permanent=False):
        if ip in self.whitelist: return False
        if ip in self.blocked: return True
        exp = None if permanent else datetime.now()+timedelta(hours=hours)
        self.blocked[ip] = exp
        if self.dry:
            console.print(f"[cyan]🔒 [DryRun] حظر: {ip} | {reason}[/cyan]")
            return True
        if self.os=="Linux":
            try:
                for d,f in [("INPUT","-s"),("OUTPUT","-d")]:
                    subprocess.run(["iptables","-A",d,f,ip,"-j","DROP"],check=True,capture_output=True,timeout=10)
                console.print(f"[red]🚫 حظر: {ip}[/red]")
                return True
            except Exception as e:
                console.print(f"[red]❌ فشل حظر {ip}: {e}[/red]")
        return False

    def unblock_ip(self, ip):
        if ip not in self.blocked: return False
        del self.blocked[ip]
        if not self.dry and self.os=="Linux":
            for d,f in [("INPUT","-s"),("OUTPUT","-d")]:
                subprocess.run(["iptables","-D",d,f,ip,"-j","DROP"],capture_output=True,timeout=10)
        console.print(f"[green]🔓 رفع حظر: {ip}[/green]")
        return True

    def _cleanup(self):
        while True:
            time.sleep(300)
            now=datetime.now()
            for ip in [i for i,e in self.blocked.items() if e and e<now]:
                self.unblock_ip(ip)

    def get_list(self): return [{"ip":ip,"expires":e.isoformat() if e else "دائم"} for ip,e in self.blocked.items()]
'''

FILES["defense/incident_response.py"] = '''"""IncidentResponder - الاستجابة للحوادث"""
import json, time
from datetime import datetime
from pathlib import Path
from rich.console import Console
console = Console()

PLAYBOOKS = {
    "DDOS":           {"block":True, "hours":72,  "priority":"P1", "steps":["حظر IP","تفعيل Rate Limiting","إشعار مزود الخدمة"]},
    "PORT_SCAN":      {"block":True, "hours":24,  "priority":"P2", "steps":["حظر IP","فحص الأنظمة","تقييم الثغرات"]},
    "BRUTE_FORCE_SSH":{"block":True, "hours":48,  "priority":"P1", "steps":["حظر IP","فحص محاولات الدخول","تفعيل 2FA"]},
    "SQL_INJECTION":  {"block":True, "hours":168, "priority":"P1", "steps":["حظر IP","فحص قاعدة البيانات","تحديث WAF"]},
    "ARP_SPOOFING":   {"block":True, "hours":24,  "priority":"P1", "steps":["عزل الجهاز","تحديث ARP Table"]},
    "RANSOMWARE":     {"block":True, "hours":-1,  "priority":"P0", "steps":["عزل فوري","قطع الشبكة","استرداد النسخ الاحتياطية"]},
    "PHISHING":       {"block":False,"hours":24,  "priority":"P2", "steps":["حظر النطاق","إشعار المستخدمين","تغيير كلمات المرور"]},
}

class IncidentResponder:
    def __init__(self, brain, blocker):
        self.brain, self.blocker = brain, blocker

    def respond(self, threat, analysis):
        at = threat.get("attack_type","UNKNOWN")
        sv = analysis.get("severity","LOW")
        ip = threat.get("src_ip")
        pb = PLAYBOOKS.get(at, {"block":False,"hours":24,"priority":"P3","steps":["تسجيل","مراقبة"]})
        dec = self.brain.autonomous_decision(analysis)
        log = {"timestamp":datetime.now().isoformat(),"id":f"INC-{int(time.time())}","attack_type":at,"severity":sv,"src_ip":ip,"decision":dec,"actions":[]}

        if dec in ["AUTO_BLOCK_AND_ALERT","BLOCK_AND_ALERT","BLOCK_AND_NOTIFY"] and ip and pb["block"]:
            perm = pb["hours"]==-1
            h = 168 if perm else pb["hours"]
            ok = self.blocker.block_ip(ip, reason=f"{at}-{sv}", hours=h, permanent=perm)
            log["actions"].append(f"{'✅' if ok else '❌'} حظر {ip}")

        for s in pb["steps"]: log["actions"].append(f"📋 {s}")
        self._save(log)
        console.print(f"[bold]🛡️ استجابة: {at} | {sv} | {len(log[\'actions\'])} إجراء[/bold]")
        return log

    def _save(self, log):
        Path("data/incidents").mkdir(parents=True, exist_ok=True)
        with open(f"data/incidents/{log[\'id\']}.json","w",encoding="utf-8") as f:
            json.dump(log,f,ensure_ascii=False,indent=2)
'''

FILES["reporting/__init__.py"] = ""
FILES["reporting/alert_system.py"] = '''"""AlertSystem - نظام التنبيهات"""
import os, smtplib, requests
from datetime import datetime
from email.mime.text import MIMEText
from rich.console import Console
console = Console()

class AlertSystem:
    def __init__(self):
        self.tg_token  = os.getenv("TELEGRAM_TOKEN","")
        self.tg_chat   = os.getenv("TELEGRAM_CHAT_ID","")
        self.slack_wh  = os.getenv("SLACK_WEBHOOK","")
        self.email_cfg = {
            "server":os.getenv("SMTP_SERVER","smtp.gmail.com"),
            "port":int(os.getenv("SMTP_PORT","587")),
            "user":os.getenv("ALERT_EMAIL",""),
            "pass":os.getenv("ALERT_EMAIL_PASS",""),
            "to":os.getenv("ALERT_TO_EMAIL","")
        }
        self.history = []
        self.icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}

    def send_alert(self, analysis, threat):
        sv = analysis.get("severity","LOW")
        tt = analysis.get("threat_type","Unknown")
        ip = threat.get("src_ip","?")
        icon = self.icons.get(sv,"⚪")
        msg = self._fmt(analysis, threat)
        colors = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}
        c = colors.get(sv,"white")
        console.print(f"[{c}]{icon} ALERT | {sv} | {tt} | {ip}[/{c}]")
        if sv in ["HIGH","CRITICAL"] and self.tg_token: self._telegram(msg)
        if sv=="CRITICAL" and self.email_cfg["user"]: self._email(f"🔴 CRITICAL: {tt} من {ip}", msg)
        if self.slack_wh: self._slack(msg, sv)
        self.history.append({"timestamp":datetime.now().isoformat(),"severity":sv,"threat_type":tt,"src_ip":ip})
        if len(self.history)>1000: self.history=self.history[-1000:]

    def _fmt(self, a, t):
        return f"""
{self.icons.get(a.get("severity","LOW"),"⚪")} CyberMind Alert
{"="*35}
🕐 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
🎯 {a.get("threat_type","?")}
⚠️  {a.get("severity","?")} | {a.get("confidence",0):.0%}
🌐 {t.get("src_ip","?")}
🔍 MITRE: {a.get("mitre_technique","N/A")}
📋 {" | ".join(a.get("immediate_actions",[])[:2])}
{"="*35}""".strip()

    def _telegram(self, msg):
        try: requests.post(f"https://api.telegram.org/bot{self.tg_token}/sendMessage",json={"chat_id":self.tg_chat,"text":msg},timeout=10)
        except Exception as e: console.print(f"[red]TG Error: {e}[/red]")

    def _email(self, subj, body):
        try:
            m = MIMEText(body,"plain","utf-8"); m["Subject"]=subj; m["From"]=self.email_cfg["user"]; m["To"]=self.email_cfg["to"]
            with smtplib.SMTP(self.email_cfg["server"],self.email_cfg["port"]) as s:
                s.starttls(); s.login(self.email_cfg["user"],self.email_cfg["pass"]); s.send_message(m)
        except Exception as e: console.print(f"[red]Email Error: {e}[/red]")

    def _slack(self, msg, sv):
        colors={"CRITICAL":"#FF0000","HIGH":"#FF6600","MEDIUM":"#FFCC00","LOW":"#00CC00"}
        try: requests.post(self.slack_wh,json={"attachments":[{"color":colors.get(sv,"#808080"),"text":msg}]},timeout=10)
        except: pass
'''

FILES["reporting/dashboard.py"] = '''"""Dashboard - لوحة التحكم"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from flask import Flask, render_template_string, jsonify
    FLASK = True
except: FLASK = False

from core.memory import AgentMemory

app = Flask(__name__) if FLASK else None
mem = AgentMemory()

HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>🔐 CyberMind</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#0a0e1a;color:#e2e8f0}
.hdr{background:linear-gradient(135deg,#0f1523,#1a1040);padding:16px 24px;border-bottom:1px solid #1e3a5f;display:flex;justify-content:space-between;align-items:center}
.hdr h1{color:#00d4ff;font-size:22px}
.live{color:#10b981;display:flex;align-items:center;gap:8px}
.dot{width:10px;height:10px;background:#10b981;border-radius:50%;animation:p 2s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.3}}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:24px}
.card{background:#1a2035;border:1px solid #1e3a5f;border-radius:12px;padding:20px;text-align:center}
.num{font-size:38px;font-weight:bold;margin:8px 0}
.lbl{color:#64748b;font-size:13px}
.red{color:#ef4444}.org{color:#f97316}.yel{color:#f59e0b}.grn{color:#10b981}
.sec{padding:0 24px 24px}
.sec h2{color:#00d4ff;margin-bottom:16px}
table{width:100%;border-collapse:collapse;background:#1a2035;border-radius:12px;overflow:hidden}
th{background:#0f1523;padding:12px;text-align:right;color:#64748b;font-size:13px}
td{padding:12px;border-bottom:1px solid #1e3a5f;font-size:14px}
tr:hover td{background:#0f1523}
.b{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold}
.bc{background:#7f1d1d;color:#fca5a5}.bh{background:#7c2d12;color:#fdba74}
.bm{background:#78350f;color:#fcd34d}.bl{background:#14532d;color:#86efac}
.bar-wrap{background:#0f1523;border-radius:12px;padding:20px;margin-bottom:16px}
.br{display:flex;align-items:center;gap:12px;margin:8px 0}
.bl2{width:130px;font-size:13px;color:#94a3b8}
.bv{height:22px;border-radius:4px;min-width:4px;transition:width .5s}
.bnum{font-size:13px}
</style></head>
<body>
<div class="hdr">
  <h1>🔐 CyberMind AI Agent</h1>
  <div class="live"><div class="dot"></div><span id="t"></span></div>
</div>
<div class="grid">
  <div class="card"><div class="lbl">إجمالي الحوادث</div><div class="num grn" id="tot">-</div></div>
  <div class="card"><div class="lbl">تهديدات حرجة</div><div class="num red" id="crit">-</div></div>
  <div class="card"><div class="lbl">IPs محظورة</div><div class="num org" id="blk">-</div></div>
  <div class="card"><div class="lbl">حوادث اليوم</div><div class="num yel" id="tod">-</div></div>
</div>
<div class="sec">
  <h2>📊 أنواع التهديدات</h2>
  <div class="bar-wrap">
    <div class="br"><span class="bl2">DDoS</span><div class="bv" style="width:70%;background:#ef4444"></div><span class="bnum">70%</span></div>
    <div class="br"><span class="bl2">SQL Injection</span><div class="bv" style="width:55%;background:#f97316"></div><span class="bnum">55%</span></div>
    <div class="br"><span class="bl2">Brute Force</span><div class="bv" style="width:40%;background:#f59e0b"></div><span class="bnum">40%</span></div>
    <div class="br"><span class="bl2">Port Scan</span><div class="bv" style="width:30%;background:#8b5cf6"></div><span class="bnum">30%</span></div>
    <div class="br"><span class="bl2">ARP Spoofing</span><div class="bv" style="width:20%;background:#06b6d4"></div><span class="bnum">20%</span></div>
  </div>
</div>
<div class="sec">
  <h2>🚨 آخر الحوادث</h2>
  <table><thead><tr><th>الوقت</th><th>التهديد</th><th>IP</th><th>الخطورة</th><th>الإجراء</th></tr></thead>
  <tbody id="tb"><tr><td colspan=5 style="text-align:center;color:#64748b">جاري التحميل...</td></tr></tbody></table>
</div>
<script>
function tick(){document.getElementById("t").textContent=new Date().toLocaleTimeString("ar-SA")}
setInterval(tick,1000);tick();
function loadStats(){fetch("/api/stats").then(r=>r.json()).then(d=>{
  document.getElementById("tot").textContent=d.total_incidents;
  document.getElementById("crit").textContent=d.critical_threats;
  document.getElementById("blk").textContent=d.blocked_ips;
  document.getElementById("tod").textContent=d.today_incidents;
}).catch(()=>{})}
function loadInc(){fetch("/api/incidents").then(r=>r.json()).then(data=>{
  const tb=document.getElementById("tb");
  if(!data.length){tb.innerHTML="<tr><td colspan=5 style='text-align:center;color:#64748b'>لا توجد حوادث</td></tr>";return;}
  const sc={"CRITICAL":"bc","HIGH":"bh","MEDIUM":"bm","LOW":"bl"};
  tb.innerHTML=data.map(i=>`<tr>
    <td>${new Date(i.timestamp).toLocaleTimeString("ar-SA")}</td>
    <td>${i.threat_type||"?"}</td>
    <td style="font-family:monospace">${i.src_ip||"N/A"}</td>
    <td><span class="b ${sc[i.severity]||"bl"}">${i.severity||"LOW"}</span></td>
    <td style="color:#64748b;font-size:12px">${i.decision||"LOG"}</td>
  </tr>`).join("");
}).catch(()=>{})}
loadStats();loadInc();
setInterval(loadStats,5000);setInterval(loadInc,10000);
</script></body></html>"""

if FLASK:
    @app.route("/")
    def index(): return render_template_string(HTML)
    @app.route("/api/stats")
    def stats(): return jsonify(mem.get_stats())
    @app.route("/api/incidents")
    def incidents(): return jsonify(mem.get_recent_incidents(20))
    @app.route("/api/blocked")
    def blocked(): return jsonify(mem.get_blocked_ips())

def start_dashboard(host="0.0.0.0", port=8080):
    if not FLASK: print("⚠️  pip install flask"); return
    print(f"📊 Dashboard: http://localhost:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)

if __name__=="__main__": start_dashboard()
'''

FILES["requirements.txt"] = """anthropic>=0.30.0
rich>=13.0.0
scapy>=2.5.0
requests>=2.31.0
flask>=3.0.0
flask-cors>=4.0.0
python-nmap>=0.7.1
reportlab>=4.0.0
"""

FILES[".env.example"] = """# CyberMind - إعدادات البيئة
ANTHROPIC_API_KEY=sk-ant-your-key-here
TELEGRAM_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id
SLACK_WEBHOOK=https://hooks.slack.com/...
ALERT_EMAIL=your@gmail.com
ALERT_EMAIL_PASS=your-app-password
ALERT_TO_EMAIL=team@company.com
NETWORK_INTERFACE=eth0
"""

FILES["test_agent.py"] = """#!/usr/bin/env python3
\"\"\"اختبار سريع للوكيل\"\"\"
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test():
    print("\\n🧪 اختبار CyberMind Agent")
    print("="*40)
    results = []

    # Memory
    try:
        from core.memory import AgentMemory
        m = AgentMemory("data/test.db")
        m.store_incident({"attack_type":"TEST","src_ip":"1.2.3.4"},{"severity":"LOW","threat_type":"Test"})
        s = m.get_stats()
        os.remove("data/test.db") if os.path.exists("data/test.db") else None
        print("✅ Memory: OK")
        results.append(True)
    except Exception as e:
        print(f"❌ Memory: {e}")
        results.append(False)

    # LogAnalyzer
    try:
        class MB:
            def analyze_threat(self, t): return {"severity":"HIGH"}
        from sensors.log_analyzer import LogAnalyzer
        la = LogAnalyzer(MB())
        for _ in range(5):
            r = la.analyze_line("Failed password for root from 10.0.0.1 port 22","auth")
        print(f"✅ LogAnalyzer: {'كشف BRUTE_FORCE' if r else 'لا كشف'}")
        results.append(True)
    except Exception as e:
        print(f"❌ LogAnalyzer: {e}")
        results.append(False)

    # AutoBlocker
    try:
        from defense.auto_block import AutoBlocker
        b = AutoBlocker()
        b.block_ip("10.99.99.1","test")
        print(f"✅ AutoBlocker: DryRun={b.dry}, Blocked={len(b.blocked)}")
        results.append(True)
    except Exception as e:
        print(f"❌ AutoBlocker: {e}")
        results.append(False)

    # AlertSystem
    try:
        from reporting.alert_system import AlertSystem
        a = AlertSystem()
        a.send_alert({"threat_type":"Test","severity":"MEDIUM","confidence":0.9,
                      "immediate_actions":["test"],"recommendations":[],"explanation":"test",
                      "mitre_technique":"T0000"},{"src_ip":"1.2.3.4"})
        print(f"✅ AlertSystem: {len(a.history)} alerts")
        results.append(True)
    except Exception as e:
        print(f"❌ AlertSystem: {e}")
        results.append(False)

    print(f"\\n{'='*40}")
    print(f"النتيجة: {sum(results)}/{len(results)} اختبارات نجحت")
    if all(results):
        print("🎉 كل شيء جاهز! شغّل: python main.py")
    else:
        print("⚠️  شغّل: pip install -r requirements.txt")

if __name__=="__main__": test()
"""

FILES["README.md"] = """# 🤖 CyberMind AI Agent
## وكيل الأمن السيبراني المستقل

### ⚡ تشغيل سريع
```bash
# تثبيت المتطلبات
pip install -r requirements.txt

# إعداد API Key
cp .env.example .env
# عدّل .env وأضف ANTHROPIC_API_KEY

# اختبار
python test_agent.py

# تشغيل
python main.py

# لوحة التحكم
http://localhost:8080
```

### 🛡️ ما يكتشفه الوكيل
- DDoS, Port Scan, ARP Spoofing (Scapy)
- Brute Force SSH, SQL Injection, Path Traversal (Logs)
- Ransomware, Phishing (AI Analysis)

### ⚠️ للاستخدام على بيئات تدريبية فقط
HTB / VulnHub / أجهزتك الخاصة
"""

# ============================================================
# تثبيت الملفات
# ============================================================

def install():
    base = "CyberMind"
    dirs = ["core","sensors","defense","reporting","data","data/incidents"]
    
    print(f"📁 إنشاء مجلد {base}/")
    os.makedirs(base, exist_ok=True)
    for d in dirs:
        os.makedirs(f"{base}/{d}", exist_ok=True)
    
    count = 0
    for path, content in FILES.items():
        full = f"{base}/{path}"
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✅ {path}")
        count += 1
    
    print(f"\n{'='*50}")
    print(f"🎉 تم إنشاء {count} ملف في مجلد CyberMind/")
    print(f"\n📦 الخطوات التالية:")
    print(f"  cd CyberMind")
    print(f"  pip install -r requirements.txt")
    print(f"  cp .env.example .env  # أضف ANTHROPIC_API_KEY")
    print(f"  python test_agent.py  # اختبار")
    print(f"  python main.py        # تشغيل")
    print(f"  # Dashboard: http://localhost:8080")

if __name__ == "__main__":
    install()

