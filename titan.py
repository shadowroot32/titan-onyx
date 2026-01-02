import sys
import os
import sqlite3
import subprocess
import json
import yaml
import shutil
import time
import queue
import threading
import signal
import psutil
import re
import random
import requests
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.traceback import install

# --- INIT ---
install()
console = Console()
DB_QUEUE = queue.Queue()
STOP_EVENT = threading.Event()

# --- CONFIG ---
CONFIG = {
    "system": {"general_threads": 40, "heavy_threads": 10, "timeout": 7200, "storage_path": "./scans", "discord_webhook": ""},
    "filter": {"extensions": "png,jpg,jpeg,gif,css,js,svg,ico,woff,mp4"}
}
try:
    with open("config.yaml", "r") as f: 
        loaded = yaml.safe_load(f)
        if loaded: CONFIG.update(loaded)
except: pass

IGNORED_EXT = tuple(f".{x}" for x in CONFIG['filter']['extensions'].split(','))
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"]

# --- DATABASE ---
class DatabaseManager(threading.Thread):
    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self.daemon = True
    def run(self):
        while not STOP_EVENT.is_set():
            try:
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=60.0)
                conn.execute("PRAGMA journal_mode=WAL;") 
                cursor = conn.cursor()
                cursor.execute('''CREATE TABLE IF NOT EXISTS assets (url TEXT PRIMARY KEY, title TEXT, tech TEXT, status INT, waf TEXT, ip TEXT)''')
                cursor.execute('''CREATE TABLE IF NOT EXISTS endpoints (url TEXT, tags TEXT)''')
                cursor.execute('''CREATE TABLE IF NOT EXISTS vulns (id INTEGER PRIMARY KEY, tool TEXT, url TEXT, severity TEXT, name TEXT, poc TEXT)''')
                conn.commit()
                break
            except: time.sleep(1)
        while not STOP_EVENT.is_set() or not DB_QUEUE.empty():
            try:
                task = DB_QUEUE.get(timeout=1)
                cursor.execute(task[0], task[1])
                conn.commit()
                DB_QUEUE.task_done()
            except queue.Empty: continue
            except: pass

# --- MAIN ENGINE ---
class TitanRagnarok:
    def __init__(self, target_input):
        self.target = self.clean_target(target_input)
        self.start_time = datetime.now()
        self.session = f"scan_{self.target}_{self.start_time.strftime('%Y%m%d_%H%M')}"
        self.work_dir = os.path.join(CONFIG['system']['storage_path'], self.session)
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(os.path.join(self.work_dir, "screenshots"), exist_ok=True)
        self.db_path = os.path.join(self.work_dir, "titan.db")
        
        self.db_mgr = DatabaseManager(self.db_path)
        self.db_mgr.start()
        
        # Patterns
        self.patterns = {
            "xss": r"(q=|s=|search=|id=|query=|page=|keywords=|view=|type=|name=|callback=|jsonp=|api=|user=|username=)",
            "sqli": r"(id=|select=|report=|role=|update=|query=|user=|name=|sort=|where=|search=|params=|process=|row=|view=|table=|from=)",
            "lfi": r"(file=|document=|folder=|root=|path=|pg=|style=|pdf=|template=|php_path=|doc=|page=|name=|cat=|dir=|action=)",
            "ssrf": r"(url=|uri=|path=|dest=|redirect=|continue=|window=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=)"
        }

    def clean_target(self, raw):
        raw = raw.strip().lower()
        if "://" in raw: raw = urlparse(raw).netloc
        if raw.endswith("/"): raw = raw[:-1]
        return raw

    def run_cmd(self, cmd_list, output_file=None):
        try:
            if output_file:
                with open(output_file, "w") as f:
                    subprocess.run(cmd_list, stdout=f, stderr=subprocess.PIPE, text=True, timeout=CONFIG['system']['timeout'])
            else:
                subprocess.run(cmd_list, capture_output=True, text=True, timeout=CONFIG['system']['timeout'])
            return True
        except: return False

    # --- PHASE 0: OSINT ---
    def phase_osint(self):
        console.print(Panel(f"[bold white]PHASE 0: OSINT[/bold white]"))
        try:
            ip = subprocess.getoutput(f"dig +short {self.target} | head -n 1").strip()
            return ip if ip else "Unknown"
        except: return "Unknown"

    # --- PHASE 1: RECON ---
    def phase_recon(self, ip_addr):
        console.print(Panel(f"[bold cyan]PHASE 1: RECONNAISSANCE[/bold cyan]"))
        subs_all = os.path.join(self.work_dir, "subs_all.txt")
        subs_clean = os.path.join(self.work_dir, "subs_clean.txt")
        ports = os.path.join(self.work_dir, "ports.txt")
        web = os.path.join(self.work_dir, "web.json")
        
        self.run_cmd(["subfinder", "-d", self.target, "-silent"], output_file=os.path.join(self.work_dir, "sub.txt"))
        self.run_cmd(["assetfinder", "--subs-only", self.target], output_file=os.path.join(self.work_dir, "asset.txt"))
        os.system(f"cat {self.work_dir}/*.txt | sort -u > {subs_all}")
        if not os.path.exists(subs_all) or os.path.getsize(subs_all) == 0:
            with open(subs_all, "w") as f: f.write(self.target + "\n")

        self.run_cmd(["dnsx", "-l", subs_all, "-silent", "-resp-only"], output_file=subs_clean)
        if not os.path.exists(subs_clean) or os.path.getsize(subs_clean) == 0: shutil.copy(subs_all, subs_clean)

        self.run_cmd(["naabu", "-l", subs_clean, "-silent", "-top-ports", "1000"], output_file=ports)
        if not os.path.exists(ports) or os.path.getsize(ports) == 0:
             with open(ports, "w") as f: f.write(f"{self.target}:80\n{self.target}:443\n")

        self.run_cmd(["httpx", "-l", ports, "-silent", "-json", "-title", "-tech-detect", "-status-code"], output_file=web)
        
        assets = []
        if os.path.exists(web):
            with open(web, 'r') as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        url = j.get("url")
                        tech = ",".join(j.get("tech", []))
                        waf = "Unknown"
                        if self.target in url and len(assets) < 1:
                            p = subprocess.run(["wafw00f", url], capture_output=True, text=True)
                            if "is behind" in p.stdout: waf = "DETECTED"
                        DB_QUEUE.put(("INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?,?)", (url, j.get("title"), tech, j.get("status_code"), waf, ip_addr)))
                        assets.append({"url": url, "tech": tech})
                    except: pass
        
        if not assets: assets.append({"url": f"https://{self.target}", "tech": "Unknown"})
        console.print(f"[bold green]✔ Live Assets: {len(assets)}[/bold green]")
        return assets

    # --- PHASE 2: VISUAL ---
    def phase_visual(self, assets):
        console.print(Panel(f"[bold blue]PHASE 2: VISUAL RECON[/bold blue]"))
        urls_file = os.path.join(self.work_dir, "urls.txt")
        with open(urls_file, "w") as f:
            for a in assets: f.write(a['url'] + "\n")
        self.run_cmd(["gowitness", "file", "-f", urls_file, "-P", os.path.join(self.work_dir, "screenshots"), "--disable-db", "--threads", "5"])

    # --- PHASE 3: MINING ---
    def phase_mining(self, assets):
        console.print(Panel(f"[bold magenta]PHASE 3: DEEP MINING[/bold magenta]"))
        targets = [a['url'] for a in assets[:3]]
        targets_file = os.path.join(self.work_dir, "targets_mining.txt")
        with open(targets_file, "w") as f: f.write("\n".join(targets))
        
        self.run_cmd(["gau", self.target], output_file=os.path.join(self.work_dir, "gau.txt"))
        self.run_cmd(["katana", "-list", targets_file, "-silent", "-d", "2", "-jc"], output_file=os.path.join(self.work_dir, "katana.txt"))
        os.system(f"cat {self.work_dir}/*.txt | sort -u > {self.work_dir}/endpoints_raw.txt")
        
        categorized = {"xss": [], "sqli": [], "lfi": [], "ssrf": [], "general": []}
        if os.path.exists(os.path.join(self.work_dir, "endpoints_raw.txt")):
            with open(os.path.join(self.work_dir, "endpoints_raw.txt"), "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.endswith(IGNORED_EXT): continue
                    matched = False
                    for tag, pattern in self.patterns.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            categorized[tag].append(line)
                            DB_QUEUE.put(("INSERT INTO endpoints VALUES (?,?)", (line, tag)))
                            matched = True
                    if not matched:
                        categorized["general"].append(line)
                        DB_QUEUE.put(("INSERT INTO endpoints VALUES (?,?)", (line, "general")))
        return categorized

    # --- PHASE 4: ATTACK ---
    def attack_asset(self, url, tech):
        tags = "cve,misconfig,exposure,takeover"
        if "WordPress" in tech: tags += ",wordpress"
        self.run_nuclei(url, tags)
        if "WordPress" in tech:
            self.run_cmd(["wpscan", "--url", url, "--no-banner", "--random-user-agent"], output_file=os.path.join(self.work_dir, f"wpscan_{hash(url)}.txt"))

    def attack_pattern(self, url, tag):
        if tag == "xss":
            dalfox_out = os.path.join(self.work_dir, f"dalfox_{hash(url)}.json")
            self.run_cmd(["dalfox", "url", url, "--skip-bmining", "--silence", "--format", "json"], output_file=dalfox_out)
            if os.path.exists(dalfox_out):
                try:
                    with open(dalfox_out) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for v in data: self.log_vuln("Dalfox", url, "CRITICAL", "XSS", v.get('payload'))
                except: pass
        elif tag in ["sqli", "lfi", "ssrf"]:
             self.run_nuclei(url, tag)

    def run_nuclei(self, url, tags):
        out = os.path.join(self.work_dir, f"nuc_{hash(url)}.json")
        self.run_cmd(["nuclei", "-u", url, "-tags", tags, "-s", "critical,high", "-rl", "50", "-nc", "-silent", "-json"], output_file=out)
        self.parse_nuclei(out, url)

    def parse_nuclei(self, file, url):
        if os.path.exists(file):
            with open(file, 'r') as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        self.log_vuln("Nuclei", url, d['info']['severity'], d['info']['name'])
                    except: pass
            os.remove(file)

    def phase_attack(self, assets, categorized_eps):
        console.print(Panel(f"[bold red]PHASE 4: ATTACK[/bold red]"))
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
            t1 = progress.add_task("[red]Scanning Assets...", total=len(assets))
            with ThreadPoolExecutor(max_workers=CONFIG['system']['heavy_threads']) as ex:
                futures = [ex.submit(self.attack_asset, a['url'], a['tech']) for a in assets]
                for f in futures: progress.advance(t1)
            for tag in ["xss", "sqli", "lfi", "ssrf"]:
                targets = categorized_eps[tag][:20]
                if targets:
                    t2 = progress.add_task(f"[yellow]Scanning {tag.upper()}...", total=len(targets))
                    with ThreadPoolExecutor(max_workers=5) as ex:
                        futures = [ex.submit(self.attack_pattern, u, tag) for u in targets]
                        for f in futures: progress.advance(t2)

    def log_vuln(self, tool, url, sev, name, poc="See Output"):
        DB_QUEUE.put(("INSERT INTO vulns (tool, url, severity, name, poc) VALUES (?,?,?,?,?)", (tool, url, sev, name, poc)))
        console.print(f"[bold red]🚨 [{tool}] {name} ({url})[/bold red]")

    # --- REPORT GENERATOR (RENGINE DASHBOARD STYLE) ---
    def generate_report(self):
        DB_QUEUE.join()
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            assets = conn.cursor().execute("SELECT * FROM assets").fetchall()
            vulns = conn.cursor().execute("SELECT * FROM vulns ORDER BY severity").fetchall()
            eps = conn.cursor().execute("SELECT * FROM endpoints LIMIT 1000").fetchall()
        except: assets, vulns, eps = [], [], []

        # Calculate Stats for Charts
        crit_count = len([v for v in vulns if v['severity'].lower() == 'critical'])
        high_count = len([v for v in vulns if v['severity'].lower() == 'high'])
        med_count = len([v for v in vulns if v['severity'].lower() == 'medium'])
        low_count = len([v for v in vulns if v['severity'].lower() == 'low'])
        info_count = len([v for v in vulns if v['severity'].lower() in ['info', 'unknown']])

        # HTML BUILDER (Bootstrap 5 + ChartJS + DataTables)
        html = f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Titan-Ragnarok: {self.target}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{ --primary-color: #5e72e4; --bg-dark: #121212; --card-bg: #1e1e2f; }}
        body {{ background-color: var(--bg-dark); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .navbar {{ background-color: var(--card-bg); border-bottom: 1px solid #2d2d3f; }}
        .card {{ background-color: var(--card-bg); border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.3); margin-bottom: 20px; }}
        .stat-card h3 {{ font-weight: 700; }}
        .badge-critical {{ background-color: #ff355e; }}
        .badge-high {{ background-color: #fd7e14; }}
        .badge-medium {{ background-color: #ffc107; color: #000; }}
        .badge-low {{ background-color: #20c997; }}
        .badge-info {{ background-color: #11cdef; }}
        .nav-tabs .nav-link {{ color: #ccc; }}
        .nav-tabs .nav-link.active {{ background-color: var(--card-bg); color: #fff; border-color: #2d2d3f; border-bottom-color: transparent; }}
        pre {{ background: #2d2d3f; padding: 10px; border-radius: 5px; color: #f8f9fa; }}
        .screenshot-box {{ position: relative; overflow: hidden; height: 200px; border-radius: 8px; border: 1px solid #333; }}
        .screenshot-box img {{ width: 100%; height: 100%; object-fit: cover; transition: transform 0.3s; }}
        .screenshot-box:hover img {{ transform: scale(1.1); }}
        .screenshot-overlay {{ position: absolute; bottom: 0; left: 0; right: 0; background: rgba(0,0,0,0.8); padding: 5px; text-align: center; }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark p-3">
        <div class="container-fluid">
            <a class="navbar-brand" href="#"><i class="fas fa-dragon text-danger"></i> TITAN-RAGNAROK</a>
            <span class="navbar-text ms-auto">Target: <strong>{self.target}</strong> | Scan Date: {self.start_time.strftime('%Y-%m-%d')}</span>
        </div>
    </nav>

    <div class="container-fluid p-4">
        <div class="row">
            <div class="col-md-3">
                <div class="card stat-card p-3 text-center border-start border-4 border-primary">
                    <h6 class="text-muted">TOTAL ASSETS</h6>
                    <h3 class="text-white">{len(assets)}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3 text-center border-start border-4 border-danger">
                    <h6 class="text-muted">VULNERABILITIES</h6>
                    <h3 class="text-white">{len(vulns)}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3 text-center border-start border-4 border-info">
                    <h6 class="text-muted">ENDPOINTS</h6>
                    <h3 class="text-white">{len(eps)}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3 text-center border-start border-4 border-success">
                    <h6 class="text-muted">PORTS OPEN</h6>
                    <h3 class="text-white">--</h3>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-4">
                <div class="card p-3">
                    <h5 class="card-title">Severity Distribution</h5>
                    <canvas id="vulnChart"></canvas>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card p-3">
                    <ul class="nav nav-tabs" id="myTab" role="tablist">
                        <li class="nav-item"><button class="nav-link active" id="vuln-tab" data-bs-toggle="tab" data-bs-target="#vuln" type="button">Vulnerabilities</button></li>
                        <li class="nav-item"><button class="nav-link" id="assets-tab" data-bs-toggle="tab" data-bs-target="#assets" type="button">Assets</button></li>
                        <li class="nav-item"><button class="nav-link" id="screens-tab" data-bs-toggle="tab" data-bs-target="#screens" type="button">Screenshots</button></li>
                    </ul>
                    <div class="tab-content p-3" id="myTabContent">
                        
                        <div class="tab-pane fade show active" id="vuln" role="tabpanel">
                            <table id="vulnTable" class="table table-hover table-dark w-100">
                                <thead><tr><th>Severity</th><th>Name</th><th>Tool</th><th>URL</th><th>Action</th></tr></thead>
                                <tbody>"""
        
        for v in vulns:
            sev_class = f"badge-{v['severity'].lower()}"
            # Escape HTML for modal
            poc_safe = str(v['poc']).replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
            html += f"""
                                    <tr>
                                        <td><span class="badge {sev_class}">{v['severity']}</span></td>
                                        <td>{v['name']}</td>
                                        <td>{v['tool']}</td>
                                        <td class="text-truncate" style="max-width: 300px;"><a href="{v['url']}" target="_blank" class="text-decoration-none text-light">{v['url']}</a></td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-info" data-bs-toggle="modal" data-bs-target="#modal-{v['id']}">
                                                <i class="fas fa-eye"></i> View
                                            </button>
                                            <div class="modal fade" id="modal-{v['id']}" tabindex="-1">
                                                <div class="modal-dialog modal-lg">
                                                    <div class="modal-content bg-dark">
                                                        <div class="modal-header border-secondary">
                                                            <h5 class="modal-title">{v['name']}</h5>
                                                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                                        </div>
                                                        <div class="modal-body">
                                                            <h6>URL:</h6> <a href="{v['url']}" target="_blank">{v['url']}</a><br><br>
                                                            <h6>Tool:</h6> {v['tool']}<br><br>
                                                            <h6>Proof of Concept / Output:</h6>
                                                            <pre>{poc_safe}</pre>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                    </tr>"""
        
        html += """                 </tbody>
                            </table>
                        </div>

                        <div class="tab-pane fade" id="assets" role="tabpanel">
                             <table id="assetTable" class="table table-hover table-dark w-100">
                                <thead><tr><th>URL</th><th>Title</th><th>Tech</th><th>Status</th><th>WAF</th></tr></thead>
                                <tbody>"""
        
        for a in assets:
            html += f"""<tr>
                <td><a href="{a['url']}" target="_blank" class="text-info">{a['url']}</a></td>
                <td>{a['title']}</td>
                <td><small>{a['tech'][:50]}</small></td>
                <td><span class="badge bg-secondary">{a['status']}</span></td>
                <td>{a['waf']}</td>
            </tr>"""

        html += """             </tbody>
                            </table>
                        </div>

                        <div class="tab-pane fade" id="screens" role="tabpanel">
                            <div class="row">"""
        
        img_dir = os.path.join(self.work_dir, "screenshots")
        if os.path.exists(img_dir):
            for f in os.listdir(img_dir):
                if f.endswith(".png"):
                    html += f"""
                    <div class="col-md-3 mb-4">
                        <div class="screenshot-box">
                            <a href="screenshots/{f}" target="_blank">
                                <img src="screenshots/{f}" loading="lazy">
                                <div class="screenshot-overlay"><small class="text-white">{f.replace('http-', '').replace('.png', '')}</small></div>
                            </a>
                        </div>
                    </div>"""
        
        html += """         </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        $(document).ready(function() {
            $('#vulnTable').DataTable({ "order": [[ 0, "desc" ]] });
            $('#assetTable').DataTable();

            // Chart JS
            const ctx = document.getElementById('vulnChart');
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [""" + f"{crit_count}, {high_count}, {med_count}, {low_count}, {info_count}" + """],
                        backgroundColor: ['#ff355e', '#fd7e14', '#ffc107', '#20c997', '#11cdef'],
                        borderWidth: 0
                    }]
                },
                options: { 
                    responsive: true,
                    plugins: { legend: { position: 'bottom', labels: { color: 'white' } } } 
                }
            });
        });
    </script>
</body>
</html>"""
        
        rep = os.path.join(self.work_dir, "report.html")
        with open(rep, "w") as f: f.write(html)
        
        # JSON EXPORT
        json_data = {"target": self.target, "stats": {"vulns": len(vulns), "assets": len(assets)}, "assets": [dict(ix) for ix in assets], "vulns": [dict(ix) for ix in vulns]}
        with open(os.path.join(self.work_dir, "titan_export.json"), "w") as f: json.dump(json_data, f, indent=4)
        
        console.print(f"[bold green]✅ Dashboard Generated: {rep}[/bold green]")
        subprocess.run(["xdg-open", rep])

def cleanup_handler(signum, frame):
    console.print("\n[yellow]Stopping...[/yellow]")
    STOP_EVENT.set()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_handler)
    if len(sys.argv) < 2:
        console.print("[red]Usage: python3 titan.py <target>[/red]")
        sys.exit(1)
    titan = TitanRagnarok(sys.argv[1])
    ip = titan.phase_osint()
    assets = titan.phase_recon(ip)
    titan.phase_visual(assets)
    eps = titan.phase_mining(assets)
    titan.phase_attack(assets, eps)
    titan.generate_report()