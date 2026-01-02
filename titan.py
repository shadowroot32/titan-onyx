import sys
import os
import sqlite3
import subprocess
import json
import requests
import yaml
import shutil
import time
import queue
import threading
import signal
import psutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.traceback import install

# --- INITIALIZATION ---
install()
console = Console()
DB_QUEUE = queue.Queue()
STOP_EVENT = threading.Event()
PAUSE_EVENT = threading.Event()
PAUSE_EVENT.set() # Default: Running

# --- LOAD CONFIG ---
CONFIG = {}
try:
    with open("config.yaml", "r") as f: CONFIG = yaml.safe_load(f)
except:
    console.print("[red]Critical: config.yaml missing![/red]")
    sys.exit(1)

# --- MODULE: RESOURCE GOVERNOR (Anti-Crash) ---
class HealthMonitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.threshold = CONFIG['system'].get('ram_threshold', 90.0)

    def run(self):
        while not STOP_EVENT.is_set():
            try:
                mem = psutil.virtual_memory().percent
                if mem > self.threshold:
                    if PAUSE_EVENT.is_set():
                        console.print(f"\n[bold red]⚠ RAM KRITIS ({mem}%). PAUSING SCAN...[/bold red]")
                        PAUSE_EVENT.clear()
                else:
                    if not PAUSE_EVENT.is_set():
                        console.print(f"\n[bold green]✔ RAM AMAN ({mem}%). RESUMING SCAN...[/bold green]")
                        PAUSE_EVENT.set()
                time.sleep(2)
            except: pass

# --- MODULE: DATABASE WAL (Write-Ahead Logging) ---
class DatabaseManager(threading.Thread):
    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self.daemon = True

    def run(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=60.0)
        conn.execute("PRAGMA journal_mode=WAL;") 
        conn.execute("PRAGMA synchronous=NORMAL;")
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS assets (url TEXT PRIMARY KEY, title TEXT, tech TEXT, status INT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulns (id INTEGER PRIMARY KEY, tool TEXT, url TEXT, severity TEXT, name TEXT, poc TEXT)''')
        conn.commit()

        while not STOP_EVENT.is_set() or not DB_QUEUE.empty():
            try:
                task = DB_QUEUE.get(timeout=1)
                cursor.execute(task[0], task[1])
                conn.commit()
                DB_QUEUE.task_done()
            except queue.Empty: continue
            except Exception as e: console.print(f"[red]DB Error: {e}[/red]")
        conn.close()

# --- MAIN ENGINE ---
class TitanOnyx:
    def __init__(self, target):
        self.target = target
        self.session = f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M')}"
        self.work_dir = os.path.join(CONFIG['system'].get('storage_path', './scans'), self.session)
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.db_path = os.path.join(self.work_dir, "titan.db")
        
        # Start Services
        self.db_mgr = DatabaseManager(self.db_path)
        self.db_mgr.start()
        
        self.monitor = HealthMonitor()
        self.monitor.start()
        
        self.self_heal_paths()

    def self_heal_paths(self):
        """Mencari tools secara otomatis jika PATH rusak"""
        paths = [os.path.expanduser("~/go/bin"), os.path.expanduser("~/.cargo/bin"), "/usr/local/go/bin", "/usr/bin"]
        for p in paths:
            if p not in os.environ["PATH"] and os.path.exists(p):
                os.environ["PATH"] += os.pathsep + p
        
        required = ["subfinder", "naabu", "httpx", "nuclei", "feroxbuster"]
        missing = [t for t in required if not shutil.which(t)]
        if missing:
            console.print(f"[bold red]CRITICAL: Tools not found: {missing}. Run install.sh![/bold red]")
            sys.exit(1)

    def run_tool(self, cmd, output_file=None):
        """Wrapper eksekusi dengan Pause/Resume Capability"""
        PAUSE_EVENT.wait() # Tunggu jika RAM penuh
        
        try:
            timeout = CONFIG['system']['timeout']
            if output_file:
                with open(output_file, "w") as f:
                    proc = subprocess.Popen(cmd, shell=True, stdout=f, stderr=subprocess.DEVNULL)
                    proc.wait(timeout=timeout)
                return True
            else:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return proc.stdout.strip()
        except: return None

    # --- PHASE 1: RECON ---
    def phase_recon(self):
        console.print(Panel(f"[bold cyan]PHASE 1: RECONNAISSANCE ({self.target})[/bold cyan]"))
        
        subs = os.path.join(self.work_dir, "subs.txt")
        ports = os.path.join(self.work_dir, "ports.txt")
        web = os.path.join(self.work_dir, "web.json")
        
        self.run_tool(f"subfinder -d {self.target} -silent", output_file=subs)
        
        if os.path.exists(subs):
            self.run_tool(f"sort -u {subs} | naabu -silent -top-ports 1000", output_file=ports)
            
        if os.path.exists(ports):
            self.run_tool(f"cat {ports} | httpx -silent -json -title -tech-detect -status-code", output_file=web)
            
        assets = []
        if os.path.exists(web):
            with open(web, 'r') as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        url = j.get("url")
                        tech = ",".join(j.get("tech", []))
                        DB_QUEUE.put(("INSERT OR IGNORE INTO assets VALUES (?,?,?,?)", (url, j.get("title"), tech, j.get("status_code"))))
                        assets.append({"url": url, "tech": tech})
                    except: pass
        
        console.print(f"[green]✔ Assets Loaded: {len(assets)}[/green]")
        return assets

    # --- PHASE 2: ATTACK ---
    def attack_target(self, asset):
        url = asset['url']
        tech = asset['tech']
        
        # Context Aware Scanning
        tags = "cve,misconfig,exposure"
        if "WordPress" in tech: tags += ",wordpress"
        if "Laravel" in tech: tags += ",laravel"
        
        tmp_file = os.path.join(self.work_dir, f"nuc_{hash(url)}.json")
        cmd = f"nuclei -u {url} -tags {tags} -s critical,high -rl 80 -j 20 -nc -silent -json"
        
        self.run_tool(cmd, output_file=tmp_file)
        
        if os.path.exists(tmp_file):
            with open(tmp_file, 'r') as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        self.log_vuln("Nuclei", url, d['info']['severity'], d['info']['name'])
                    except: pass
            os.remove(tmp_file)

    def phase_attack(self, assets):
        console.print(Panel(f"[bold red]PHASE 2: ATTACK SEQUENCE[/bold red]"))
        max_t = CONFIG['system']['max_threads']
        
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
            task = progress.add_task("[red]Attacking...", total=len(assets))
            with ThreadPoolExecutor(max_workers=max_t) as ex:
                futures = [ex.submit(self.attack_target, a) for a in assets]
                for f in futures: progress.advance(task)

    # --- PHASE 3: FUZZING ---
    def phase_fuzz(self, assets):
        console.print(Panel("[bold magenta]PHASE 3: DIRECTORY FUZZING[/bold magenta]"))
        targets = assets[:5] # Limit top 5
        wl = "wordlists/raft.txt"
        for t in targets:
            self.run_tool(f"feroxbuster -u {t['url']} -w {wl} --depth 1 --json --time-limit 5m --silent --no-state")

    def log_vuln(self, tool, url, sev, name):
        DB_QUEUE.put(("INSERT INTO vulns (tool, url, severity, name, poc) VALUES (?,?,?,?,?)", (tool, url, sev, name, "Output Saved")))
        if sev.lower() in ["critical", "high"]:
            console.print(f"[bold red]🚨 {name} ({url})[/bold red]")

    # --- REPORT ---
    def generate_report(self):
        DB_QUEUE.join()
        conn = sqlite3.connect(self.db_path)
        assets = conn.cursor().execute("SELECT * FROM assets").fetchall()
        vulns = conn.cursor().execute("SELECT * FROM vulns ORDER BY severity").fetchall()
        
        html = f"""
        <html><head><title>TITAN-ONYX: {self.target}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
        </head><body class="bg-dark text-white p-5">
        <h1>TITAN-ONYX REPORT: {self.target}</h1>
        <div class="alert alert-info">Assets: {len(assets)} | Vulns: {len(vulns)}</div>
        <table id="t1" class="table table-dark table-striped"><thead><tr><th>Sev</th><th>Tool</th><th>Name</th><th>URL</th></tr></thead>
        <tbody>
        """
        for v in vulns:
            html += f"<tr><td><span class='badge bg-danger'>{v[3]}</span></td><td>{v[1]}</td><td>{v[4]}</td><td>{v[2]}</td></tr>"
        
        html += "</tbody></table><script src='https://code.jquery.com/jquery-3.7.0.min.js'></script><script src='https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js'></script><script src='https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js'></script><script>$('#t1').DataTable();</script></body></html>"
        
        rep = os.path.join(self.work_dir, "report.html")
        with open(rep, "w") as f: f.write(html)
        console.print(f"[bold green]✅ Report: {rep}[/bold green]")
        subprocess.run(f"xdg-open {rep}", shell=True)

# --- CLEANUP ---
def cleanup_handler(signum, frame):
    console.print("\n[yellow]Stopping...[/yellow]")
    STOP_EVENT.set()
    parent = psutil.Process(os.getpid())
    for child in parent.children(recursive=True): child.kill()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_handler)
    if len(sys.argv) < 2:
        console.print("[red]Usage: python3 titan.py <target>[/red]")
        sys.exit(1)
        
    titan = TitanOnyx(sys.argv[1])
    assets = titan.phase_recon()
    if assets:
        titan.phase_attack(assets)
        titan.phase_fuzz(assets)
        titan.generate_report()