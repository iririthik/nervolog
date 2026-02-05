import asyncio
import sys
import re
import os
import json
import csv
import hashlib
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, List, Optional

# Third-party imports
try:
    import aiohttp
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from rich.text import Text
except ImportError:
    print("Missing dependencies. Run: pip install rich aiohttp")
    sys.exit(1)

# --- CONFIGURATION ---
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:latest"
DEBUG_FILE = "decision_debug.jsonl"
CSV_FILE = "test.csv"

# Thresholds to trigger an "Interrupt"
INTERRUPT_THRESHOLD_NET = 500
INTERRUPT_THRESHOLD_VIS = 60
INTERRUPT_THRESHOLD_DISK = 200

# --- SYSCALL DATABASE LOADER ---

SYSCALL_MAP = {}
SYSCALL_CATS = {}  # New: Maps ID -> Category for aggregation

FALLBACK_DB = {
    0: "read", 1: "write", 2: "open", 3: "close",
    7: "poll", 8: "lseek", 9: "mmap", 16: "ioctl",
    23: "select", 35: "nanosleep", 41: "socket",
    42: "connect", 44: "sendto", 45: "recvfrom",
    59: "execve", 202: "futex", 232: "epoll_wait",
    257: "openat", 262: "newfstatat", 318: "getrandom"
}

def load_syscalls():
    global SYSCALL_MAP, SYSCALL_CATS
    SYSCALL_MAP = FALLBACK_DB.copy()

    if os.path.exists(CSV_FILE):
        try:
            with open(CSV_FILE, mode='r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        sid = int(row.get('Number', row.get('id', -1)))
                        name = row.get('Name', row.get('name', 'unknown'))
                        cat = row.get('Category', row.get('type', 'System'))

                        # Store display name (e.g. "read(IO)")
                        display_name = f"{name}({cat})" if cat else name
                        SYSCALL_MAP[sid] = display_name

                        # Store raw category for aggregation (e.g. "IO")
                        if cat:
                            SYSCALL_CATS[sid] = cat

                    except ValueError: continue
            print(f"[INIT] Loaded custom syscalls from {CSV_FILE}")
        except Exception as e:
            print(f"[WARN] Failed to load CSV: {e}")

def get_syscall_name(sid):
    return SYSCALL_MAP.get(sid, f"sys_{sid}")

# --- BPF SCRIPT ---
BPF_SCRIPT = """
BEGIN { printf("--- NERVOUS_SYSTEM_ONLINE ---\\n"); }

/* 1. VISUAL / GPU (ioctl) */
tracepoint:syscalls:sys_enter_ioctl
/comm != "bpftrace"/
{ @vis[comm] = count(); }

/* 2. NETWORK IN (recvmsg) */
tracepoint:syscalls:sys_enter_recvmsg
/comm != "bpftrace"/
{ @net[comm] = count(); }

/* 3. DISK WRITE (write) */
tracepoint:syscalls:sys_enter_write
/comm != "bpftrace"/
{ @disk[comm] = count(); }

/* 4. RAW SYSCALLS */
tracepoint:raw_syscalls:sys_enter
/comm != "bpftrace"/
{ @calls[comm, args->id] = count(); }

interval:ms:1000 {
    printf("--- PULSE ---\\n");
    print(@vis);
    print(@net);
    print(@disk);
    print(@calls);
    clear(@vis); clear(@net); clear(@disk); clear(@calls);
}
"""

# --- CORE SYSTEMS ---

def generate_fingerprint(metrics: Dict) -> str:
    def bucket(val):
        if val < 10: return 0
        if val < 100: return 1
        if val < 500: return 2
        return 3
    shape = f"V:{bucket(metrics['vis'])}-N:{bucket(metrics['net'])}-D:{bucket(metrics['disk'])}"
    top = sorted(metrics['calls'].items(), key=lambda x: x[1], reverse=True)[:3]
    call_sig = "-".join([str(k) for k, v in top])
    return hashlib.md5(f"{shape}|{call_sig}".encode()).hexdigest()

class GlobalState:
    def __init__(self):
        self.interrupt_active = False
        self.interrupt_target = None

class PatternMatcher:
    def __init__(self):
        self.history = {}

    def is_new_pattern(self, proc_name, current_metrics):
        fp = generate_fingerprint(current_metrics)
        if self.history.get(proc_name) != fp:
            self.history[proc_name] = fp
            return True
        return False

class AuditQueue:
    def __init__(self):
        self.queue = deque(maxlen=20)
        self.processing = None

    def add_normal(self, item):
        if item['process'] not in [x['process'] for x in self.queue]:
            self.queue.append(item)

    def trigger_interrupt(self, item):
        if self.processing and self.processing['process'] == item['process']:
            return
        try:
            self.queue.remove(next(x for x in self.queue if x['process'] == item['process']))
        except StopIteration:
            pass
        self.queue.appendleft(item)

    def pop(self):
        if self.queue:
            self.processing = self.queue.popleft()
            return self.processing
        return None

    def done(self):
        self.processing = None

class LlamaJudge:
    def __init__(self):
        self.logs = deque(maxlen=10)
        # Clear debug log on start
        with open(DEBUG_FILE, "w") as f: f.write("")

    def _log_to_disk(self, entry):
        try:
            with open(DEBUG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except: pass

    async def judge(self, data):
        proc = data['process']
        m = data['metrics']

        # 1. Prepare Top Syscalls (Raw Evidence)
        top_calls = sorted(m['calls'].items(), key=lambda x: x[1], reverse=True)[:10]
        trace_str = ", ".join([f"{get_syscall_name(k)}: {v}" for k,v in top_calls])

        # 2. Prepare Rich Context (Aggregated Categories)
        cat_counts = defaultdict(int)
        for sid, count in m['calls'].items():
            cat = SYSCALL_CATS.get(sid, "Uncategorized")
            if cat and cat != "Uncategorized":
                cat_counts[cat] += count

        # Sort categories by frequency
        sorted_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        rich_summary = "\n".join([f"- {k}: {v} events" for k, v in sorted_cats])
        if not rich_summary: rich_summary = "- Generic System Activity"

        # --- THE RICH INTENT PROMPT ---
        prompt = (
            f"SYSTEM BEHAVIOR FORENSICS.\n"
            f"Subject: {proc}\n"
            f"Metrics: GPU_Cmds={m['vis']}, Net_Packets={m['net']}, Disk_Writes={m['disk']}\n\n"

            f"RAW EVIDENCE:\n"
            f"[{trace_str}]\n\n"

            f"ANALYSIS CONTEXT (Enriched Data):\n"
            f"{rich_summary}\n\n"

            "MISSION: Deduce the *intent* (the WHY) behind this activity.\n"
            "1. Use the 'Enriched Data' to see what the process is actually doing (e.g., mostly Networking vs. GPU).\n"
            "2. If the activity is vague (only 'futex' or 'read' with no specific context), set 'needs_logs': true.\n"
            "3. Keep the description short and concise (max 10 words).\n\n"

            "EXAMPLES:\n"
            "- High 'Networking' counts -> 'Streaming data or Remote Handshake'\n"
            "- High 'GPU/ioctl' counts -> 'Compositing display updates'\n"
            "- High 'Polling/epoll' counts -> 'Waiting for user input'\n\n"

            "OUTPUT JSON: {\"description\": \"<Intent>\", \"needs_logs\": <true/false>}"
        )

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1} # Lower temp for more deterministic logic
                }
                async with session.post(OLLAMA_URL, json=payload) as resp:
                    if resp.status == 200:
                        res = await resp.json()
                        decision = json.loads(res.get('response', '{}'))

                        self.logs.append({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "proc": proc,
                            "desc": decision.get("description", "Unknown"),
                            "needs_logs": decision.get("needs_logs", True)
                        })
                        self._log_to_disk({"process": proc, "prompt": prompt, "response": decision})

        except Exception as e:
            self.logs.append({"ts": "-", "proc": proc, "desc": str(e), "needs_logs": False})

# --- DASHBOARD ---

class Dashboard:
    def __init__(self, state, queue, judge):
        self.state = state
        self.queue = queue
        self.judge = judge
        self.layout = Layout()
        self.layout.split_column(Layout(name="header", size=3), Layout(name="body"))
        self.layout["body"].split_row(Layout(name="monitor"), Layout(name="audit"))

    def render(self, live_data):
        status_text = "● MONITORING ACTIVE"
        status_style = "bold green"
        if self.state.interrupt_active:
            status_text = f"⚡ INTERRUPT: {self.state.interrupt_target}"
            status_style = "bold white on red blink"

        self.layout["header"].update(Panel(Text(status_text, style=status_style, justify="center")))

        # Monitor
        table = Table(title="Live Activity", box=box.SIMPLE)
        table.add_column("Proc")
        table.add_column("V/N/D", justify="right")
        table.add_column("State")

        active = sorted(live_data.items(), key=lambda x: x[1]['vis']+x[1]['net'], reverse=True)[:10]
        for name, m in active:
            is_int = (m['vis'] > INTERRUPT_THRESHOLD_VIS or m['net'] > INTERRUPT_THRESHOLD_NET)
            state = "⚡ INT" if is_int else "Norm"
            style = "red" if is_int else "white"
            table.add_row(name, f"{m['vis']}/{m['net']}/{m['disk']}", state, style=style)

        self.layout["monitor"].update(Panel(table, border_style="blue"))

        # Audit
        a_table = Table(title="Intent Verdicts", box=box.ROUNDED)
        a_table.add_column("Proc", style="cyan")
        a_table.add_column("Deduced Intent")
        a_table.add_column("LogReq", justify="right")

        for log in reversed(self.judge.logs):
            desc = log['desc']
            if len(desc) > 35: desc = desc[:32] + ".."
            req = "[bold red]YES[/]" if log['needs_logs'] else "[dim]NO[/]"
            a_table.add_row(log['proc'], desc, req)

        self.layout["audit"].update(Panel(a_table, border_style="yellow"))
        return self.layout

# --- MAIN ---

async def main():
    if os.geteuid() != 0:
        print("Root required.")
        return

    load_syscalls()

    state = GlobalState()
    matcher = PatternMatcher()
    queue = AuditQueue()
    judge = LlamaJudge()
    dash = Dashboard(state, queue, judge)

    bt_file = f"/tmp/nervolog_{os.getpid()}.bt"
    with open(bt_file, "w") as f: f.write(BPF_SCRIPT)

    proc = await asyncio.create_subprocess_exec(
        "bpftrace", bt_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={"BPFTRACE_STRLEN": "64"}
    )

    re_map = re.compile(r"@(\w+)\[(.*?)\]:\s*(\d+)")
    re_sys = re.compile(r"@calls\[(.*?),\s*(\d+)\]:\s*(\d+)")
    batch = defaultdict(lambda: {"vis": 0, "net": 0, "disk": 0, "calls": defaultdict(int)})

    async def judge_worker():
        while True:
            # 1. Get Top Item
            item = queue.pop()
            if item:
                # 2. Check Interrupt
                is_int = (item['metrics']['vis'] > INTERRUPT_THRESHOLD_VIS or
                          item['metrics']['net'] > INTERRUPT_THRESHOLD_NET)

                if is_int:
                    state.interrupt_active = True
                    state.interrupt_target = item['process']

                await judge.judge(item)

                state.interrupt_active = False
                state.interrupt_target = None
                queue.done()
            else:
                await asyncio.sleep(0.1)

    worker_task = asyncio.create_task(judge_worker())

    with Live(dash.layout, refresh_per_second=4, screen=True) as live:
        try:
            while True:
                line = await proc.stdout.readline()
                if not line: break
                txt = line.decode('utf-8', errors='replace').strip()

                if txt == "--- PULSE ---":
                    if not state.interrupt_active:
                        top_int_proc = None
                        max_intensity = 0
                        candidates = []

                        for name, m in batch.items():
                            intensity = m['vis'] + m['net'] + m['disk']
                            candidates.append((name, m))

                            is_int_candidate = (m['vis'] > INTERRUPT_THRESHOLD_VIS or
                                                m['net'] > INTERRUPT_THRESHOLD_NET or
                                                m['disk'] > INTERRUPT_THRESHOLD_DISK)

                            if is_int_candidate and intensity > max_intensity:
                                max_intensity = intensity
                                top_int_proc = (name, m)

                        if top_int_proc:
                            name, m = top_int_proc
                            queue.trigger_interrupt({"process": name, "metrics": m})
                        else:
                            for name, m in candidates:
                                if matcher.is_new_pattern(name, m):
                                    queue.add_normal({"process": name, "metrics": m})

                    live.update(dash.render(batch))
                    batch = defaultdict(lambda: {"vis": 0, "net": 0, "disk": 0, "calls": defaultdict(int)})

                else:
                    m = re_sys.search(txt)
                    if m:
                        batch[m.group(1).replace("'", "")]["calls"][int(m.group(2))] = int(m.group(3))
                        continue
                    m = re_map.search(txt)
                    if m:
                        if m.group(1) == "calls": continue
                        batch[m.group(2).replace("'", "")][m.group(1)] = int(m.group(3))

        finally:
            if proc: proc.terminate()
            if os.path.exists(bt_file): os.remove(bt_file)
            worker_task.cancel()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
