import sys
import re
import subprocess
import signal
import os
import collections
from collections import deque
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich import box
from rich.align import Align

# --- 1. The Heavy-Duty BPF Script ---
BPF_SCRIPT = """
BEGIN { printf("--- READY ---\\n"); }

/* -- CPU & SCHEDULER -- */
/* Tracks context switches: How often a process gets CPU time. 
   High count = CPU intensive or very interactive. */
tracepoint:sched:sched_switch 
/args.next_comm != "bpftrace"/ 
{ @cpu_sched[args.next_comm] = count(); }

/* -- MEMORY -- */
/* Tracks page faults: When apps request new memory or access paged-out RAM.
   High count = Loading data, allocating RAM. */
tracepoint:exceptions:page_fault_user 
/comm != "bpftrace"/ 
{ @mem_faults[comm] = count(); }

/* -- DISK / VFS -- */
/* Tracks File I/O (Read/Write). Differentiates actual disk usage 
   from socket usage (network/IPC). */
kprobe:vfs_read, kprobe:vfs_write 
/comm != "bpftrace"/ 
{ @disk_io[comm] = count(); }

/* -- GPU DRIVER -- */
tracepoint:syscalls:sys_enter_ioctl 
/comm != "bpftrace"/ 
{ @gpu_calls[comm] = count(); }

/* -- UI RENDERING -- */
tracepoint:syscalls:sys_enter_writev 
/comm != "bpftrace"/ 
{ @ui_batches[comm] = count(); }

/* -- IPC / HANDOFFS -- */
tracepoint:syscalls:sys_enter_sendmsg 
/comm != "bpftrace"/ 
{ @ipc_handoffs[comm] = count(); }

/* -- GLOBAL VSYNC -- */
tracepoint:drm:drm_vblank_event 
{ @screen_refreshes = count(); }

interval:ms:500 {
    printf("--- START_BATCH ---\\n");
    print(@screen_refreshes);
    print(@cpu_sched);
    print(@mem_faults);
    print(@disk_io);
    print(@gpu_calls);
    print(@ui_batches);
    print(@ipc_handoffs);
    printf("--- END_BATCH ---\\n");
    
    clear(@screen_refreshes);
    clear(@cpu_sched);
    clear(@mem_faults);
    clear(@disk_io);
    clear(@gpu_calls);
    clear(@ui_batches);
    clear(@ipc_handoffs);
}
"""

# --- 2. Visualization Utilities ---

class Sparkline:
    """ASCII History Graph Generator"""
    def __init__(self, max_len=60):
        self.data = deque([0]*max_len, maxlen=max_len)
        self.chars = "  ▂▃▄▅▆▇█"
    
    def add(self, value):
        self.data.append(value)
    
    def render(self):
        if not self.data: return ""
        max_val = max(self.data) or 1
        graph = ""
        for x in self.data:
            idx = int((x / max_val) * (len(self.chars) - 1))
            graph += self.chars[idx]
        return graph

def generate_bar(value, max_value, width=8):
    if max_value == 0: return " " * width
    filled = int((value / max_value) * width)
    return "█" * filled + "░" * (width - filled)

def create_table(title, data, color="white"):
    table = Table(box=box.SIMPLE_HEAD, expand=True, title=f"[{color}]{title}[/]")
    table.add_column("Proc", style="white", ratio=4)
    table.add_column("Load", style=color, ratio=3)
    table.add_column("Cnt", justify="right", style="dim", ratio=2)

    sorted_items = sorted(data.items(), key=lambda item: item[1], reverse=True)[:8]
    
    if not sorted_items:
        table.add_row("-", "", "-")
    else:
        max_val = sorted_items[0][1]
        for proc, count in sorted_items:
            table.add_row(proc, generate_bar(count, max_val), str(count))
    return table

# --- 3. Main Dashboard Logic ---

def make_layout(data_snapshot, history):
    layout = Layout()
    
    # Header area for Global Stats + Graphs
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="upper_row", ratio=1),
        Layout(name="lower_row", ratio=1)
    )
    
    # Calculate Totals for Graphs
    total_cpu = sum(data_snapshot['cpu_sched'].values())
    total_gpu = sum(data_snapshot['gpu_calls'].values())
    
    # Update History
    history['cpu'].add(total_cpu)
    history['gpu'].add(total_gpu)

    # Header Panel
    fps = data_snapshot.get('screen_refreshes', {}).get('count', 0) * 2
    header_text = Table.grid(expand=True)
    header_text.add_column(ratio=1)
    header_text.add_column(ratio=1)
    header_text.add_column(ratio=1)
    
    # Add Sparklines to Header
    header_text.add_row(
        f"[bold cyan]CPU Activity[/]\n[cyan]{history['cpu'].render()}[/]",
        f"[bold magenta]GPU Activity[/]\n[magenta]{history['gpu'].render()}[/]",
        f"[bold green]VSync[/]: {fps} Hz\n[dim]Fedora BPF Monitor[/]"
    )
    
    layout["header"].update(Panel(header_text, style="white on black"))

    # Grid 3x2
    layout["upper_row"].split_row(
        Layout(name="u1"), Layout(name="u2"), Layout(name="u3")
    )
    layout["lower_row"].split_row(
        Layout(name="l1"), Layout(name="l2"), Layout(name="l3")
    )
    
    # Populate Panels
    # Row 1: Core System (CPU, Mem, Disk)
    layout["u1"].update(Panel(create_table("CPU Sched (Ctx Sw)", data_snapshot['cpu_sched'], "cyan")))
    layout["u2"].update(Panel(create_table("Mem Faults (Alloc)", data_snapshot['mem_faults'], "blue")))
    layout["u3"].update(Panel(create_table("Disk I/O (VFS)", data_snapshot['disk_io'], "yellow")))
    
    # Row 2: Graphics Pipeline (GPU, UI, IPC)
    layout["l1"].update(Panel(create_table("GPU Driver (IOCTL)", data_snapshot['gpu_calls'], "magenta")))
    layout["l2"].update(Panel(create_table("UI Draw (WriteV)", data_snapshot['ui_batches'], "green")))
    layout["l3"].update(Panel(create_table("IPC/Comp (SendMsg)", data_snapshot['ipc_handoffs'], "red")))
    
    return layout

def main():
    bt_filename = "/tmp/monitor_ultimate.bt"
    with open(bt_filename, "w") as f:
        f.write(BPF_SCRIPT)

    cmd = ["sudo", "bpftrace", bt_filename]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
    )

    # Data Stores
    data_keys = ['cpu_sched', 'mem_faults', 'disk_io', 'gpu_calls', 'ui_batches', 'ipc_handoffs']
    data_snapshot = {k: collections.defaultdict(int) for k in data_keys}
    data_snapshot['screen_refreshes'] = {'count': 0}
    
    # History for Sparklines
    history = {
        'cpu': Sparkline(max_len=40),
        'gpu': Sparkline(max_len=40)
    }

    re_map_entry = re.compile(r"@(\w+)\[(.*?)\]: (\d+)")
    re_single_var = re.compile(r"@(\w+): (\d+)")

    print("Booting Kernel Probes... (Ctrl+C to stop)")

    try:
        with Live(make_layout(data_snapshot, history), refresh_per_second=10, screen=True) as live:
            current_batch = {k: collections.defaultdict(int) for k in data_keys}
            current_batch['screen_refreshes'] = {'count': 0}

            for line in process.stdout:
                line = line.strip()
                
                if line == "--- START_BATCH ---":
                    # Reset batch
                    current_batch = {k: collections.defaultdict(int) for k in data_keys}
                    current_batch['screen_refreshes'] = {'count': 0}
                    
                elif line == "--- END_BATCH ---":
                    # Commit batch to snapshot
                    data_snapshot = current_batch
                    live.update(make_layout(data_snapshot, history))
                    
                else:
                    # Parsing
                    match_map = re_map_entry.search(line)
                    if match_map:
                        map_name, proc_name, count = match_map.groups()
                        current_batch[map_name][proc_name] = int(count)
                        continue
                        
                    match_single = re_single_var.search(line)
                    if match_single:
                        var_name, count = match_single.groups()
                        current_batch['screen_refreshes']['count'] = int(count)

    except KeyboardInterrupt:
        pass
    finally:
        os.kill(process.pid, signal.SIGTERM)

if __name__ == "__main__":
    main()