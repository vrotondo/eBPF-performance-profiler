#!/usr/bin/env python3
"""
eBPF Performance Profiler - Web Dashboard
Flask application with real-time metrics via WebSocket
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import sys
import threading
import time

# Add parent directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from bcc import BPF, PerfType, PerfSWConfig
from collector.metrics_collector import MetricsCollector, PeriodicSnapshotter


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ebpf-profiler-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
collector = MetricsCollector(max_history=60)
snapshotter = None
bpf_program = None
profiler_thread = None
profiler_running = False


class WebProfiler:
    """eBPF Profiler integrated with web metrics collector"""
    
    def __init__(self, collector, sample_freq=99):
        self.collector = collector
        self.sample_freq = sample_freq
        self.bpf = None
        self.running = False
    
    def load_and_attach(self):
        """Load and attach eBPF programs"""
        print("[*] Loading eBPF program...")
        
        # Get path to BPF C file
        ebpf_dir = os.path.join(os.path.dirname(__file__), '..', 'ebpf')
        bpf_file = os.path.join(ebpf_dir, 'profiler.bpf.c')
        
        if not os.path.exists(bpf_file):
            raise FileNotFoundError(f"eBPF program not found: {bpf_file}")
        
        # Load BPF program
        self.bpf = BPF(src_file=bpf_file)
        print("[✓] eBPF program loaded")
        
        # Attach CPU profiler
        self.bpf.attach_perf_event(
            ev_type=PerfType.SOFTWARE,
            ev_config=PerfSWConfig.CPU_CLOCK,
            fn_name="on_cpu_sample",
            sample_period=0,
            sample_freq=self.sample_freq,
            pid=-1  # All processes
        )
        print(f"[✓] CPU profiler attached ({self.sample_freq} Hz)")
        
        # Attach I/O tracers
        try:
            self.bpf.attach_kprobe(event="__x64_sys_read", fn_name="trace_read_entry")
            self.bpf.attach_kretprobe(event="__x64_sys_read", fn_name="trace_read_return")
            self.bpf.attach_kprobe(event="__x64_sys_write", fn_name="trace_write_entry")
            self.bpf.attach_kretprobe(event="__x64_sys_write", fn_name="trace_write_return")
            print("[✓] I/O tracers attached")
        except Exception as e:
            print(f"[!] Warning: Could not attach I/O tracers: {e}")
        
        print("[✓] All eBPF programs attached successfully")
    
    def handle_cpu_sample(self, cpu, data, size):
        """Handle CPU sample events"""
        event = self.bpf["events"].event(data)
        comm = event.comm.decode('utf-8', 'replace')
        self.collector.add_cpu_sample(event.pid, comm, event.timestamp)
    
    def handle_syscall_event(self, cpu, data, size):
        """Handle syscall events"""
        event = self.bpf["syscall_events"].event(data)
        comm = event.comm.decode('utf-8', 'replace')
        self.collector.add_syscall_event(
            event.pid, 
            comm, 
            event.syscall_id, 
            event.duration_ns
        )
    
    def handle_io_event(self, cpu, data, size):
        """Handle I/O events"""
        event = self.bpf["io_events"].event(data)
        comm = event.comm.decode('utf-8', 'replace')
        self.collector.add_io_event(
            event.pid,
            comm,
            event.bytes,
            event.operation,
            event.duration_ns
        )
    
    def start_polling(self):
        """Start collecting events"""
        print("[*] Starting event collection...")
        
        # Open perf buffers
        self.bpf["events"].open_perf_buffer(self.handle_cpu_sample)
        self.bpf["syscall_events"].open_perf_buffer(self.handle_syscall_event)
        self.bpf["io_events"].open_perf_buffer(self.handle_io_event)
        
        self.running = True
        
        # Poll for events
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error during polling: {e}")
                break
    
    def stop(self):
        """Stop the profiler"""
        self.running = False
        if self.bpf:
            try:
                self.bpf.cleanup()
            except:
                pass


# ============================================================================
# Flask Routes
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    """Get profiler status"""
    return jsonify({
        "running": profiler_running,
        "uptime": collector.get_summary_stats()["uptime_seconds"] if profiler_running else 0
    })


@app.route('/api/summary')
def api_summary():
    """Get summary statistics"""
    return jsonify(collector.get_summary_stats())


@app.route('/api/cpu')
def api_cpu():
    """Get CPU usage data"""
    return jsonify({
        "processes": collector.get_top_cpu_processes(10)
    })


@app.route('/api/io')
def api_io():
    """Get I/O statistics"""
    return jsonify({
        "processes": collector.get_top_io_processes(10)
    })


@app.route('/api/syscalls')
def api_syscalls():
    """Get syscall statistics"""
    return jsonify({
        "syscalls": collector.get_top_syscalls(10)
    })


@app.route('/api/all')
def api_all():
    """Get all metrics at once"""
    return jsonify(collector.to_json())


# ============================================================================
# WebSocket Events
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('[*] Client connected')
    emit('status', {'running': profiler_running})


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('[*] Client disconnected')


@socketio.on('request_update')
def handle_request_update():
    """Client requested data update"""
    if profiler_running:
        emit('metrics_update', collector.to_json())


def broadcast_metrics():
    """Background task to broadcast metrics to all clients"""
    while True:
        time.sleep(1)  # Update every second
        if profiler_running:
            socketio.emit('metrics_update', collector.to_json())


# ============================================================================
# Profiler Control
# ============================================================================

def start_profiler():
    """Start the eBPF profiler"""
    global profiler_running, bpf_program, profiler_thread, snapshotter
    
    if profiler_running:
        return
    
    try:
        # Create profiler
        profiler = WebProfiler(collector, sample_freq=99)
        profiler.load_and_attach()
        
        bpf_program = profiler
        
        # Start snapshotter
        snapshotter = PeriodicSnapshotter(collector, interval=1.0)
        snapshotter.start()
        
        # Start profiler in background thread
        profiler_thread = threading.Thread(target=profiler.start_polling, daemon=True)
        profiler_thread.start()
        
        profiler_running = True
        print("[✓] Profiler started successfully")
        
    except Exception as e:
        print(f"[✗] Failed to start profiler: {e}")
        import traceback
        traceback.print_exc()


def stop_profiler():
    """Stop the eBPF profiler"""
    global profiler_running, bpf_program, snapshotter
    
    if not profiler_running:
        return
    
    profiler_running = False
    
    if bpf_program:
        bpf_program.stop()
    
    if snapshotter:
        snapshotter.stop()
    
    print("[✓] Profiler stopped")


# ============================================================================
# Main
# ============================================================================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="eBPF Performance Profiler - Web Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[✗] Error: This application requires root privileges")
        print("    Please run with: sudo python3 app.py")
        sys.exit(1)
    
    print("="*80)
    print("eBPF Performance Profiler - Web Dashboard")
    print("="*80)
    print(f"\n[*] Starting web server on {args.host}:{args.port}")
    print(f"[*] Dashboard URL: http://localhost:{args.port}")
    print("[*] Press Ctrl+C to stop\n")
    
    # Start profiler
    start_profiler()
    
    # Start metrics broadcaster
    broadcast_thread = threading.Thread(target=broadcast_metrics, daemon=True)
    broadcast_thread.start()
    
    try:
        # Start Flask app with SocketIO
        socketio.run(
            app,
            host=args.host,
            port=args.port,
            debug=args.debug,
            use_reloader=False  # Disable reloader to avoid double profiler start
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        stop_profiler()
        print("[✓] Shutdown complete")


if __name__ == "__main__":
    main()