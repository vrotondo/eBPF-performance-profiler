#!/usr/bin/env python3
"""
eBPF Performance Profiler - Loader
Loads the eBPF program and collects performance data
"""

from bcc import BPF, PerfType, PerfSWConfig
import time
import os
import signal
import sys
from collections import defaultdict
from datetime import datetime


class EBPFProfiler:
    """Main profiler class that loads eBPF programs and collects metrics"""
    
    def __init__(self, target_pid=None, sample_freq=99):
        """
        Initialize the profiler
        
        Args:
            target_pid: If set, only profile this PID. If None, profile all processes
            sample_freq: CPU sampling frequency in Hz (default 99 Hz)
        """
        self.target_pid = target_pid
        self.sample_freq = sample_freq
        self.bpf = None
        self.running = False
        
        # Statistics storage
        self.cpu_samples = defaultdict(int)
        self.syscall_stats = defaultdict(lambda: {"count": 0, "total_duration": 0})
        self.io_stats = defaultdict(lambda: {"read_bytes": 0, "write_bytes": 0, "read_ops": 0, "write_ops": 0})
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\n[*] Shutting down profiler...")
        self.running = False
        
        # Print results BEFORE cleanup (to avoid segfault hiding results)
        self.print_results()
        
        try:
            self.cleanup()
        except:
            pass  # Ignore cleanup errors (common in WSL2)
        
        sys.exit(0)
    
    def load(self):
        """Load the eBPF program"""
        print("[*] Loading eBPF program...")
        
        # Get the path to the BPF C file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        bpf_file = os.path.join(current_dir, "profiler.bpf.c")
        
        # Check if file exists
        if not os.path.exists(bpf_file):
            raise FileNotFoundError(f"eBPF program not found: {bpf_file}")
        
        # Load and compile the BPF program
        try:
            self.bpf = BPF(src_file=bpf_file)
            print("[✓] eBPF program loaded successfully")
        except Exception as e:
            print(f"[✗] Failed to load eBPF program: {e}")
            raise
    
    def attach(self):
        """Attach eBPF programs to appropriate hooks"""
        print("[*] Attaching eBPF programs to kernel hooks...")
        
        try:
            # Attach CPU profiler to perf events (samples CPU usage)
            # This will call on_cpu_sample() function in the BPF program
            self.bpf.attach_perf_event(
                ev_type=PerfType.SOFTWARE,
                ev_config=PerfSWConfig.CPU_CLOCK,
                fn_name="on_cpu_sample",
                sample_period=0,
                sample_freq=self.sample_freq,
                pid=self.target_pid if self.target_pid else -1
            )
            print(f"[✓] CPU profiler attached (sampling at {self.sample_freq} Hz)")
            
            # Attach I/O tracers to read/write syscalls
            # These will track when processes read or write data
            self.bpf.attach_kprobe(event="__x64_sys_read", fn_name="trace_read_entry")
            self.bpf.attach_kretprobe(event="__x64_sys_read", fn_name="trace_read_return")
            self.bpf.attach_kprobe(event="__x64_sys_write", fn_name="trace_write_entry")
            self.bpf.attach_kretprobe(event="__x64_sys_write", fn_name="trace_write_return")
            print("[✓] I/O tracers attached")
            
            # Syscall tracers are attached via TRACEPOINT in the BPF code
            print("[✓] Syscall tracers attached")
            
        except Exception as e:
            print(f"[✗] Failed to attach eBPF programs: {e}")
            raise
    
    def _handle_cpu_sample(self, cpu, data, size):
        """Callback for CPU sample events"""
        event = self.bpf["events"].event(data)
        
        # Store sample data
        key = (event.pid, event.comm.decode('utf-8', 'replace'))
        self.cpu_samples[key] += 1
    
    def _handle_syscall_event(self, cpu, data, size):
        """Callback for syscall events"""
        event = self.bpf["syscall_events"].event(data)
        
        key = (event.pid, event.comm.decode('utf-8', 'replace'), event.syscall_id)
        self.syscall_stats[key]["count"] += 1
        self.syscall_stats[key]["total_duration"] += event.duration_ns
    
    def _handle_io_event(self, cpu, data, size):
        """Callback for I/O events"""
        event = self.bpf["io_events"].event(data)
        
        key = (event.pid, event.comm.decode('utf-8', 'replace'))
        
        if event.operation == 0:  # read
            self.io_stats[key]["read_bytes"] += event.bytes
            self.io_stats[key]["read_ops"] += 1
        else:  # write
            self.io_stats[key]["write_bytes"] += event.bytes
            self.io_stats[key]["write_ops"] += 1
    
    def start_polling(self):
        """Start collecting events from eBPF"""
        print("[*] Starting event collection...")
        print("[*] Press Ctrl+C to stop and see results\n")
        
        # Open perf buffers for each event type
        self.bpf["events"].open_perf_buffer(self._handle_cpu_sample)
        self.bpf["syscall_events"].open_perf_buffer(self._handle_syscall_event)
        self.bpf["io_events"].open_perf_buffer(self._handle_io_event)
        
        self.running = True
        start_time = time.time()
        
        try:
            # Main event loop - poll for events
            while self.running:
                self.bpf.perf_buffer_poll(timeout=100)
                
                # Print periodic updates every 5 seconds
                if int(time.time() - start_time) % 5 == 0:
                    elapsed = int(time.time() - start_time)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Collecting data... ({elapsed}s elapsed, {len(self.cpu_samples)} processes sampled)")
                    time.sleep(1)  # Avoid printing multiple times per second
                    
        except KeyboardInterrupt:
            pass
        
        print("\n[*] Event collection stopped")
    
    def print_results(self):
        """Print collected statistics"""
        print("\n" + "="*80)
        print("PERFORMANCE PROFILING RESULTS")
        print("="*80)
        
        # CPU Statistics
        print("\n📊 CPU USAGE (by sample count)")
        print("-" * 80)
        if self.cpu_samples:
            sorted_cpu = sorted(self.cpu_samples.items(), key=lambda x: x[1], reverse=True)
            print(f"{'PID':<8} {'PROCESS':<20} {'SAMPLES':<10} {'ESTIMATED CPU %':<15}")
            print("-" * 80)
            
            total_samples = sum(self.cpu_samples.values())
            for (pid, comm), samples in sorted_cpu[:20]:  # Top 20 processes
                cpu_percent = (samples / total_samples * 100) if total_samples > 0 else 0
                print(f"{pid:<8} {comm:<20} {samples:<10} {cpu_percent:.2f}%")
        else:
            print("No CPU samples collected")
        
        # I/O Statistics
        print("\n💾 I/O OPERATIONS")
        print("-" * 80)
        if self.io_stats:
            sorted_io = sorted(self.io_stats.items(), 
                             key=lambda x: x[1]["read_bytes"] + x[1]["write_bytes"], 
                             reverse=True)
            print(f"{'PID':<8} {'PROCESS':<20} {'READ (MB)':<12} {'WRITE (MB)':<12} {'OPS':<10}")
            print("-" * 80)
            
            for (pid, comm), stats in sorted_io[:20]:  # Top 20 processes
                read_mb = stats["read_bytes"] / (1024 * 1024)
                write_mb = stats["write_bytes"] / (1024 * 1024)
                total_ops = stats["read_ops"] + stats["write_ops"]
                print(f"{pid:<8} {comm:<20} {read_mb:<12.2f} {write_mb:<12.2f} {total_ops:<10}")
        else:
            print("No I/O operations tracked")
        
        # Syscall Statistics
        print("\n🔧 TOP SYSCALLS (by frequency)")
        print("-" * 80)
        if self.syscall_stats:
            sorted_syscalls = sorted(self.syscall_stats.items(), 
                                   key=lambda x: x[1]["count"], 
                                   reverse=True)
            print(f"{'PID':<8} {'PROCESS':<20} {'SYSCALL ID':<12} {'COUNT':<10} {'AVG DURATION (μs)'}")
            print("-" * 80)
            
            for (pid, comm, syscall_id), stats in sorted_syscalls[:20]:  # Top 20
                avg_duration = (stats["total_duration"] / stats["count"]) / 1000  # Convert to microseconds
                print(f"{pid:<8} {comm:<20} {syscall_id:<12} {stats['count']:<10} {avg_duration:.2f}")
        else:
            print("No syscall data collected")
        
        print("\n" + "="*80)
    
    def get_stack_traces(self):
        """Get and print stack traces from profiled processes"""
        print("\n🔍 STACK TRACES")
        print("-" * 80)
        
        stack_traces = self.bpf.get_table("stack_traces")
        
        # Get some sample stack traces
        sample_count = 0
        for k, v in sorted(self.cpu_samples.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"\nProcess: {k[1]} (PID: {k[0]})")
            print("-" * 40)
            sample_count += 1
            if sample_count > 5:  # Limit to 5 processes
                break
    
    def cleanup(self):
        """Clean up and detach eBPF programs"""
        if self.bpf:
            print("[*] Cleaning up eBPF programs...")
            # BCC automatically detaches on cleanup
            self.bpf.cleanup()
            print("[✓] Cleanup complete")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="eBPF Performance Profiler")
    parser.add_argument("--pid", type=int, help="Profile specific PID only")
    parser.add_argument("--freq", type=int, default=99, help="Sampling frequency in Hz (default: 99)")
    parser.add_argument("--duration", type=int, help="Profile duration in seconds (default: run until Ctrl+C)")
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[✗] Error: This program requires root privileges")
        print("    Please run with: sudo python3 profiler_loader.py")
        sys.exit(1)
    
    # Initialize profiler
    profiler = EBPFProfiler(target_pid=args.pid, sample_freq=args.freq)
    
    try:
        # Load and attach eBPF programs
        profiler.load()
        profiler.attach()
        
        # Start collecting data
        if args.duration:
            print(f"[*] Profiling for {args.duration} seconds...")
            profiler.running = True
            profiler.start_polling()
            time.sleep(args.duration)
            profiler.running = False
        else:
            profiler.start_polling()
        
        # Print results
        profiler.print_results()
        
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        profiler.cleanup()


if __name__ == "__main__":
    main()