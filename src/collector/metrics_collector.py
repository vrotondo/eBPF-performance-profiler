#!/usr/bin/env python3
"""
Metrics Collector - Aggregates eBPF data for the web dashboard
Runs in background and provides clean data to Flask API
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
import json


class MetricsCollector:
    """Collects and aggregates metrics from eBPF profiler"""
    
    def __init__(self, max_history=60):
        """
        Initialize metrics collector
        
        Args:
            max_history: Number of data points to keep (default 60 = 1 minute at 1Hz)
        """
        self.max_history = max_history
        
        # Time-series data storage
        self.cpu_history = deque(maxlen=max_history)
        self.io_history = deque(maxlen=max_history)
        self.syscall_history = deque(maxlen=max_history)
        
        # Current aggregated data
        self.cpu_data = defaultdict(lambda: {"samples": 0, "percent": 0.0})
        self.io_data = defaultdict(lambda: {
            "read_bytes": 0,
            "write_bytes": 0,
            "read_ops": 0,
            "write_ops": 0
        })
        self.syscall_data = defaultdict(lambda: {
            "count": 0,
            "total_duration": 0,
            "avg_duration": 0
        })
        
        # Process metadata
        self.processes = {}  # pid -> {name, last_seen}
        
        # Stats
        self.total_samples = 0
        self.start_time = time.time()
        
        # Thread safety
        self.lock = threading.Lock()
    
    def add_cpu_sample(self, pid, comm, timestamp):
        """Add a CPU sample"""
        with self.lock:
            key = f"{pid}:{comm}"
            self.cpu_data[key]["samples"] += 1
            self.total_samples += 1
            
            # Update process metadata
            self.processes[pid] = {
                "name": comm,
                "last_seen": timestamp
            }
    
    def add_io_event(self, pid, comm, bytes_amount, operation, duration):
        """
        Add an I/O event
        
        Args:
            operation: 0 for read, 1 for write
        """
        with self.lock:
            key = f"{pid}:{comm}"
            
            if operation == 0:  # read
                self.io_data[key]["read_bytes"] += bytes_amount
                self.io_data[key]["read_ops"] += 1
            else:  # write
                self.io_data[key]["write_bytes"] += bytes_amount
                self.io_data[key]["write_ops"] += 1
    
    def add_syscall_event(self, pid, comm, syscall_id, duration):
        """Add a syscall event"""
        with self.lock:
            key = f"{pid}:{comm}:{syscall_id}"
            self.syscall_data[key]["count"] += 1
            self.syscall_data[key]["total_duration"] += duration
    
    def calculate_percentages(self):
        """Calculate CPU percentages from sample counts"""
        with self.lock:
            if self.total_samples == 0:
                return
            
            for key in self.cpu_data:
                samples = self.cpu_data[key]["samples"]
                self.cpu_data[key]["percent"] = (samples / self.total_samples) * 100
    
    def get_top_cpu_processes(self, n=10):
        """Get top N CPU-using processes"""
        with self.lock:
            self.calculate_percentages()
            
            # Sort by percentage
            sorted_procs = sorted(
                self.cpu_data.items(),
                key=lambda x: x[1]["percent"],
                reverse=True
            )
            
            result = []
            for key, data in sorted_procs[:n]:
                pid, comm = key.split(":", 1)
                result.append({
                    "pid": int(pid),
                    "name": comm,
                    "samples": data["samples"],
                    "cpu_percent": round(data["percent"], 2)
                })
            
            return result
    
    def get_top_io_processes(self, n=10):
        """Get top N I/O-heavy processes"""
        with self.lock:
            # Sort by total bytes (read + write)
            sorted_procs = sorted(
                self.io_data.items(),
                key=lambda x: x[1]["read_bytes"] + x[1]["write_bytes"],
                reverse=True
            )
            
            result = []
            for key, data in sorted_procs[:n]:
                if data["read_bytes"] == 0 and data["write_bytes"] == 0:
                    continue
                
                pid, comm = key.split(":", 1)
                result.append({
                    "pid": int(pid),
                    "name": comm,
                    "read_mb": round(data["read_bytes"] / (1024 * 1024), 2),
                    "write_mb": round(data["write_bytes"] / (1024 * 1024), 2),
                    "total_ops": data["read_ops"] + data["write_ops"]
                })
            
            return result
    
    def get_top_syscalls(self, n=10):
        """Get top N most frequent syscalls"""
        with self.lock:
            # Sort by count
            sorted_syscalls = sorted(
                self.syscall_data.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )
            
            result = []
            for key, data in sorted_syscalls[:n]:
                parts = key.split(":")
                if len(parts) >= 3:
                    pid, comm, syscall_id = parts[0], parts[1], parts[2]
                    
                    avg_duration = 0
                    if data["count"] > 0:
                        avg_duration = data["total_duration"] / data["count"] / 1000  # Convert to microseconds
                    
                    result.append({
                        "pid": int(pid),
                        "name": comm,
                        "syscall_id": int(syscall_id),
                        "count": data["count"],
                        "avg_duration_us": round(avg_duration, 2)
                    })
            
            return result
    
    def get_summary_stats(self):
        """Get overall summary statistics"""
        with self.lock:
            uptime = time.time() - self.start_time
            
            # Total I/O
            total_read = sum(data["read_bytes"] for data in self.io_data.values())
            total_write = sum(data["write_bytes"] for data in self.io_data.values())
            total_io_ops = sum(
                data["read_ops"] + data["write_ops"] 
                for data in self.io_data.values()
            )
            
            # Total syscalls
            total_syscalls = sum(data["count"] for data in self.syscall_data.values())
            
            return {
                "uptime_seconds": round(uptime, 1),
                "total_processes": len(self.processes),
                "total_cpu_samples": self.total_samples,
                "total_io_mb": round((total_read + total_write) / (1024 * 1024), 2),
                "total_io_ops": total_io_ops,
                "total_syscalls": total_syscalls,
                "timestamp": datetime.now().isoformat()
            }
    
    def snapshot(self):
        """Take a snapshot of current metrics for time-series"""
        snapshot_data = {
            "timestamp": time.time(),
            "cpu": self.get_top_cpu_processes(5),
            "io": self.get_top_io_processes(5),
            "syscalls": self.get_top_syscalls(5),
            "summary": self.get_summary_stats()
        }
        
        with self.lock:
            self.cpu_history.append(snapshot_data)
    
    def get_time_series_data(self):
        """Get time-series data for charting"""
        with self.lock:
            return list(self.cpu_history)
    
    def reset_stats(self):
        """Reset all statistics"""
        with self.lock:
            self.cpu_data.clear()
            self.io_data.clear()
            self.syscall_data.clear()
            self.processes.clear()
            self.total_samples = 0
            self.cpu_history.clear()
            self.io_history.clear()
            self.syscall_history.clear()
            self.start_time = time.time()
    
    def to_json(self):
        """Export current state as JSON"""
        return {
            "summary": self.get_summary_stats(),
            "top_cpu": self.get_top_cpu_processes(10),
            "top_io": self.get_top_io_processes(10),
            "top_syscalls": self.get_top_syscalls(10),
            "time_series": self.get_time_series_data()
        }


class PeriodicSnapshotter(threading.Thread):
    """Background thread that takes periodic snapshots"""
    
    def __init__(self, collector, interval=1.0):
        """
        Args:
            collector: MetricsCollector instance
            interval: Snapshot interval in seconds
        """
        super().__init__(daemon=True)
        self.collector = collector
        self.interval = interval
        self.running = True
    
    def run(self):
        """Run the snapshot loop"""
        while self.running:
            self.collector.snapshot()
            time.sleep(self.interval)
    
    def stop(self):
        """Stop the snapshotter"""
        self.running = False