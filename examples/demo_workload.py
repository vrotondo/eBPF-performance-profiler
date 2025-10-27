#!/usr/bin/env python3
"""
Demo Workload for eBPF Performance Profiler
This program creates CPU, I/O, and syscall activity for testing
"""

import time
import os
import random
import threading
import tempfile


def cpu_intensive_task():
    """Generate CPU load"""
    print("[CPU Worker] Starting CPU-intensive work...")
    while True:
        # Calculate prime numbers (CPU intensive)
        result = sum(range(100000))
        # Add some randomness
        _ = [random.random() ** 2 for _ in range(1000)]
        time.sleep(0.1)


def io_intensive_task():
    """Generate I/O load"""
    print("[I/O Worker] Starting I/O-intensive work...")
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
    temp_path = temp_file.name
    
    try:
        while True:
            # Write data
            data = "x" * 10000  # 10KB of data
            temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            
            # Read data
            temp_file.seek(0)
            _ = temp_file.read()
            
            time.sleep(0.2)
    finally:
        temp_file.close()
        os.unlink(temp_path)


def syscall_intensive_task():
    """Generate syscall activity"""
    print("[Syscall Worker] Starting syscall-intensive work...")
    while True:
        # Make various syscalls
        _ = os.getpid()
        _ = os.getcwd()
        _ = time.time()
        _ = os.listdir('.')
        time.sleep(0.15)


def mixed_workload():
    """Mixed CPU and I/O work"""
    print("[Mixed Worker] Starting mixed workload...")
    temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
    temp_path = temp_file.name
    
    try:
        while True:
            # Some CPU work
            _ = sum(range(50000))
            
            # Some I/O
            temp_file.write("data" * 1000)
            temp_file.flush()
            
            # Some syscalls
            _ = os.getpid()
            
            time.sleep(0.1)
    finally:
        temp_file.close()
        try:
            os.unlink(temp_path)
        except:
            pass


def main():
    print("="*60)
    print("eBPF Performance Profiler - Demo Workload")
    print("="*60)
    print("\nThis program creates various types of load for testing:")
    print("  • CPU-intensive operations")
    print("  • I/O operations (read/write)")
    print("  • System call activity")
    print("  • Mixed workload")
    print("\nIn another terminal, run the profiler:")
    print(f"  sudo python3 profiler_loader.py --pid {os.getpid()}")
    print("\nPress Ctrl+C to stop")
    print("="*60 + "\n")
    
    # Start worker threads
    threads = [
        threading.Thread(target=cpu_intensive_task, daemon=True),
        threading.Thread(target=io_intensive_task, daemon=True),
        threading.Thread(target=syscall_intensive_task, daemon=True),
        threading.Thread(target=mixed_workload, daemon=True),
    ]
    
    for thread in threads:
        thread.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Stopping demo workload...")
        print("[✓] Demo complete!")


if __name__ == "__main__":
    main()