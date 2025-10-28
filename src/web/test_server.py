#!/usr/bin/env python3
"""
SIMPLE TEST VERSION - Just to verify WebSocket works
This sends fake data to test the connection
"""

from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import time
import threading
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('[*] Client connected!')
    # Send test data immediately
    test_data = {
        "summary": {
            "uptime_seconds": 10.0,
            "total_processes": 5,
            "total_cpu_samples": 100,
            "total_io_mb": 25.5,
            "total_io_ops": 50,
            "total_syscalls": 200,
            "timestamp": "2025-10-28T12:00:00"
        },
        "top_cpu": [
            {"pid": 1234, "name": "test-process", "samples": 50, "cpu_percent": 45.5},
            {"pid": 5678, "name": "python3", "samples": 30, "cpu_percent": 27.3}
        ],
        "top_io": [
            {"pid": 1234, "name": "test-process", "read_mb": 10.5, "write_mb": 5.2, "total_ops": 25}
        ],
        "top_syscalls": [
            {"pid": 1234, "name": "test-process", "syscall_id": 0, "count": 100, "avg_duration_us": 1.5}
        ],
        "time_series": []
    }
    emit('metrics_update', test_data)

@socketio.on('request_update')
def handle_request():
    print('[*] Update requested')
    handle_connect()  # Send same test data

def broadcast():
    """Send fake data every second"""
    while True:
        time.sleep(1)
        test_data = {
            "summary": {
                "uptime_seconds": random.randint(10, 100),
                "total_processes": random.randint(5, 20),
                "total_cpu_samples": random.randint(100, 1000),
                "total_io_mb": round(random.uniform(10, 100), 2),
                "total_io_ops": random.randint(50, 500),
                "total_syscalls": random.randint(200, 2000),
                "timestamp": "2025-10-28T12:00:00"
            },
            "top_cpu": [
                {"pid": 1234, "name": "test-process", "samples": random.randint(10, 100), "cpu_percent": round(random.uniform(10, 50), 2)},
                {"pid": 5678, "name": "python3", "samples": random.randint(10, 100), "cpu_percent": round(random.uniform(10, 50), 2)}
            ],
            "top_io": [
                {"pid": 1234, "name": "test-process", "read_mb": round(random.uniform(5, 50), 2), "write_mb": round(random.uniform(5, 50), 2), "total_ops": random.randint(10, 100)}
            ],
            "top_syscalls": [
                {"pid": 1234, "name": "test-process", "syscall_id": 0, "count": random.randint(50, 500), "avg_duration_us": round(random.uniform(0.5, 5), 2)}
            ],
            "time_series": []
        }
        print(f'[*] Broadcasting test data: {test_data["summary"]["total_cpu_samples"]} samples')
        socketio.emit('metrics_update', test_data)

if __name__ == '__main__':
    print("="*80)
    print("SIMPLE TEST SERVER - Sending Fake Data")
    print("="*80)
    print("\nOpen browser to: http://localhost:5000")
    print("You should see fake data updating every second\n")
    
    # Start broadcaster
    thread = threading.Thread(target=broadcast, daemon=True)
    thread.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)