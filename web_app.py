import eventlet
eventlet.monkey_patch()

import os
import sys
import threading
import queue
import time
import psutil # Added for subprocess management
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from hacksmarter import run_swarm, parse_targets

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Queue to store stdout logs from the swarm thread
log_queue = queue.Queue()

class SocketIOWriter:
    """Redirects stdout to a queue that gets emitted via SocketIO."""
    def write(self, data):
        if data.strip():
            log_queue.put(data)
        sys.__stdout__.write(data) # Still print to actual console

    def flush(self):
        sys.__stdout__.flush()

# Redirect stdout globally (careful!)
sys.stdout = SocketIOWriter()

def swarm_worker(targets, excluded_tools, client_name):
    """Background thread that runs the actual AI swarm logic."""
    try:
        run_swarm(targets, excluded_tools, client_name, verbose=True)
    except Exception as e:
        print(f"[ERROR] Web Worker failed: {e}")
    finally:
        log_queue.put("SWARM_COMPLETE")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/clients')
def get_clients():
    clients_dir = "clients"
    if not os.path.exists(clients_dir):
        return jsonify([])
    clients = [d for d in os.listdir(clients_dir) if os.path.isdir(os.path.join(clients_dir, d))]
    return jsonify(clients)

@app.route('/api/reports/<client>')
def get_report(client):
    report_path = os.path.join("clients", client, "final_report.md")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path, "r") as f:
        return jsonify({"content": f.read()})

@socketio.on('skip_task')
def handle_skip_task():
    import tools
    tools.SKIP_CURRENT_TASK = True
    
    # Forcefully terminate any subprocesses spawned by the swarm (nmap, ferox, etc.)
    try:
        parent = psutil.Process()
        for child in parent.children(recursive=True):
            if child.pid != os.getpid():
                child.terminate()
    except Exception as e:
        print(f"[!] Error skipping: {e}")
        
    emit('log', {'data': '[!] USER SIGNAL: Terminating current task subprocesses...'})

@socketio.on('start_swarm')
def handle_start_swarm(data):
    target_raw = data.get('targets', '')
    excluded_tools = data.get('exclude', [])
    client_name = data.get('client_name', 'default')
    
    targets = parse_targets(target_raw)
    
    if not targets:
        emit('log', {'data': '[!] No valid targets found.'})
        return

    emit('log', {'data': f'[*] Swarm initialized for targets: {", ".join(targets)}'})
    
    # Start the swarm in a background thread
    thread = threading.Thread(target=swarm_worker, args=(targets, excluded_tools, client_name))
    thread.daemon = True
    thread.start()

def log_emitter():
    """Reads logs from the queue and sends them to all connected clients."""
    while True:
        try:
            msg = log_queue.get(timeout=1)
            socketio.emit('log', {'data': msg})
        except queue.Empty:
            continue

# Start the log emitter background task
socketio.start_background_task(log_emitter)

if __name__ == '__main__':
    print("[*] Launching Hack Smarter Swarm GUI on http://0.0.0.0:1337")
    socketio.run(app, host='0.0.0.0', port=1337, debug=False)
