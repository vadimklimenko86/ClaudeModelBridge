"""Main entry point that provides Flask app for gunicorn."""

import os
import threading
import time
from flask import Flask, jsonify
from server import main as mcp_main

# Create Flask app for gunicorn compatibility
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Global variable to track MCP server
mcp_thread = None
mcp_running = False

def run_mcp_server():
    """Run MCP server in background thread."""
    global mcp_running
    try:
        import sys
        # Override sys.argv to pass correct arguments to MCP server
        original_argv = sys.argv
        sys.argv = ['server.py', '--port', '5001', '--log-level', 'INFO']
        mcp_running = True
        mcp_main()
    except Exception as e:
        print(f"MCP Server error: {e}")
        mcp_running = False
    finally:
        sys.argv = original_argv

@app.route('/')
def index():
    """Health check endpoint."""
    return jsonify({
        "status": "running",
        "service": "MCP Server",
        "mcp_port": 5001,
        "web_port": 5000
    })

@app.route('/health')
def health():
    """Health check."""
    return jsonify({"status": "healthy"})

def start_mcp_server():
    """Start MCP server in background."""
    global mcp_thread
    if mcp_thread is None or not mcp_thread.is_alive():
        mcp_thread = threading.Thread(target=run_mcp_server, daemon=True)
        mcp_thread.start()
        time.sleep(1)  # Give it a moment to start

# Start MCP server when module is imported
start_mcp_server()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
