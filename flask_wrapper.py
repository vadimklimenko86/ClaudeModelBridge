"""Flask wrapper for the MCP server to make it work with gunicorn."""

import os
import asyncio
import threading
from flask import Flask, jsonify, render_template_string
from server import main as mcp_main

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Global variable to store MCP server thread
mcp_thread = None
mcp_running = False

def run_mcp_server():
    """Run MCP server in background thread."""
    global mcp_running
    try:
        # Run MCP server on a different port
        import sys
        sys.argv = ['server.py', '--port', '5001']
        mcp_running = True
        mcp_main()
    except Exception as e:
        print(f"MCP Server error: {e}")
        mcp_running = False

@app.route('/')
def index():
    """Main dashboard page."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Server Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .status { padding: 10px; border-radius: 5px; margin: 10px 0; }
            .running { background-color: #d4edda; color: #155724; }
            .stopped { background-color: #f8d7da; color: #721c24; }
            .info { background-color: #d1ecf1; color: #0c5460; }
            ul { margin: 10px 0; }
            li { margin: 5px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>MCP Server Dashboard</h1>
            
            <div class="status {{ 'running' if mcp_status else 'stopped' }}">
                <strong>Status:</strong> {{ 'Running' if mcp_status else 'Stopped' }}
            </div>
            
            <div class="info">
                <h3>Available Tools:</h3>
                <ul>
                    <li><strong>echo</strong> - Echo back messages with timestamp</li>
                    <li><strong>system_info</strong> - Get comprehensive system information</li>
                    <li><strong>calculator</strong> - Perform mathematical calculations</li>
                    <li><strong>file_operations</strong> - File system operations (read, write, list)</li>
                    <li><strong>memory</strong> - Memory management with vector search</li>
                </ul>
            </div>
            
            <div class="info">
                <h3>Configuration:</h3>
                <ul>
                    <li><strong>Web Interface:</strong> Port 5000 (Flask)</li>
                    <li><strong>MCP Server:</strong> Port 5001 (Starlette)</li>
                    <li><strong>Database:</strong> PostgreSQL ({{ db_status }})</li>
                </ul>
            </div>
            
            <div class="info">
                <h3>API Endpoints:</h3>
                <ul>
                    <li><strong>GET /api/health</strong> - Health check</li>
                    <li><strong>GET /api/status</strong> - Server status</li>
                    <li><strong>GET /api/tools</strong> - List available tools</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    db_status = "Connected" if os.environ.get("DATABASE_URL") else "Not configured"
    return render_template_string(html, mcp_status=mcp_running, db_status=db_status)

@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "mcp_server": "running" if mcp_running else "stopped",
        "database": "connected" if os.environ.get("DATABASE_URL") else "not_configured"
    })

@app.route('/api/status')
def status():
    """Get detailed status information."""
    return jsonify({
        "web_server": "running",
        "mcp_server": "running" if mcp_running else "stopped",
        "mcp_port": 5001,
        "web_port": 5000,
        "database_url": bool(os.environ.get("DATABASE_URL"))
    })

@app.route('/api/tools')
def tools():
    """List available MCP tools."""
    tools_list = [
        {
            "name": "echo",
            "description": "Echo back any message with timestamp",
            "parameters": {"message": "string (required)"}
        },
        {
            "name": "system_info", 
            "description": "Get real-time system information and metrics",
            "parameters": {"detail_level": "string (optional) - basic, detailed, or full"}
        },
        {
            "name": "calculator",
            "description": "Perform mathematical calculations safely", 
            "parameters": {"expression": "string (required)"}
        },
        {
            "name": "file_operations",
            "description": "File system operations (read, write, list, delete)",
            "parameters": {"action": "string (required)", "path": "string (required)"}
        },
        {
            "name": "memory",
            "description": "Memory management with vector search capabilities",
            "parameters": {"action": "string (required)", "content": "string (optional)"}
        }
    ]
    return jsonify({"tools": tools_list, "count": len(tools_list)})

def start_mcp_server():
    """Start MCP server in background thread."""
    global mcp_thread
    if mcp_thread is None or not mcp_thread.is_alive():
        mcp_thread = threading.Thread(target=run_mcp_server, daemon=True)
        mcp_thread.start()

# Start MCP server when Flask app starts
start_mcp_server()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)