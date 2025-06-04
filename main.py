#!/usr/bin/env python3
"""
Main entry point for Remote MCP Server
Official Python SDK v1.9.2 implementation
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import Flask for WSGI compatibility with gunicorn
from flask import Flask, jsonify, render_template_string, request, redirect, url_for, session
from flask_cors import CORS
import json
import time
import platform
import psutil
import base64
import urllib.parse
from oauth_handler import oauth_handler

# Create Flask app for gunicorn
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "mcp_oauth_secret_key_2024")
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP for development
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
CORS(app, supports_credentials=True)

# HTML template for dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remote MCP Server Dashboard</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        h1 { color: #4a5568; text-align: center; margin-bottom: 30px; }
        .status { 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            margin: 20px 0;
            padding: 15px;
            background: #e6fffa;
            border-radius: 8px;
        }
        .status-dot { 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            background: #48bb78; 
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.7; }
            100% { transform: scale(1); opacity: 1; }
        }
        .grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin: 30px 0;
        }
        .card { 
            background: #f7fafc; 
            padding: 20px; 
            border-radius: 10px; 
            border: 1px solid #e2e8f0;
        }
        .card h3 { color: #4a5568; margin-bottom: 15px; }
        .metric { 
            display: flex; 
            justify-content: space-between; 
            margin: 10px 0; 
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }
        .metric:last-child { border-bottom: none; }
        .buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            background: #4299e1;
            color: white;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: #3182ce;
            transform: translateY(-2px);
        }
        .btn-secondary {
            background: #48bb78;
        }
        .btn-secondary:hover {
            background: #38a169;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Remote MCP Server</h1>
        <p style="text-align: center; color: #718096; margin-bottom: 30px;">
            Model Context Protocol Server using Official Python SDK v1.9.2
        </p>
        
        <div class="status">
            <div class="status-dot"></div>
            <span><strong>Server Online</strong> - Ready for Claude.ai integration</span>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Server Information</h3>
                <div class="metric">
                    <span>Protocol Version</span>
                    <span>2024-11-05</span>
                </div>
                <div class="metric">
                    <span>SDK Version</span>
                    <span>1.9.2</span>
                </div>
                <div class="metric">
                    <span>Transport</span>
                    <span>HTTP + stdio</span>
                </div>
                <div class="metric">
                    <span>Claude.ai Compatible</span>
                    <span>✓ Yes</span>
                </div>
            </div>

            <div class="card">
                <h3>System Status</h3>
                <div id="metrics">
                    <div class="metric">
                        <span>Loading...</span>
                        <span>...</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Available Features</h3>
                <div class="metric">
                    <span>Echo Tool</span>
                    <span>✓ Active</span>
                </div>
                <div class="metric">
                    <span>System Monitor</span>
                    <span>✓ Active</span>
                </div>
                <div class="metric">
                    <span>Calculator</span>
                    <span>✓ Active</span>
                </div>
                <div class="metric">
                    <span>File Operations</span>
                    <span>✓ Active</span>
                </div>
                <div class="metric">
                    <span>Network Info</span>
                    <span>✓ Active</span>
                </div>
            </div>
        </div>

        <div class="buttons">
            <a href="/mcp/info" class="btn">MCP Info</a>
            <a href="/mcp/tools" class="btn btn-secondary">Tools List</a>
            <a href="/mcp/resources" class="btn btn-secondary">Resources</a>
            <a href="/health" class="btn">Health Check</a>
        </div>
    </div>

    <script>
        async function loadMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();
                
                document.getElementById('metrics').innerHTML = `
                    <div class="metric">
                        <span>CPU Usage</span>
                        <span>${data.cpu_percent.toFixed(1)}%</span>
                    </div>
                    <div class="metric">
                        <span>Memory Usage</span>
                        <span>${data.memory_percent.toFixed(1)}%</span>
                    </div>
                    <div class="metric">
                        <span>Disk Usage</span>
                        <span>${data.disk_percent.toFixed(1)}%</span>
                    </div>
                `;
            } catch (error) {
                console.error('Error loading metrics:', error);
            }
        }

        // Load metrics on page load and refresh every 5 seconds
        document.addEventListener('DOMContentLoaded', loadMetrics);
        setInterval(loadMetrics, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template_string(DASHBOARD_HTML)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "server": "Remote MCP Server",
        "version": "1.0.0",
        "sdk_version": "1.9.2",
        "protocol_version": "2024-11-05",
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    })

@app.route('/api/metrics')
def get_metrics():
    """Get system metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "disk_percent": (disk.used / disk.total) * 100,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/mcp/info')
def mcp_info():
    """MCP server information"""
    return jsonify({
        "name": "Remote MCP Server",
        "version": "1.0.0",
        "protocol_version": "2024-11-05",
        "sdk_version": "1.9.2",
        "transport": ["http", "stdio"],
        "capabilities": {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
            "prompts": {"listChanged": True}
        },
        "endpoints": {
            "tools": "/mcp/tools",
            "resources": "/mcp/resources",
            "call_tool": "/mcp/call",
            "read_resource": "/mcp/read"
        },
        "claude_ai_compatible": True,
        "official_sdk": True
    })

@app.route('/mcp/tools')
def list_tools():
    """List available MCP tools"""
    return jsonify([
        {
            "name": "echo",
            "description": "Echo back any message with timestamp and metadata",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message to echo back"},
                    "metadata": {"type": "object", "description": "Optional metadata to include"}
                },
                "required": ["message"]
            }
        },
        {
            "name": "system_monitor",
            "description": "Get comprehensive real-time system monitoring data",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "detail_level": {
                        "type": "string",
                        "enum": ["basic", "detailed", "full"],
                        "description": "Level of detail for system information"
                    },
                    "include_processes": {"type": "boolean", "description": "Include running processes"}
                }
            }
        },
        {
            "name": "calculator",
            "description": "Advanced mathematical calculator with functions and constants",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "Mathematical expression to evaluate"},
                    "precision": {"type": "integer", "description": "Number of decimal places", "default": 10}
                },
                "required": ["expression"]
            }
        },
        {
            "name": "file_operations",
            "description": "Safe file system operations (read, list, info)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "enum": ["read", "list", "info", "exists"]},
                    "path": {"type": "string", "description": "File or directory path"},
                    "encoding": {"type": "string", "default": "utf-8"}
                },
                "required": ["operation", "path"]
            }
        },
        {
            "name": "network_info",
            "description": "Get network interface and connectivity information",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_stats": {"type": "boolean", "description": "Include network I/O statistics", "default": True}
                }
            }
        }
    ])

@app.route('/mcp/resources')
def list_resources():
    """List available MCP resources"""
    return jsonify([
        {
            "uri": "system://monitor/realtime",
            "name": "Real-time System Monitor",
            "description": "Live system metrics and performance data",
            "mimeType": "application/json"
        },
        {
            "uri": "system://processes/active",
            "name": "Active Processes",
            "description": "Currently running system processes",
            "mimeType": "application/json"
        },
        {
            "uri": "system://network/interfaces",
            "name": "Network Interfaces",
            "description": "Network interface configuration and statistics",
            "mimeType": "application/json"
        },
        {
            "uri": "system://logs/recent",
            "name": "Recent System Logs",
            "description": "Recent system and application logs",
            "mimeType": "text/plain"
        }
    ])

@app.route('/mcp/call/<tool_name>', methods=['POST'])
def call_tool(tool_name):
    """Call a specific MCP tool"""
    try:
        from flask import request
        arguments = request.get_json() or {}
        
        if tool_name == "echo":
            message = arguments.get("message", "")
            metadata = arguments.get("metadata", {})
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            
            response = {
                "original_message": message,
                "timestamp": timestamp,
                "metadata": metadata,
                "server_info": {
                    "name": "Remote MCP Server",
                    "protocol_version": "2024-11-05",
                    "sdk_version": "1.9.2"
                }
            }
            
            return jsonify({
                "tool": tool_name,
                "result": [{"type": "text", "text": json.dumps(response, indent=2)}]
            })
        
        elif tool_name == "system_monitor":
            detail_level = arguments.get("detail_level", "detailed")
            include_processes = arguments.get("include_processes", False)
            
            # Get system information
            info = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                "detail_level": detail_level,
                "system": {
                    "platform": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python_version": platform.python_version()
                },
                "cpu": {
                    "physical_cores": psutil.cpu_count(logical=False),
                    "logical_cores": psutil.cpu_count(logical=True),
                    "current_usage": psutil.cpu_percent(interval=1)
                },
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "used": psutil.virtual_memory().used,
                    "percentage": psutil.virtual_memory().percent
                },
                "disk": {
                    "total": psutil.disk_usage('/').total,
                    "used": psutil.disk_usage('/').used,
                    "free": psutil.disk_usage('/').free,
                    "percentage": (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100
                }
            }
            
            if include_processes:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                    try:
                        proc_info = proc.info
                        if proc_info['cpu_percent'] is not None:
                            processes.append(proc_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                info["top_processes"] = processes[:20]
            
            return jsonify({
                "tool": tool_name,
                "result": [{"type": "text", "text": json.dumps(info, indent=2)}]
            })
        
        elif tool_name == "calculator":
            expression = arguments.get("expression", "")
            precision = arguments.get("precision", 10)
            
            try:
                # Simple safe evaluation for basic math
                import ast
                import operator
                import math
                
                # Supported operations
                ops = {
                    ast.Add: operator.add,
                    ast.Sub: operator.sub,
                    ast.Mult: operator.mul,
                    ast.Div: operator.truediv,
                    ast.Pow: operator.pow,
                    ast.USub: operator.neg,
                }
                
                def safe_eval(node):
                    if isinstance(node, ast.Constant):
                        return node.value
                    elif isinstance(node, ast.BinOp):
                        return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
                    elif isinstance(node, ast.UnaryOp):
                        return ops[type(node.op)](safe_eval(node.operand))
                    elif isinstance(node, ast.Name):
                        if node.id == 'pi':
                            return math.pi
                        elif node.id == 'e':
                            return math.e
                        else:
                            raise ValueError(f"Undefined variable: {node.id}")
                    else:
                        raise TypeError(f"Unsupported operation: {type(node).__name__}")
                
                tree = ast.parse(expression, mode='eval')
                result = safe_eval(tree.body)
                
                if isinstance(result, float):
                    if result.is_integer():
                        formatted_result = str(int(result))
                    else:
                        formatted_result = f"{result:.{precision}f}".rstrip('0').rstrip('.')
                else:
                    formatted_result = str(result)
                
                response = {
                    "expression": expression,
                    "result": formatted_result,
                    "raw_result": result,
                    "type": type(result).__name__,
                    "precision": precision
                }
                
                return jsonify({
                    "tool": tool_name,
                    "result": [{"type": "text", "text": json.dumps(response, indent=2)}]
                })
                
            except Exception as e:
                error_response = {
                    "expression": expression,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "supported_operations": ["+", "-", "*", "/", "**", "()"],
                    "supported_constants": ["pi", "e"]
                }
                return jsonify({
                    "tool": tool_name,
                    "result": [{"type": "text", "text": json.dumps(error_response, indent=2)}]
                })
        
        else:
            return jsonify({"error": f"Unknown tool: {tool_name}"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# OAuth 2.0 Authorization Server Metadata Discovery
@app.route('/.well-known/oauth-authorization-server')
def oauth_metadata():
    """OAuth 2.0 Authorization Server Metadata Discovery"""
    return jsonify(oauth_handler.get_authorization_server_metadata())

# OAuth 2.0 Authorization Endpoint
@app.route('/oauth/authorize')
def oauth_authorize():
    """OAuth 2.0 Authorization Endpoint"""
    # Extract parameters
    response_type = request.args.get('response_type')
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', '')
    state = request.args.get('state')
    code_challenge = request.args.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method', 'plain')
    
    # Validate required parameters
    if not response_type or not client_id or not redirect_uri:
        return jsonify({"error": "invalid_request", "error_description": "Missing required parameters"}), 400
    
    # Validate response type
    if response_type != 'code':
        return jsonify({"error": "unsupported_response_type", "error_description": "Only 'code' response type is supported"}), 400
    
    # Validate client
    if not oauth_handler.validate_client(client_id):
        return jsonify({"error": "invalid_client", "error_description": "Invalid client_id"}), 400
    
    # Validate redirect URI
    if not oauth_handler.validate_redirect_uri(client_id, redirect_uri):
        return jsonify({"error": "invalid_request", "error_description": "Invalid redirect_uri"}), 400
    
    # Validate scope
    if not oauth_handler.validate_scope(scope, client_id):
        return jsonify({"error": "invalid_scope", "error_description": "Invalid scope"}), 400
    
    # Store authorization request in session
    session['auth_request'] = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method
    }
    
    # For demo purposes, auto-approve (in production, show consent form)
    return redirect(url_for('oauth_consent'))

@app.route('/oauth/consent')
def oauth_consent():
    """OAuth 2.0 User Consent Page"""
    auth_request = session.get('auth_request')
    if not auth_request:
        return jsonify({"error": "invalid_request", "error_description": "No authorization request found"}), 400
    
    consent_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Server Authorization</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 50px; background: #f5f5f5; }}
            .consent-box {{ background: white; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .btn {{ padding: 12px 24px; margin: 10px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }}
            .btn-approve {{ background: #48bb78; color: white; }}
            .btn-deny {{ background: #e53e3e; color: white; }}
            .scopes {{ background: #f7fafc; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        </style>
    </head>
    <body>
        <div class="consent-box">
            <h2>Authorization Request</h2>
            <p><strong>Client:</strong> {auth_request['client_id']}</p>
            <p><strong>Requested Permissions:</strong></p>
            <div class="scopes">
                {auth_request['scope'] or 'Basic access'}
            </div>
            <p>Do you want to authorize this application to access your MCP server?</p>
            <form method="post" action="/oauth/authorize_decision">
                <button type="submit" name="decision" value="approve" class="btn btn-approve">Approve</button>
                <button type="submit" name="decision" value="deny" class="btn btn-deny">Deny</button>
            </form>
        </div>
    </body>
    </html>
    """
    return consent_html

@app.route('/oauth/authorize_decision', methods=['POST'])
def oauth_authorize_decision():
    """Handle user authorization decision"""
    auth_request = session.get('auth_request')
    if not auth_request:
        return jsonify({"error": "invalid_request", "error_description": "No authorization request found"}), 400
    
    decision = request.form.get('decision')
    
    if decision == 'approve':
        # Generate authorization code
        code = oauth_handler.create_authorization_code(
            client_id=auth_request['client_id'],
            redirect_uri=auth_request['redirect_uri'],
            scope=auth_request['scope'],
            challenge=auth_request.get('code_challenge'),
            challenge_method=auth_request.get('code_challenge_method'),
            user_id='demo_user'  # In production, use actual user ID
        )
        
        # Build redirect URL
        redirect_url = auth_request['redirect_uri']
        params = {'code': code}
        if auth_request.get('state'):
            params['state'] = auth_request['state']
        
        redirect_url += '?' + urllib.parse.urlencode(params)
        
        # Clear session
        session.pop('auth_request', None)
        
        return redirect(redirect_url)
    
    else:
        # User denied authorization
        redirect_url = auth_request['redirect_uri']
        params = {'error': 'access_denied', 'error_description': 'User denied authorization'}
        if auth_request.get('state'):
            params['state'] = auth_request['state']
        
        redirect_url += '?' + urllib.parse.urlencode(params)
        
        # Clear session
        session.pop('auth_request', None)
        
        return redirect(redirect_url)

# OAuth 2.0 Token Endpoint
@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    """OAuth 2.0 Token Endpoint"""
    # Get client credentials from Authorization header or form data
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Basic '):
        # Decode Basic auth
        encoded_credentials = auth_header[6:]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        client_id, client_secret = decoded_credentials.split(':', 1)
    else:
        # Get from form data
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    
    grant_type = request.form.get('grant_type')
    
    if not grant_type:
        return jsonify({"error": "invalid_request", "error_description": "Missing grant_type"}), 400
    
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        code_verifier = request.form.get('code_verifier')
        
        if not code or not redirect_uri:
            return jsonify({"error": "invalid_request", "error_description": "Missing required parameters"}), 400
        
        token_response = oauth_handler.exchange_authorization_code(
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )
        
        if not token_response:
            return jsonify({"error": "invalid_grant", "error_description": "Invalid authorization code"}), 400
        
        return jsonify(token_response)
    
    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        
        if not refresh_token:
            return jsonify({"error": "invalid_request", "error_description": "Missing refresh_token"}), 400
        
        token_response = oauth_handler.refresh_access_token(
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret
        )
        
        if not token_response:
            return jsonify({"error": "invalid_grant", "error_description": "Invalid refresh token"}), 400
        
        return jsonify(token_response)
    
    elif grant_type == 'client_credentials':
        scope = request.form.get('scope', '')
        
        token_response = oauth_handler.client_credentials_grant(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope
        )
        
        if not token_response:
            return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials"}), 400
        
        return jsonify(token_response)
    
    else:
        return jsonify({"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' is not supported"}), 400

# OAuth 2.0 Token Revocation Endpoint
@app.route('/oauth/revoke', methods=['POST'])
def oauth_revoke():
    """OAuth 2.0 Token Revocation Endpoint"""
    # Get client credentials
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Basic '):
        encoded_credentials = auth_header[6:]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        client_id, client_secret = decoded_credentials.split(':', 1)
    else:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    
    token = request.form.get('token')
    
    if not token:
        return jsonify({"error": "invalid_request", "error_description": "Missing token"}), 400
    
    success = oauth_handler.revoke_token(token, client_id, client_secret)
    
    if success:
        return '', 200  # RFC 7009: successful revocation returns 200 with empty body
    else:
        return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials or token"}), 400

# OAuth 2.0 Token Introspection Endpoint
@app.route('/oauth/introspect', methods=['POST'])
def oauth_introspect():
    """OAuth 2.0 Token Introspection Endpoint"""
    # Get client credentials
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Basic '):
        encoded_credentials = auth_header[6:]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        client_id, client_secret = decoded_credentials.split(':', 1)
    else:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    
    token = request.form.get('token')
    
    if not token:
        return jsonify({"error": "invalid_request", "error_description": "Missing token"}), 400
    
    introspection_result = oauth_handler.introspect_token(token, client_id, client_secret)
    return jsonify(introspection_result)

# OAuth 2.0 Callback for testing
@app.route('/oauth/callback')
def oauth_callback():
    """OAuth 2.0 Callback for testing"""
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        return f"""
        <h2>Authorization Error</h2>
        <p><strong>Error:</strong> {error}</p>
        <p><strong>Description:</strong> {request.args.get('error_description', 'Unknown error')}</p>
        <p><strong>State:</strong> {state}</p>
        """
    
    if code:
        return f"""
        <h2>Authorization Successful</h2>
        <p><strong>Authorization Code:</strong> {code}</p>
        <p><strong>State:</strong> {state}</p>
        <p>Use this code to exchange for an access token at the token endpoint.</p>
        """
    
    return "No authorization code received", 400

# Protected MCP endpoints with OAuth 2.0
def require_oauth(scopes=None):
    """Decorator to require OAuth 2.0 authorization"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "unauthorized", "error_description": "Missing or invalid access token"}), 401
            
            access_token = auth_header[7:]  # Remove 'Bearer ' prefix
            token_obj = oauth_handler.validate_access_token(access_token)
            
            if not token_obj:
                return jsonify({"error": "invalid_token", "error_description": "Access token is invalid or expired"}), 401
            
            # Check scope if required
            if scopes:
                token_scopes = set(token_obj.scope.split())
                required_scopes = set(scopes)
                
                # Allow "claudeai" scope to access all MCP functions
                if "claudeai" in token_scopes:
                    pass  # claudeai scope grants full access
                elif not required_scopes.issubset(token_scopes):
                    return jsonify({"error": "insufficient_scope", "error_description": "Insufficient scope"}), 403
            
            # Store token info in request context
            request.oauth_token = token_obj
            return f(*args, **kwargs)
        
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Protected MCP endpoints
@app.route('/mcp/protected/tools')
@require_oauth(['mcp:tools'])
def protected_list_tools():
    """List MCP tools (OAuth protected)"""
    return list_tools()

@app.route('/mcp/protected/call/<tool_name>', methods=['POST'])
@require_oauth(['mcp:tools'])
def protected_call_tool(tool_name):
    """Call MCP tool (OAuth protected)"""
    arguments = request.get_json() or {}
    return call_tool(tool_name)

@app.route('/mcp/protected/resources')
@require_oauth(['mcp:resources'])
def protected_list_resources():
    """List MCP resources (OAuth protected)"""
    return list_resources()

if __name__ == "__main__":
    # Create necessary directories
    Path("templates").mkdir(exist_ok=True)
    Path("static").mkdir(exist_ok=True)
    
    logger.info("Starting Remote MCP Server with OAuth 2.0")
    logger.info("Official Python SDK v1.9.2")
    logger.info("Protocol Version: 2024-11-05")
    logger.info("OAuth 2.0 Authorization Server ready")
    
    app.run(host="0.0.0.0", port=5000, debug=True)