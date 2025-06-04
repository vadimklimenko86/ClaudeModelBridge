#!/usr/bin/env python3
"""
HTTP Bridge for MCP Server using official Python SDK
Provides HTTP/JSON-RPC interface for Claude.ai integration
"""

import asyncio
import json
import logging
import platform
import psutil
import ast
import operator
from typing import Any, Dict, List, Optional
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
CORS(app)

class MCPHTTPBridge:
    """HTTP Bridge for MCP Server"""
    
    def __init__(self):
        self.server = Server("flask-mcp-server")
        self.tools = []
        self.resources = []
        self.setup_handlers()
        
    def setup_handlers(self):
        """Setup MCP handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            return [
                Tool(
                    name="echo",
                    description="Echo back the input message",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Message to echo back"
                            }
                        },
                        "required": ["message"]
                    }
                ),
                Tool(
                    name="system_info",
                    description="Get detailed system information",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="calculator",
                    description="Perform safe mathematical calculations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "expression": {
                                "type": "string",
                                "description": "Mathematical expression to evaluate"
                            }
                        },
                        "required": ["expression"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[TextContent]:
            if name == "echo":
                message = arguments.get("message", "")
                return [TextContent(type="text", text=f"Echo: {message}")]
            
            elif name == "system_info":
                try:
                    cpu_count = psutil.cpu_count()
                    memory = psutil.virtual_memory()
                    
                    info = f"""System Information:
OS: {platform.system()} {platform.release()}
CPU: {cpu_count} cores, {psutil.cpu_percent()}% usage
Memory: {memory.total // (1024**3)} GB total, {memory.percent}% used
Python: {platform.python_version()}"""
                    
                    return [TextContent(type="text", text=info)]
                except Exception as e:
                    return [TextContent(type="text", text=f"Error: {str(e)}")]
            
            elif name == "calculator":
                expression = arguments.get("expression", "")
                try:
                    def safe_eval(node):
                        if isinstance(node, ast.Constant):
                            return node.value
                        elif isinstance(node, ast.BinOp):
                            return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
                        elif isinstance(node, ast.UnaryOp):
                            return ops[type(node.op)](safe_eval(node.operand))
                        else:
                            raise TypeError(f"Unsupported operation: {type(node)}")
                    
                    ops = {
                        ast.Add: operator.add,
                        ast.Sub: operator.sub,
                        ast.Mult: operator.mul,
                        ast.Div: operator.truediv,
                        ast.Pow: operator.pow,
                        ast.USub: operator.neg,
                    }
                    
                    tree = ast.parse(expression, mode='eval')
                    result = safe_eval(tree.body)
                    
                    return [TextContent(type="text", text=f"Result: {result}")]
                except Exception as e:
                    return [TextContent(type="text", text=f"Error: {str(e)}")]
            else:
                raise ValueError(f"Unknown tool: {name}")

# Create bridge instance
bridge = MCPHTTPBridge()

@app.route('/mcp', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/mcp/', methods=['GET', 'POST', 'OPTIONS'])
def mcp_endpoint():
    """MCP HTTP endpoint using official SDK"""
    
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        return response
    
    if request.method == 'GET':
        return jsonify({
            'name': 'Official MCP Server',
            'version': '1.0.0',
            'protocolVersion': '2024-11-05',
            'capabilities': {
                'tools': {'listChanged': True},
                'resources': {'subscribe': True, 'listChanged': True}
            },
            'serverInfo': {
                'name': 'flask-mcp-server',
                'version': '1.0.0'
            },
            'transport': 'http',
            'tools': [
                {
                    'name': 'echo',
                    'description': 'Echo back the input message',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'message': {'type': 'string', 'description': 'Message to echo'}
                        },
                        'required': ['message']
                    }
                },
                {
                    'name': 'system_info',
                    'description': 'Get system information',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {},
                        'required': []
                    }
                },
                {
                    'name': 'calculator',
                    'description': 'Calculate mathematical expressions',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'expression': {'type': 'string', 'description': 'Math expression'}
                        },
                        'required': ['expression']
                    }
                }
            ]
        })
    
    # Handle POST - JSON-RPC
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'jsonrpc': '2.0',
                'error': {'code': -32700, 'message': 'Parse error'},
                'id': None
            }), 400
        
        method = data.get('method')
        params = data.get('params', {})
        request_id = data.get('id')
        
        if method == 'initialize':
            result = {
                'protocolVersion': '2024-11-05',
                'capabilities': {
                    'tools': {'listChanged': True},
                    'resources': {'subscribe': True, 'listChanged': True}
                },
                'serverInfo': {
                    'name': 'flask-mcp-server',
                    'version': '1.0.0'
                }
            }
            return jsonify({'jsonrpc': '2.0', 'result': result, 'id': request_id})
        
        elif method == 'tools/list':
            tools_list = asyncio.run(bridge.server._handlers['tools/list']())
            tools_json = []
            for tool in tools_list:
                tools_json.append({
                    'name': tool.name,
                    'description': tool.description,
                    'inputSchema': tool.inputSchema
                })
            
            return jsonify({
                'jsonrpc': '2.0',
                'result': {'tools': tools_json},
                'id': request_id
            })
        
        elif method == 'tools/call':
            tool_name = params.get('name')
            arguments = params.get('arguments', {})
            
            try:
                result_content = asyncio.run(
                    bridge.server._handlers['tools/call'](tool_name, arguments)
                )
                
                content_list = []
                for item in result_content:
                    content_list.append({
                        'type': item.type,
                        'text': item.text
                    })
                
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {'content': content_list},
                    'id': request_id
                })
            except Exception as e:
                return jsonify({
                    'jsonrpc': '2.0',
                    'error': {'code': -32602, 'message': str(e)},
                    'id': request_id
                }), 400
        
        else:
            return jsonify({
                'jsonrpc': '2.0',
                'error': {'code': -32601, 'message': 'Method not found'},
                'id': request_id
            }), 404
            
    except Exception as e:
        logger.error(f"MCP error: {e}")
        return jsonify({
            'jsonrpc': '2.0',
            'error': {'code': -32603, 'message': 'Internal error'},
            'id': request_id
        }), 500

if __name__ == '__main__':
    logger.info("Starting MCP HTTP Bridge Server...")
    app.run(host='0.0.0.0', port=5003, debug=True)