"""
MCP Server implementation specifically optimized for Claude.ai integration
"""
import json
import logging
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import time
import threading
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ClaudeMCPServer:
    """MCP Server optimized for Claude.ai"""
    
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        self.tools = self._get_default_tools()
        self.setup_routes()
        
    def _get_default_tools(self):
        """Get default tool definitions"""
        return [
            {
                "name": "echo",
                "description": "Echo back the input message",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Message to echo back"
                        }
                    },
                    "required": ["message"]
                }
            },
            {
                "name": "system_info",
                "description": "Get system information",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "calculator",
                "description": "Perform basic mathematical calculations",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "Mathematical expression to evaluate"
                        }
                    },
                    "required": ["expression"]
                }
            }
        ]
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/mcp', methods=['GET', 'POST', 'OPTIONS'])
        def mcp_endpoint():
            if request.method == 'OPTIONS':
                response = Response()
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                return response
                
            if request.method == 'GET':
                # Return server information
                return jsonify({
                    "name": "Claude MCP Server",
                    "version": "1.0.0",
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True, "listChanged": True}
                    },
                    "serverInfo": {
                        "name": "Flask MCP Server",
                        "version": "1.0.0"
                    },
                    "transport": "http",
                    "tools_count": len(self.tools)
                })
                
            # Handle POST requests (MCP JSON-RPC)
            try:
                data = request.get_json()
                if not data:
                    return self._error_response(-32700, "Parse error"), 400
                    
                logger.info(f"MCP Request: {data.get('method', 'unknown')}")
                
                method = data.get('method')
                params = data.get('params', {})
                request_id = data.get('id')
                
                if method == 'initialize':
                    return self._handle_initialize(params, request_id)
                elif method == 'tools/list':
                    return self._handle_tools_list(request_id)
                elif method == 'tools/call':
                    return self._handle_tool_call(params, request_id)
                else:
                    return self._error_response(-32601, "Method not found", request_id), 404
                    
            except Exception as e:
                logger.error(f"MCP request error: {e}")
                return self._error_response(-32603, "Internal error"), 500
    
    def _handle_initialize(self, params: Dict, request_id: Any):
        """Handle MCP initialize request"""
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True, "listChanged": True}
            },
            "serverInfo": {
                "name": "Flask MCP Server",
                "version": "1.0.0"
            }
        }
        return self._success_response(result, request_id)
    
    def _handle_tools_list(self, request_id: Any):
        """Handle tools/list request"""
        result = {
            "tools": self.tools
        }
        return self._success_response(result, request_id)
    
    def _handle_tool_call(self, params: Dict, request_id: Any):
        """Handle tools/call request"""
        tool_name = params.get('name')
        arguments = params.get('arguments', {})
        
        if tool_name == 'echo':
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": f"Echo: {arguments.get('message', '')}"
                    }
                ]
            }
        elif tool_name == 'system_info':
            import platform
            import psutil
            
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": f"System: {platform.system()} {platform.release()}\nCPU: {psutil.cpu_count()} cores\nMemory: {psutil.virtual_memory().total // (1024**3)} GB"
                    }
                ]
            }
        elif tool_name == 'calculator':
            try:
                import ast
                import operator
                
                # Safe evaluation of mathematical expressions
                def eval_expr(node):
                    if isinstance(node, ast.Constant):
                        return node.value
                    elif isinstance(node, ast.BinOp):
                        return ops[type(node.op)](eval_expr(node.left), eval_expr(node.right))
                    elif isinstance(node, ast.UnaryOp):
                        return ops[type(node.op)](eval_expr(node.operand))
                    else:
                        raise TypeError(node)
                
                ops = {
                    ast.Add: operator.add,
                    ast.Sub: operator.sub,
                    ast.Mult: operator.mul,
                    ast.Div: operator.truediv,
                    ast.Pow: operator.pow,
                    ast.USub: operator.neg,
                }
                
                expression = arguments.get('expression', '')
                tree = ast.parse(expression, mode='eval')
                calc_result = eval_expr(tree.body)
                
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Result: {calc_result}"
                        }
                    ]
                }
            except Exception as e:
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error: {str(e)}"
                        }
                    ]
                }
        else:
            return self._error_response(-32602, f"Unknown tool: {tool_name}", request_id), 400
            
        return self._success_response(result, request_id)
    
    def _success_response(self, result: Any, request_id: Any = None):
        """Create success response"""
        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id
        }
        return jsonify(response)
    
    def _error_response(self, code: int, message: str, request_id: Any = None):
        """Create error response"""
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            },
            "id": request_id
        }
        return jsonify(response)

# Create server instance
claude_mcp_server = ClaudeMCPServer()

if __name__ == '__main__':
    claude_mcp_server.app.run(host='0.0.0.0', port=5001, debug=True)