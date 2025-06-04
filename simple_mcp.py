"""
Simple MCP Server for Claude.ai integration
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/mcp', methods=['GET', 'POST', 'OPTIONS'])
def mcp_endpoint():
    """MCP endpoint for Claude.ai"""
    
    # Handle CORS
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        return response
    
    # GET request - server info
    if request.method == 'GET':
        return jsonify({
            "name": "Simple MCP Server",
            "version": "1.0.0",
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True}
            },
            "serverInfo": {
                "name": "Simple MCP Server",
                "version": "1.0.0"
            }
        })
    
    # POST request - JSON-RPC
    try:
        data = request.get_json()
        logger.info(f"MCP request: {data}")
        
        method = data.get('method')
        params = data.get('params', {})
        request_id = data.get('id')
        
        if method == 'initialize':
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True}
                },
                "serverInfo": {
                    "name": "Simple MCP Server",
                    "version": "1.0.0"
                }
            }
            return jsonify({
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id
            })
        
        elif method == 'tools/list':
            tools = [
                {
                    "name": "echo",
                    "description": "Echo back the input message",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string", "description": "Message to echo"}
                        },
                        "required": ["message"]
                    }
                },
                {
                    "name": "calculator",
                    "description": "Calculate mathematical expressions",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string", "description": "Math expression"}
                        },
                        "required": ["expression"]
                    }
                }
            ]
            return jsonify({
                "jsonrpc": "2.0",
                "result": {"tools": tools},
                "id": request_id
            })
        
        elif method == 'tools/call':
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
            elif tool_name == 'calculator':
                try:
                    expr = arguments.get('expression', '')
                    # Safe eval for basic math
                    result_val = eval(expr, {"__builtins__": {}}, {})
                    result = {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Result: {result_val}"
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
                return jsonify({
                    "jsonrpc": "2.0",
                    "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
                    "id": request_id
                }), 400
            
            return jsonify({
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id
            })
        
        else:
            return jsonify({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method not found"},
                "id": request_id
            }), 404
            
    except Exception as e:
        logger.error(f"MCP error: {e}")
        return jsonify({
            "jsonrpc": "2.0",
            "error": {"code": -32603, "message": "Internal error"},
            "id": request_id
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)