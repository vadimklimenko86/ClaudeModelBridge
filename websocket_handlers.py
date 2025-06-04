"""
WebSocket handlers for MCP protocol communication with Claude.ai
"""
import json
import logging
from flask import current_app
from flask_socketio import emit, disconnect
import platform
import ast
import operator

logger = logging.getLogger(__name__)

def handle_mcp_message(data):
    """Handle incoming MCP JSON-RPC messages over WebSocket"""
    try:
        if not isinstance(data, dict):
            data = json.loads(data)
        
        logger.info(f"WebSocket MCP message: {data.get('method', 'unknown')}")
        
        method = data.get('method')
        params = data.get('params', {})
        request_id = data.get('id')
        
        if method == 'initialize':
            result = {
                'protocolVersion': '2025-03-26',
                'capabilities': {
                    'tools': {'listChanged': True},
                    'resources': {'subscribe': True, 'listChanged': True},
                    'logging': {},
                    'prompts': {'listChanged': True}
                },
                'serverInfo': {
                    'name': 'Flask MCP Server',
                    'version': '1.0.0'
                }
            }
        elif method == 'tools/list':
            result = {
                'tools': [
                    {
                        'name': 'echo',
                        'description': 'Echo back the input message',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'message': {
                                    'type': 'string',
                                    'description': 'Message to echo back'
                                }
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
                        'description': 'Perform basic mathematical calculations',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'expression': {
                                    'type': 'string',
                                    'description': 'Mathematical expression to evaluate'
                                }
                            },
                            'required': ['expression']
                        }
                    }
                ]
            }
        elif method == 'tools/call':
            tool_name = params.get('name')
            arguments = params.get('arguments', {})
            
            if tool_name == 'echo':
                result = {
                    'content': [
                        {
                            'type': 'text',
                            'text': f"Echo: {arguments.get('message', '')}"
                        }
                    ]
                }
            elif tool_name == 'system_info':
                result = {
                    'content': [
                        {
                            'type': 'text',
                            'text': f"System: {platform.system()} {platform.release()}\nPython: {platform.python_version()}\nArchitecture: {platform.machine()}"
                        }
                    ]
                }
            elif tool_name == 'calculator':
                try:
                    expression = arguments.get('expression', '')
                    # Safe evaluation of basic math expressions
                    ops = {
                        ast.Add: operator.add,
                        ast.Sub: operator.sub,
                        ast.Mult: operator.mul,
                        ast.Div: operator.truediv,
                        ast.Pow: operator.pow,
                        ast.USub: operator.neg,
                    }
                    
                    def eval_expr(node):
                        if isinstance(node, ast.Num):
                            return node.n
                        elif isinstance(node, ast.BinOp):
                            return ops[type(node.op)](eval_expr(node.left), eval_expr(node.right))
                        elif isinstance(node, ast.UnaryOp):
                            return ops[type(node.op)](eval_expr(node.operand))
                        else:
                            raise TypeError(node)
                    
                    tree = ast.parse(expression, mode='eval')
                    calc_result = eval_expr(tree.body)
                    
                    result = {
                        'content': [
                            {
                                'type': 'text',
                                'text': f"Result: {expression} = {calc_result}"
                            }
                        ]
                    }
                except Exception as e:
                    result = {
                        'content': [
                            {
                                'type': 'text',
                                'text': f"Error calculating '{expression}': {str(e)}"
                            }
                        ]
                    }
            else:
                emit('mcp_response', {
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32601,
                        'message': f'Unknown tool: {tool_name}'
                    },
                    'id': request_id
                })
                return
        else:
            emit('mcp_response', {
                'jsonrpc': '2.0',
                'error': {
                    'code': -32601,
                    'message': f'Method not found: {method}'
                },
                'id': request_id
            })
            return

        response_data = {
            'jsonrpc': '2.0',
            'result': result,
            'id': request_id
        }
        
        emit('mcp_response', response_data)
        
    except Exception as e:
        logger.error(f"WebSocket MCP error: {str(e)}")
        emit('mcp_response', {
            'jsonrpc': '2.0',
            'error': {
                'code': -32603,
                'message': f'Internal error: {str(e)}'
            },
            'id': data.get('id') if isinstance(data, dict) else None
        })

def handle_connect():
    """Handle WebSocket connection"""
    logger.info("Claude.ai WebSocket client connected")
    
    # Send initial server capabilities
    emit('mcp_notification', {
        'jsonrpc': '2.0',
        'method': 'notifications/initialized',
        'params': {}
    })

def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info("Claude.ai WebSocket client disconnected")