#!/usr/bin/env python3
"""
Direct MCP Server for Claude.ai Integration
Using Official Python SDK with stdio transport
"""

import asyncio
import logging
import json
import time
import platform
import psutil
import ast
import operator
import math
from typing import Any, Sequence
from pathlib import Path

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp import types

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the server
server = Server("claude-mcp-server")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """Return list of available tools"""
    return [
        types.Tool(
            name="echo",
            description="Echo back any message with timestamp",
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
        types.Tool(
            name="system_info",
            description="Get real-time system information and metrics",
            inputSchema={
                "type": "object",
                "properties": {
                    "detail_level": {
                        "type": "string",
                        "enum": ["basic", "detailed", "full"],
                        "description": "Level of system detail to return",
                        "default": "detailed"
                    }
                }
            }
        ),
        types.Tool(
            name="calculator",
            description="Perform mathematical calculations safely",
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

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Handle tool calls"""
    
    if name == "echo":
        message = arguments.get("message", "")
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        
        response = {
            "original_message": message,
            "timestamp": timestamp,
            "server": "Claude MCP Server",
            "sdk_version": "1.9.2",
            "protocol_version": "2024-11-05"
        }
        
        return [types.TextContent(
            type="text",
            text=json.dumps(response, indent=2)
        )]
    
    elif name == "system_info":
        detail_level = arguments.get("detail_level", "detailed")
        
        try:
            info = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                "detail_level": detail_level,
                "system": {
                    "platform": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python_version": platform.python_version()
                }
            }
            
            if detail_level in ["detailed", "full"]:
                # CPU info
                info["cpu"] = {
                    "physical_cores": psutil.cpu_count(logical=False),
                    "logical_cores": psutil.cpu_count(logical=True),
                    "usage_percent": psutil.cpu_percent(interval=1)
                }
                
                # Memory info  
                memory = psutil.virtual_memory()
                info["memory"] = {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "used_percent": memory.percent
                }
                
                # Disk info
                disk = psutil.disk_usage('/')
                info["disk"] = {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "used_percent": round((disk.used / disk.total) * 100, 1)
                }
            
            if detail_level == "full":
                # Network info
                net_io = psutil.net_io_counters()
                info["network"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                }
                
                # Boot time
                boot_time = psutil.boot_time()
                info["uptime"] = {
                    "boot_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(boot_time)),
                    "uptime_hours": round((time.time() - boot_time) / 3600, 1)
                }
            
            return [types.TextContent(
                type="text",
                text=json.dumps(info, indent=2)
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text", 
                text=f"Error gathering system information: {str(e)}"
            )]
    
    elif name == "calculator":
        expression = arguments.get("expression", "")
        
        try:
            # Safe mathematical evaluation
            def safe_eval(node):
                if isinstance(node, ast.Constant):
                    return node.value
                elif isinstance(node, ast.BinOp):
                    return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
                elif isinstance(node, ast.UnaryOp):
                    return ops[type(node.op)](safe_eval(node.operand))
                elif isinstance(node, ast.Name):
                    if node.id in constants:
                        return constants[node.id]
                    else:
                        raise ValueError(f"Undefined variable: {node.id}")
                elif isinstance(node, ast.Call):
                    func_name = node.func.id if isinstance(node.func, ast.Name) else None
                    if func_name in functions:
                        args = [safe_eval(arg) for arg in node.args]
                        return functions[func_name](*args)
                    else:
                        raise ValueError(f"Undefined function: {func_name}")
                else:
                    raise TypeError(f"Unsupported operation: {type(node).__name__}")
            
            # Supported operations
            ops = {
                ast.Add: operator.add,
                ast.Sub: operator.sub, 
                ast.Mult: operator.mul,
                ast.Div: operator.truediv,
                ast.Pow: operator.pow,
                ast.USub: operator.neg,
            }
            
            # Constants
            constants = {
                'pi': math.pi,
                'e': math.e,
            }
            
            # Functions
            functions = {
                'sqrt': math.sqrt,
                'sin': math.sin,
                'cos': math.cos,
                'tan': math.tan,
                'log': math.log,
                'exp': math.exp,
                'abs': abs,
                'round': round,
            }
            
            # Parse and evaluate
            tree = ast.parse(expression, mode='eval')
            result = safe_eval(tree.body)
            
            response = {
                "expression": expression,
                "result": result,
                "type": type(result).__name__
            }
            
            return [types.TextContent(
                type="text",
                text=json.dumps(response, indent=2)
            )]
            
        except Exception as e:
            error_response = {
                "expression": expression,
                "error": str(e),
                "supported_operations": ["+", "-", "*", "/", "**", "()"],
                "supported_functions": ["sqrt", "sin", "cos", "tan", "log", "exp", "abs", "round"],
                "supported_constants": ["pi", "e"]
            }
            return [types.TextContent(
                type="text",
                text=json.dumps(error_response, indent=2)
            )]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """Return list of available resources"""
    return [
        types.Resource(
            uri="system://metrics/realtime",
            name="Real-time System Metrics",
            description="Current system performance metrics",
            mimeType="application/json"
        ),
        types.Resource(
            uri="system://info/platform", 
            name="Platform Information",
            description="Operating system and platform details",
            mimeType="application/json"
        )
    ]

@server.read_resource()
async def handle_read_resource(uri: types.AnyUrl) -> str:
    """Read resource content"""
    uri_str = str(uri)
    
    if uri_str == "system://metrics/realtime":
        try:
            metrics = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": round((psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100, 1),
                "load_average": list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else None
            }
            return json.dumps(metrics, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    elif uri_str == "system://info/platform":
        try:
            info = {
                "platform": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "hostname": platform.node()
            }
            return json.dumps(info, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    else:
        raise ValueError(f"Unknown resource: {uri}")

async def main():
    """Main entry point for stdio server"""
    logger.info("Starting Claude MCP Server with stdio transport")
    logger.info("Protocol Version: 2024-11-05")
    logger.info("SDK Version: 1.9.2")
    
    # Use stdio server transport
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="claude-mcp-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities()
            )
        )

if __name__ == "__main__":
    asyncio.run(main())