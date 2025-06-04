#!/usr/bin/env python3
"""
MCP Server using official Python SDK with Streamable HTTP transport
Direct implementation without Flask wrappers
"""

import asyncio
import logging
import platform
import psutil
import ast
import operator
from typing import Any, Sequence

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.sse import SseServerTransport
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
from pydantic import AnyUrl

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server instance
server = Server("flask-mcp-server")

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available tools for Claude.ai"""
    return [
        Tool(
            name="echo",
            description="Echo back the input message using official MCP SDK",
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
            description="Get comprehensive system information with real-time metrics",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="calculator",
            description="Perform safe mathematical calculations with AST parsing",
            inputSchema={
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "Mathematical expression to evaluate (supports +, -, *, /, **, parentheses)"
                    }
                },
                "required": ["expression"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent | ImageContent | EmbeddedResource]:
    """Handle tool calls from Claude.ai"""
    
    if name == "echo":
        message = arguments.get("message", "")
        return [
            TextContent(
                type="text",
                text=f"Echo (Official MCP SDK): {message}"
            )
        ]
    
    elif name == "system_info":
        try:
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            boot_time = psutil.boot_time()
            
            system_info = f"""System Information (Real-time):
OS: {platform.system()} {platform.release()} ({platform.architecture()[0]})
Machine: {platform.machine()}
Processor: {platform.processor()}
Python: {platform.python_version()}

CPU Information:
Cores: {cpu_count} physical
Frequency: {cpu_freq.current if cpu_freq else 'N/A'} MHz
Usage: {psutil.cpu_percent(interval=1)}%

Memory Information:
Total: {memory.total // (1024**3)} GB
Available: {memory.available // (1024**3)} GB  
Used: {memory.used // (1024**3)} GB ({memory.percent}%)

Disk Information:
Total: {disk.total // (1024**3)} GB
Free: {disk.free // (1024**3)} GB
Used: {disk.used // (1024**3)} GB ({(disk.used / disk.total) * 100:.1f}%)

System Uptime: {(psutil.time.time() - boot_time) / 3600:.1f} hours"""
            
            return [
                TextContent(
                    type="text",
                    text=system_info
                )
            ]
        except Exception as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error getting system info: {str(e)}"
                )
            ]
    
    elif name == "calculator":
        expression = arguments.get("expression", "")
        
        try:
            # Safe mathematical evaluation using AST
            def safe_eval(node):
                if isinstance(node, ast.Constant):
                    return node.value
                elif isinstance(node, ast.BinOp):
                    return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
                elif isinstance(node, ast.UnaryOp):
                    return ops[type(node.op)](safe_eval(node.operand))
                elif isinstance(node, ast.Name):
                    # Allow mathematical constants
                    if node.id in constants:
                        return constants[node.id]
                    else:
                        raise ValueError(f"Undefined variable: {node.id}")
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
            
            # Mathematical constants
            constants = {
                'pi': 3.141592653589793,
                'e': 2.718281828459045,
            }
            
            # Parse and evaluate
            tree = ast.parse(expression, mode='eval')
            result = safe_eval(tree.body)
            
            return [
                TextContent(
                    type="text",
                    text=f"Expression: {expression}\nResult: {result}"
                )
            ]
            
        except Exception as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error calculating '{expression}': {str(e)}"
                )
            ]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """List available resources"""
    return [
        Resource(
            uri=AnyUrl("memory://system/info"),
            name="Real-time System Information",
            description="Live system status and metrics",
            mimeType="text/plain"
        ),
        Resource(
            uri=AnyUrl("memory://system/processes"),
            name="System Processes",
            description="Current running processes information",
            mimeType="application/json"
        )
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """Read resource content"""
    if str(uri) == "memory://system/info":
        try:
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            
            return f"""Real-time System Status:
OS: {platform.system()} {platform.release()}
CPU: {cpu_count} cores, {psutil.cpu_percent()}% usage
Memory: {memory.total // (1024**3)} GB total, {memory.percent}% used
Load Average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}
Python: {platform.python_version()}
Timestamp: {psutil.time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        except Exception as e:
            return f"Error reading system info: {str(e)}"
    
    elif str(uri) == "memory://system/processes":
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage and get top 10
            top_processes = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:10]
            
            import json
            return json.dumps({
                "timestamp": psutil.time.strftime('%Y-%m-%d %H:%M:%S'),
                "total_processes": len(processes),
                "top_processes": top_processes
            }, indent=2)
            
        except Exception as e:
            return f'{{"error": "Failed to read processes: {str(e)}"}}'
    
    else:
        raise ValueError(f"Unknown resource: {uri}")

async def main():
    """Run the MCP server with SSE transport"""
    logger.info("Starting MCP Server with SSE transport...")
    
    # Create SSE transport
    async with SseServerTransport("/messages") as streams:
        await server.run(
            streams[0], streams[1],
            InitializationOptions(
                server_name="mcp-streamable-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())