#!/usr/bin/env python3
"""
Direct MCP Server using official Python SDK with HTTP transport
No Flask/FastAPI wrappers - pure MCP implementation
"""

import asyncio
import logging
import platform
import psutil
import ast
import operator
import time
from typing import Any, Sequence

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
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
server = Server("mcp-direct-server")

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available tools for Claude.ai"""
    return [
        Tool(
            name="echo",
            description="Echo back the input message using official MCP SDK v1.9.2",
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
            description="Get comprehensive real-time system information with metrics",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="calculator",
            description="Perform safe mathematical calculations with AST parsing support",
            inputSchema={
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "Mathematical expression to evaluate (supports +, -, *, /, **, parentheses, pi, e)"
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
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        return [
            TextContent(
                type="text",
                text=f"Echo (Official MCP SDK v1.9.2) [{timestamp}]: {message}"
            )
        ]
    
    elif name == "system_info":
        try:
            # CPU information
            cpu_count = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory information
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk information
            disk = psutil.disk_usage('/')
            
            # Network information
            net_io = psutil.net_io_counters()
            
            # System information
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_hours = uptime_seconds / 3600
            
            # Load average (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()
                load_info = f"Load Average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}"
            except AttributeError:
                load_info = "Load Average: Not available on this system"
            
            system_info = f"""Real-time System Information:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Operating System:
• OS: {platform.system()} {platform.release()} ({platform.architecture()[0]})
• Machine: {platform.machine()}
• Processor: {platform.processor() or 'Unknown'}
• Python: {platform.python_version()}
• Node: {platform.node()}

CPU Information:
• Physical Cores: {cpu_count}
• Logical Cores: {cpu_count_logical}
• Frequency: {cpu_freq.current if cpu_freq else 'N/A'} MHz (Max: {cpu_freq.max if cpu_freq else 'N/A'} MHz)
• Current Usage: {cpu_percent}%

Memory Information:
• Total RAM: {memory.total // (1024**3)} GB ({memory.total // (1024**2)} MB)
• Available: {memory.available // (1024**3)} GB ({memory.percent:.1f}% used)
• Used: {memory.used // (1024**3)} GB
• Swap Total: {swap.total // (1024**3)} GB ({swap.percent:.1f}% used)

Storage Information:
• Total Disk: {disk.total // (1024**3)} GB
• Free Space: {disk.free // (1024**3)} GB
• Used Space: {disk.used // (1024**3)} GB ({(disk.used / disk.total) * 100:.1f}%)

Network Information:
• Bytes Sent: {net_io.bytes_sent // (1024**2)} MB
• Bytes Received: {net_io.bytes_recv // (1024**2)} MB
• Packets Sent: {net_io.packets_sent:,}
• Packets Received: {net_io.packets_recv:,}

System Status:
• {load_info}
• Uptime: {uptime_hours:.1f} hours ({int(uptime_seconds // 86400)} days)
• Boot Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(boot_time))}
• Current Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            
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
                    text=f"Error retrieving system information: {str(e)}"
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
                elif isinstance(node, ast.Call):
                    # Allow mathematical functions
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
                ast.Mod: operator.mod,
            }
            
            # Mathematical constants
            constants = {
                'pi': 3.141592653589793,
                'e': 2.718281828459045,
                'tau': 6.283185307179586,
            }
            
            # Mathematical functions
            import math
            functions = {
                'sqrt': math.sqrt,
                'sin': math.sin,
                'cos': math.cos,
                'tan': math.tan,
                'log': math.log,
                'log10': math.log10,
                'abs': abs,
                'round': round,
            }
            
            # Parse and evaluate
            tree = ast.parse(expression, mode='eval')
            result = safe_eval(tree.body)
            
            # Format result nicely
            if isinstance(result, float):
                if result.is_integer():
                    result_str = str(int(result))
                else:
                    result_str = f"{result:.10f}".rstrip('0').rstrip('.')
            else:
                result_str = str(result)
            
            return [
                TextContent(
                    type="text",
                    text=f"""Mathematical Calculation:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Expression: {expression}
Result: {result_str}
Type: {type(result).__name__}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
                )
            ]
            
        except Exception as e:
            return [
                TextContent(
                    type="text",
                    text=f"""Calculation Error:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Expression: {expression}
Error: {str(e)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Supported operations: +, -, *, /, **, %, ()
Supported functions: sqrt, sin, cos, tan, log, log10, abs, round
Supported constants: pi, e, tau"""
                )
            ]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """List available resources"""
    return [
        Resource(
            uri=AnyUrl("memory://system/realtime"),
            name="Real-time System Metrics",
            description="Live system status, CPU, memory, and disk metrics",
            mimeType="text/plain"
        ),
        Resource(
            uri=AnyUrl("memory://system/processes"),
            name="Active System Processes",
            description="Current running processes with resource usage",
            mimeType="application/json"
        ),
        Resource(
            uri=AnyUrl("memory://system/network"),
            name="Network Statistics",
            description="Network interface statistics and connections",
            mimeType="application/json"
        )
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """Read resource content"""
    if str(uri) == "memory://system/realtime":
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return f"""Real-time System Metrics [{time.strftime('%Y-%m-%d %H:%M:%S')}]:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CPU Usage: {cpu_percent}%
Memory Usage: {memory.percent}% ({memory.used // (1024**3)} GB / {memory.total // (1024**3)} GB)
Disk Usage: {(disk.used / disk.total) * 100:.1f}% ({disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB)

OS: {platform.system()} {platform.release()}
Python: {platform.python_version()}
Machine: {platform.machine()}
"""
        except Exception as e:
            return f"Error reading real-time metrics: {str(e)}"
    
    elif str(uri) == "memory://system/processes":
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    info = proc.info
                    if info['cpu_percent'] is not None and info['cpu_percent'] > 0:
                        processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage and get top 15
            top_processes = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:15]
            
            import json
            return json.dumps({
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "total_processes": len(processes),
                "active_processes": len([p for p in processes if p['cpu_percent'] > 0]),
                "top_processes_by_cpu": top_processes
            }, indent=2)
            
        except Exception as e:
            return f'{{"error": "Failed to read processes: {str(e)}"}}'
    
    elif str(uri) == "memory://system/network":
        try:
            net_io = psutil.net_io_counters()
            net_connections = len(psutil.net_connections())
            
            import json
            return json.dumps({
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "io_counters": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "errin": net_io.errin,
                    "errout": net_io.errout,
                    "dropin": net_io.dropin,
                    "dropout": net_io.dropout
                },
                "active_connections": net_connections
            }, indent=2)
            
        except Exception as e:
            return f'{{"error": "Failed to read network stats: {str(e)}"}}'
    
    else:
        raise ValueError(f"Unknown resource: {uri}")

async def main():
    """Run the direct MCP server"""
    logger.info("Starting Direct MCP Server (Official SDK v1.9.2)...")
    logger.info("Protocol Version: 2024-11-05")
    logger.info("Transport: stdio")
    
    # Run the server using stdio transport (official method)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-direct-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities()
            )
        )

if __name__ == "__main__":
    asyncio.run(main())