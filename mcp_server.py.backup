#!/usr/bin/env python3
"""
Remote MCP Server using Official Python SDK v1.9.2
Supports all transports: stdio, SSE, WebSocket for Claude.ai compatibility
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
from typing import Any, Sequence, Dict, List
from pathlib import Path

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    Prompt,
    PromptMessage,
    GetPromptResult,
)
from pydantic import AnyUrl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RemoteMCPServer:
    """Remote MCP Server with full protocol support"""
    
    def __init__(self, name: str = "remote-mcp-server"):
        self.server = Server(name)
        self.setup_handlers()
        
    def setup_handlers(self):
        """Setup all MCP protocol handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List all available tools"""
            return [
                Tool(
                    name="echo",
                    description="Echo back any message with timestamp and metadata",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Message to echo back"
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional metadata to include",
                                "properties": {
                                    "priority": {"type": "string", "enum": ["low", "medium", "high"]},
                                    "category": {"type": "string"}
                                }
                            }
                        },
                        "required": ["message"]
                    }
                ),
                Tool(
                    name="system_monitor",
                    description="Get comprehensive real-time system monitoring data",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detail_level": {
                                "type": "string",
                                "enum": ["basic", "detailed", "full"],
                                "description": "Level of detail for system information",
                                "default": "detailed"
                            },
                            "include_processes": {
                                "type": "boolean",
                                "description": "Include running processes information",
                                "default": False
                            }
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="calculator",
                    description="Advanced mathematical calculator with functions and constants",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "expression": {
                                "type": "string",
                                "description": "Mathematical expression to evaluate"
                            },
                            "precision": {
                                "type": "integer",
                                "description": "Number of decimal places for result",
                                "default": 10,
                                "minimum": 0,
                                "maximum": 15
                            }
                        },
                        "required": ["expression"]
                    }
                ),
                Tool(
                    name="file_operations",
                    description="Safe file system operations (read, list, info)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "enum": ["read", "list", "info", "exists"],
                                "description": "File operation to perform"
                            },
                            "path": {
                                "type": "string",
                                "description": "File or directory path"
                            },
                            "encoding": {
                                "type": "string",
                                "description": "Text encoding for read operations",
                                "default": "utf-8"
                            }
                        },
                        "required": ["operation", "path"]
                    }
                ),
                Tool(
                    name="network_info",
                    description="Get network interface and connectivity information",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "include_stats": {
                                "type": "boolean",
                                "description": "Include network I/O statistics",
                                "default": True
                            }
                        },
                        "required": []
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[TextContent | ImageContent | EmbeddedResource]:
            """Handle tool execution"""
            
            if name == "echo":
                message = arguments.get("message", "")
                metadata = arguments.get("metadata", {})
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
                
                response = {
                    "original_message": message,
                    "timestamp": timestamp,
                    "metadata": metadata,
                    "server_info": {
                        "name": self.server.name,
                        "protocol_version": "2024-11-05",
                        "sdk_version": "1.9.2"
                    }
                }
                
                return [TextContent(
                    type="text",
                    text=f"Echo Response:\n{json.dumps(response, indent=2)}"
                )]
            
            elif name == "system_monitor":
                detail_level = arguments.get("detail_level", "detailed")
                include_processes = arguments.get("include_processes", False)
                
                return [TextContent(
                    type="text",
                    text=await self._get_system_info(detail_level, include_processes)
                )]
            
            elif name == "calculator":
                expression = arguments.get("expression", "")
                precision = arguments.get("precision", 10)
                
                return [TextContent(
                    type="text",
                    text=await self._calculate_expression(expression, precision)
                )]
            
            elif name == "file_operations":
                operation = arguments.get("operation")
                path = arguments.get("path")
                encoding = arguments.get("encoding", "utf-8")
                
                return [TextContent(
                    type="text",
                    text=await self._handle_file_operation(operation, path, encoding)
                )]
            
            elif name == "network_info":
                include_stats = arguments.get("include_stats", True)
                
                return [TextContent(
                    type="text",
                    text=await self._get_network_info(include_stats)
                )]
            
            else:
                raise ValueError(f"Unknown tool: {name}")
        
        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available resources"""
            return [
                Resource(
                    uri=AnyUrl("system://monitor/realtime"),
                    name="Real-time System Monitor",
                    description="Live system metrics and performance data",
                    mimeType="application/json"
                ),
                Resource(
                    uri=AnyUrl("system://processes/active"),
                    name="Active Processes",
                    description="Currently running system processes",
                    mimeType="application/json"
                ),
                Resource(
                    uri=AnyUrl("system://network/interfaces"),
                    name="Network Interfaces",
                    description="Network interface configuration and statistics",
                    mimeType="application/json"
                ),
                Resource(
                    uri=AnyUrl("system://logs/recent"),
                    name="Recent System Logs",
                    description="Recent system and application logs",
                    mimeType="text/plain"
                )
            ]
        
        @self.server.read_resource()
        async def handle_read_resource(uri: AnyUrl) -> str:
            """Read resource content"""
            uri_str = str(uri)
            
            if uri_str == "system://monitor/realtime":
                data = await self._get_realtime_metrics()
                return json.dumps(data, indent=2)
            
            elif uri_str == "system://processes/active":
                data = await self._get_active_processes()
                return json.dumps(data, indent=2)
            
            elif uri_str == "system://network/interfaces":
                data = await self._get_network_interfaces()
                return json.dumps(data, indent=2)
            
            elif uri_str == "system://logs/recent":
                return await self._get_recent_logs()
            
            else:
                raise ValueError(f"Unknown resource: {uri}")
        
        @self.server.list_prompts()
        async def handle_list_prompts() -> List[Prompt]:
            """List available prompts"""
            return [
                Prompt(
                    name="system_analysis",
                    description="Analyze current system performance and provide recommendations",
                    arguments=[
                        {
                            "name": "focus_area",
                            "description": "Area to focus analysis on",
                            "required": False
                        }
                    ]
                ),
                Prompt(
                    name="troubleshoot",
                    description="Help troubleshoot system issues",
                    arguments=[
                        {
                            "name": "symptoms",
                            "description": "Symptoms or issues observed",
                            "required": True
                        }
                    ]
                )
            ]
        
        @self.server.get_prompt()
        async def handle_get_prompt(name: str, arguments: dict) -> GetPromptResult:
            """Get prompt content"""
            
            if name == "system_analysis":
                focus_area = arguments.get("focus_area", "general")
                system_data = await self._get_system_info("full", True)
                
                prompt_text = f"""System Analysis Request

Focus Area: {focus_area}

Current System State:
{system_data}

Please analyze this system information and provide:
1. Performance assessment
2. Potential issues or bottlenecks
3. Optimization recommendations
4. Security considerations

Focus your analysis on the {focus_area} aspects if specified."""
                
                return GetPromptResult(
                    description=f"System analysis focused on {focus_area}",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(type="text", text=prompt_text)
                        )
                    ]
                )
            
            elif name == "troubleshoot":
                symptoms = arguments.get("symptoms", "")
                system_data = await self._get_system_info("detailed", False)
                
                prompt_text = f"""Troubleshooting Request

Reported Symptoms:
{symptoms}

Current System Information:
{system_data}

Please help troubleshoot these symptoms by:
1. Analyzing the provided system information
2. Identifying potential root causes
3. Suggesting diagnostic steps
4. Recommending solutions or workarounds"""
                
                return GetPromptResult(
                    description="System troubleshooting assistance",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(type="text", text=prompt_text)
                        )
                    ]
                )
            
            else:
                raise ValueError(f"Unknown prompt: {name}")
    
    async def _get_system_info(self, detail_level: str, include_processes: bool) -> str:
        """Get system information with specified detail level"""
        try:
            info = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                "detail_level": detail_level,
                "system": {
                    "platform": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "node": platform.node(),
                    "python_version": platform.python_version()
                }
            }
            
            if detail_level in ["detailed", "full"]:
                # CPU Information
                info["cpu"] = {
                    "physical_cores": psutil.cpu_count(logical=False),
                    "logical_cores": psutil.cpu_count(logical=True),
                    "current_usage": psutil.cpu_percent(interval=1),
                    "per_cpu_usage": psutil.cpu_percent(interval=1, percpu=True)
                }
                
                if hasattr(psutil, 'cpu_freq'):
                    cpu_freq = psutil.cpu_freq()
                    if cpu_freq:
                        info["cpu"]["frequency"] = {
                            "current": cpu_freq.current,
                            "min": cpu_freq.min,
                            "max": cpu_freq.max
                        }
                
                # Memory Information
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                info["memory"] = {
                    "virtual": {
                        "total": memory.total,
                        "available": memory.available,
                        "used": memory.used,
                        "percentage": memory.percent
                    },
                    "swap": {
                        "total": swap.total,
                        "used": swap.used,
                        "free": swap.free,
                        "percentage": swap.percent
                    }
                }
                
                # Disk Information
                disk_usage = psutil.disk_usage('/')
                info["disk"] = {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free,
                    "percentage": (disk_usage.used / disk_usage.total) * 100
                }
                
                # Network Information
                net_io = psutil.net_io_counters()
                info["network"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                }
            
            if detail_level == "full":
                # Boot time and uptime
                boot_time = psutil.boot_time()
                info["uptime"] = {
                    "boot_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(boot_time)),
                    "uptime_seconds": time.time() - boot_time
                }
                
                # Load average (Unix-like systems)
                if hasattr(psutil, 'getloadavg'):
                    try:
                        load_avg = psutil.getloadavg()
                        info["load_average"] = {
                            "1min": load_avg[0],
                            "5min": load_avg[1],
                            "15min": load_avg[2]
                        }
                    except OSError:
                        pass
            
            if include_processes:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                    try:
                        proc_info = proc.info
                        if proc_info['cpu_percent'] is not None:
                            processes.append(proc_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Sort by CPU usage and get top 20
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                info["top_processes"] = processes[:20]
            
            return json.dumps(info, indent=2)
            
        except Exception as e:
            return f"Error gathering system information: {str(e)}"
    
    async def _calculate_expression(self, expression: str, precision: int) -> str:
        """Calculate mathematical expression safely"""
        try:
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
                ast.Mod: operator.mod,
            }
            
            # Mathematical constants
            constants = {
                'pi': math.pi,
                'e': math.e,
                'tau': math.tau,
                'inf': math.inf,
            }
            
            # Mathematical functions
            functions = {
                'sqrt': math.sqrt,
                'sin': math.sin,
                'cos': math.cos,
                'tan': math.tan,
                'asin': math.asin,
                'acos': math.acos,
                'atan': math.atan,
                'sinh': math.sinh,
                'cosh': math.cosh,
                'tanh': math.tanh,
                'log': math.log,
                'log10': math.log10,
                'log2': math.log2,
                'exp': math.exp,
                'abs': abs,
                'round': round,
                'floor': math.floor,
                'ceil': math.ceil,
                'degrees': math.degrees,
                'radians': math.radians,
            }
            
            # Parse and evaluate
            tree = ast.parse(expression, mode='eval')
            result = safe_eval(tree.body)
            
            # Format result
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
                "precision": precision,
                "supported_functions": list(functions.keys()),
                "supported_constants": list(constants.keys())
            }
            
            return json.dumps(response, indent=2)
            
        except Exception as e:
            error_response = {
                "expression": expression,
                "error": str(e),
                "error_type": type(e).__name__,
                "supported_operations": ["+", "-", "*", "/", "**", "%", "()"],
                "supported_functions": ["sqrt", "sin", "cos", "tan", "log", "exp", "abs", "round", "floor", "ceil"],
                "supported_constants": ["pi", "e", "tau", "inf"]
            }
            return json.dumps(error_response, indent=2)
    
    async def _handle_file_operation(self, operation: str, path: str, encoding: str) -> str:
        """Handle safe file operations"""
        try:
            file_path = Path(path)
            
            if operation == "exists":
                return json.dumps({
                    "path": str(file_path),
                    "exists": file_path.exists(),
                    "is_file": file_path.is_file() if file_path.exists() else False,
                    "is_directory": file_path.is_dir() if file_path.exists() else False
                }, indent=2)
            
            elif operation == "info":
                if not file_path.exists():
                    return json.dumps({"error": "Path does not exist"}, indent=2)
                
                stat = file_path.stat()
                info = {
                    "path": str(file_path),
                    "name": file_path.name,
                    "size": stat.st_size,
                    "modified_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                    "is_file": file_path.is_file(),
                    "is_directory": file_path.is_dir(),
                    "permissions": oct(stat.st_mode)[-3:]
                }
                
                if file_path.is_file():
                    info["suffix"] = file_path.suffix
                
                return json.dumps(info, indent=2)
            
            elif operation == "list":
                if not file_path.exists():
                    return json.dumps({"error": "Directory does not exist"}, indent=2)
                
                if not file_path.is_dir():
                    return json.dumps({"error": "Path is not a directory"}, indent=2)
                
                items = []
                for item in file_path.iterdir():
                    try:
                        stat = item.stat()
                        items.append({
                            "name": item.name,
                            "type": "directory" if item.is_dir() else "file",
                            "size": stat.st_size if item.is_file() else None,
                            "modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
                        })
                    except (PermissionError, OSError):
                        items.append({
                            "name": item.name,
                            "type": "unknown",
                            "error": "Permission denied"
                        })
                
                return json.dumps({
                    "directory": str(file_path),
                    "items": sorted(items, key=lambda x: (x.get("type", ""), x["name"]))
                }, indent=2)
            
            elif operation == "read":
                if not file_path.exists():
                    return json.dumps({"error": "File does not exist"}, indent=2)
                
                if not file_path.is_file():
                    return json.dumps({"error": "Path is not a file"}, indent=2)
                
                # Limit file size for safety
                if file_path.stat().st_size > 1024 * 1024:  # 1MB limit
                    return json.dumps({"error": "File too large (>1MB)"}, indent=2)
                
                try:
                    content = file_path.read_text(encoding=encoding)
                    return json.dumps({
                        "path": str(file_path),
                        "content": content,
                        "size": len(content),
                        "encoding": encoding
                    }, indent=2)
                except UnicodeDecodeError:
                    return json.dumps({"error": f"Cannot decode file with {encoding} encoding"}, indent=2)
            
            else:
                return json.dumps({"error": f"Unknown operation: {operation}"}, indent=2)
                
        except Exception as e:
            return json.dumps({"error": str(e), "error_type": type(e).__name__}, indent=2)
    
    async def _get_network_info(self, include_stats: bool) -> str:
        """Get network information"""
        try:
            info = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                "interfaces": {}
            }
            
            # Network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {"addresses": []}
                
                for addr in addrs:
                    addr_info = {
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    }
                    interface_info["addresses"].append(addr_info)
                
                info["interfaces"][interface] = interface_info
            
            if include_stats:
                # Global network I/O statistics
                net_io = psutil.net_io_counters()
                info["global_stats"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "errin": net_io.errin,
                    "errout": net_io.errout,
                    "dropin": net_io.dropin,
                    "dropout": net_io.dropout
                }
                
                # Per-interface statistics
                net_io_per_nic = psutil.net_io_counters(pernic=True)
                for interface, stats in net_io_per_nic.items():
                    if interface in info["interfaces"]:
                        info["interfaces"][interface]["stats"] = {
                            "bytes_sent": stats.bytes_sent,
                            "bytes_recv": stats.bytes_recv,
                            "packets_sent": stats.packets_sent,
                            "packets_recv": stats.packets_recv
                        }
            
            return json.dumps(info, indent=2)
            
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    async def _get_realtime_metrics(self) -> Dict:
        """Get real-time system metrics"""
        return {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
            "network_io": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            }
        }
    
    async def _get_active_processes(self) -> Dict:
        """Get active processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                proc_info = proc.info
                if proc_info['cpu_percent'] is not None and proc_info['cpu_percent'] > 0:
                    proc_info['create_time'] = time.strftime('%Y-%m-%d %H:%M:%S', 
                                                           time.localtime(proc_info['create_time']))
                    processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "total_processes": len(psutil.pids()),
            "active_processes": len(processes),
            "processes": sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:25]
        }
    
    async def _get_network_interfaces(self) -> Dict:
        """Get network interfaces"""
        interfaces = {}
        
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = {
                "addresses": [
                    {
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask
                    } for addr in addrs
                ]
            }
        
        return {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "interfaces": interfaces
        }
    
    async def _get_recent_logs(self) -> str:
        """Get recent system logs (placeholder)"""
        return f"""System Log Summary - {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

MCP Server Status: Active
Protocol Version: 2024-11-05
SDK Version: 1.9.2

Recent Activity:
- Server initialization completed
- All tools and resources loaded
- Ready for Claude.ai integration

System Health: All systems operational
"""

# Server instances for different transports
stdio_server_instance = RemoteMCPServer("mcp-stdio-server")
sse_server_instance = RemoteMCPServer("mcp-sse-server")

async def run_stdio_server():
    """Run MCP server with stdio transport"""
    logger.info("Starting MCP Server with stdio transport")
    
    async with stdio_server() as (read_stream, write_stream):
        await stdio_server_instance.server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name=stdio_server_instance.server.name,
                server_version="1.0.0",
                capabilities=stdio_server_instance.server.get_capabilities()
            )
        )

async def run_sse_server(host: str = "0.0.0.0", port: int = 8000):
    """Run MCP server with SSE transport"""
    logger.info(f"Starting MCP Server with SSE transport on {host}:{port}")
    
    # Create SSE server transport
    transport = SseServerTransport("/messages")
    
    # Start the transport server
    await transport.run(
        host=host,
        port=port,
        context=sse_server_instance.server
    )

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "sse":
        # Run with SSE transport
        asyncio.run(run_sse_server())
    else:
        # Run with stdio transport (default)
        asyncio.run(run_stdio_server())