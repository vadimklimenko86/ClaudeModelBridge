#!/usr/bin/env python3
"""
Official MCP Server implementation using Python SDK
Compatible with Claude.ai MCP integration
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
server = Server("flask-mcp-server")

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available tools for Claude.ai"""
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
                text=f"Echo: {message}"
            )
        ]
    
    elif name == "system_info":
        # Get comprehensive system information
        try:
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            system_info = f"""System Information:
OS: {platform.system()} {platform.release()}
Architecture: {platform.machine()}
Python: {platform.python_version()}

Hardware:
CPU Cores: {cpu_count}
Memory: {memory.total // (1024**3)} GB total, {memory.available // (1024**3)} GB available
Disk: {disk.total // (1024**3)} GB total, {disk.free // (1024**3)} GB free

Load:
CPU Usage: {psutil.cpu_percent()}%
Memory Usage: {memory.percent}%
Disk Usage: {(disk.used / disk.total) * 100:.1f}%"""
            
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
            # Safe mathematical evaluation
            def safe_eval(node):
                if isinstance(node, ast.Constant):
                    return node.value
                elif isinstance(node, ast.BinOp):
                    return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
                elif isinstance(node, ast.UnaryOp):
                    return ops[type(node.op)](safe_eval(node.operand))
                else:
                    raise TypeError(f"Unsupported operation: {type(node)}")
            
            # Supported operations
            ops = {
                ast.Add: operator.add,
                ast.Sub: operator.sub,
                ast.Mult: operator.mul,
                ast.Div: operator.truediv,
                ast.Pow: operator.pow,
                ast.USub: operator.neg,
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
            name="System Information",
            description="Current system status and information",
            mimeType="text/plain"
        )
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """Read resource content"""
    if str(uri) == "memory://system/info":
        try:
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            
            return f"""Real-time System Status:
OS: {platform.system()} {platform.release()}
CPU: {cpu_count} cores, {psutil.cpu_percent()}% usage
Memory: {memory.total // (1024**3)} GB total, {memory.percent}% used
Python: {platform.python_version()}
"""
        except Exception as e:
            return f"Error reading system info: {str(e)}"
    else:
        raise ValueError(f"Unknown resource: {uri}")

async def main():
    """Run the MCP server"""
    logger.info("Starting Official MCP Server for Claude.ai...")
    
    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="flask-mcp-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())