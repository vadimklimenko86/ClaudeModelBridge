#!/usr/bin/env python3
"""
HTTP Server for Remote MCP using Official Python SDK v1.9.2
Provides web interface and REST API for Claude.ai integration
"""

import asyncio
import json
import logging
from typing import Dict, Any
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from mcp_server import RemoteMCPServer, stdio_server_instance
from mcp.server.stdio import StdioServerTransport
from mcp.server.models import InitializationOptions

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global MCP server instance
mcp_server = RemoteMCPServer("http-mcp-server")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting HTTP MCP Server...")
    yield
    logger.info("Shutting down HTTP MCP Server...")

# Create FastAPI app
app = FastAPI(
    title="Remote MCP Server",
    description="HTTP interface for Model Context Protocol server using official Python SDK v1.9.2",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create directories
Path("static").mkdir(exist_ok=True)
Path("templates").mkdir(exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/mcp")
@app.get("/mcp/")
async def mcp_info():
    """MCP server information"""
    return {
        "name": "Remote MCP Server",
        "version": "1.0.0",
        "protocol_version": "2024-11-05",
        "sdk_version": "1.9.2",
        "transport": "http",
        "capabilities": {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
            "prompts": {"listChanged": True}
        },
        "endpoints": {
            "tools": "/mcp/tools",
            "resources": "/mcp/resources", 
            "prompts": "/mcp/prompts",
            "call_tool": "/mcp/call",
            "read_resource": "/mcp/read",
            "get_prompt": "/mcp/prompt"
        }
    }

@app.post("/mcp")
@app.post("/mcp/")
async def mcp_jsonrpc(request: Request):
    """MCP JSON-RPC endpoint"""
    try:
        data = await request.json()
        method = data.get("method")
        params = data.get("params", {})
        request_id = data.get("id")
        
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": True, "listChanged": True},
                    "prompts": {"listChanged": True}
                },
                "serverInfo": {
                    "name": "http-mcp-server",
                    "version": "1.0.0"
                }
            }
            return {"jsonrpc": "2.0", "result": result, "id": request_id}
        
        elif method == "tools/list":
            tools = await mcp_server.server._handlers["tools/list"]()
            tools_json = []
            for tool in tools:
                tools_json.append({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema
                })
            return {"jsonrpc": "2.0", "result": {"tools": tools_json}, "id": request_id}
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            result_content = await mcp_server.server._handlers["tools/call"](tool_name, arguments)
            content_list = []
            for item in result_content:
                content_list.append({
                    "type": item.type,
                    "text": item.text
                })
            
            return {"jsonrpc": "2.0", "result": {"content": content_list}, "id": request_id}
        
        elif method == "resources/list":
            resources = await mcp_server.server._handlers["resources/list"]()
            resources_json = []
            for resource in resources:
                resources_json.append({
                    "uri": str(resource.uri),
                    "name": resource.name,
                    "description": resource.description,
                    "mimeType": resource.mimeType
                })
            return {"jsonrpc": "2.0", "result": {"resources": resources_json}, "id": request_id}
        
        elif method == "resources/read":
            uri = params.get("uri")
            content = await mcp_server.server._handlers["resources/read"](uri)
            return {"jsonrpc": "2.0", "result": {"contents": [{"uri": uri, "text": content}]}, "id": request_id}
        
        elif method == "prompts/list":
            prompts = await mcp_server.server._handlers["prompts/list"]()
            prompts_json = []
            for prompt in prompts:
                prompts_json.append({
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments
                })
            return {"jsonrpc": "2.0", "result": {"prompts": prompts_json}, "id": request_id}
        
        elif method == "prompts/get":
            prompt_name = params.get("name")
            arguments = params.get("arguments", {})
            
            result = await mcp_server.server._handlers["prompts/get"](prompt_name, arguments)
            messages_json = []
            for message in result.messages:
                messages_json.append({
                    "role": message.role,
                    "content": {
                        "type": message.content.type,
                        "text": message.content.text
                    }
                })
            
            return {"jsonrpc": "2.0", "result": {
                "description": result.description,
                "messages": messages_json
            }, "id": request_id}
        
        else:
            return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": request_id}
            
    except Exception as e:
        logger.error(f"MCP JSON-RPC error: {e}")
        return {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": request_id}

@app.get("/mcp/tools")
async def list_tools():
    """List available tools"""
    try:
        tools = await mcp_server.server._handlers["tools/list"]()
        return [{"name": tool.name, "description": tool.description, "inputSchema": tool.inputSchema} for tool in tools]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mcp/call/{tool_name}")
async def call_tool(tool_name: str, arguments: Dict[str, Any]):
    """Call a specific tool"""
    try:
        result = await mcp_server.server._handlers["tools/call"](tool_name, arguments)
        return {"tool": tool_name, "result": [{"type": item.type, "text": item.text} for item in result]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/mcp/resources")
async def list_resources():
    """List available resources"""
    try:
        resources = await mcp_server.server._handlers["resources/list"]()
        return [{"uri": str(r.uri), "name": r.name, "description": r.description, "mimeType": r.mimeType} for r in resources]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/mcp/read")
async def read_resource(uri: str):
    """Read a resource"""
    try:
        content = await mcp_server.server._handlers["resources/read"](uri)
        return {"uri": uri, "content": content}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/mcp/prompts")
async def list_prompts():
    """List available prompts"""
    try:
        prompts = await mcp_server.server._handlers["prompts/list"]()
        return [{"name": p.name, "description": p.description, "arguments": p.arguments} for p in prompts]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mcp/prompt/{prompt_name}")
async def get_prompt(prompt_name: str, arguments: Dict[str, Any]):
    """Get a specific prompt"""
    try:
        result = await mcp_server.server._handlers["prompts/get"](prompt_name, arguments)
        return {
            "name": prompt_name,
            "description": result.description,
            "messages": [
                {
                    "role": msg.role,
                    "content": {"type": msg.content.type, "text": msg.content.text}
                } for msg in result.messages
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "server": "Remote MCP Server",
        "version": "1.0.0",
        "sdk_version": "1.9.2",
        "protocol_version": "2024-11-05"
    }

@app.get("/api/stats")
async def get_stats():
    """Get server statistics"""
    try:
        # Get real-time metrics
        metrics = await mcp_server._get_realtime_metrics()
        
        return {
            "server_info": {
                "name": mcp_server.server.name,
                "uptime": "Running",
                "protocol_version": "2024-11-05",
                "sdk_version": "1.9.2"
            },
            "metrics": metrics,
            "capabilities": {
                "tools_count": len(await mcp_server.server._handlers["tools/list"]()),
                "resources_count": len(await mcp_server.server._handlers["resources/list"]()),
                "prompts_count": len(await mcp_server.server._handlers["prompts/list"]())
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# SSE endpoint for real-time updates
@app.get("/events")
async def stream_events():
    """Server-Sent Events for real-time updates"""
    async def event_generator():
        while True:
            try:
                metrics = await mcp_server._get_realtime_metrics()
                yield f"data: {json.dumps(metrics)}\n\n"
                await asyncio.sleep(2)
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
    
    return StreamingResponse(event_generator(), media_type="text/plain")

if __name__ == "__main__":
    uvicorn.run(
        "http_server:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
        log_level="info"
    )