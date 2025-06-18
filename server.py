import asyncio
import contextlib
import logging
import json
from collections.abc import AsyncIterator, Awaitable, Coroutine
from typing import Self

import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from event_store import InMemoryEventStore

import datetime
import MCP_Tools
from mcp.shared.context import RequestContext
#logger = logging.getLogger("uvicorn")
#logger.setLevel(logging.INFO)
# Configure logging
logger = logging.getLogger(__name__)
#logger = logging.getLogger()
logger.setLevel(logging.INFO)


@click.command()
@click.option("--port", default=5000, help="Port to listen on for HTTP")
@click.option(
    "--log-level",
    default="INFO",
    help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
)
@click.option(
    "--json-response",
    is_flag=True,
    default=False,
    help="Enable JSON responses instead of SSE streams",
)
def main(
    port: int,
    log_level: str,
    json_response: bool,
) -> int:
	# Configure logging
	logging.basicConfig(
	    level=getattr(logging, log_level.upper()),
	    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
	)

	mcp = Server("mcp-streamable-http-demo")
	tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))

	tools = MCP_Tools.MCP_Tools(mcp)

	from Tools.System import SystemTools
	from Tools.FileSystem_improved import FileSystemTools
	from Tools.Memory_fixed import MemoryTools

	[SystemTools(tools), FileSystemTools(tools), MemoryTools(tools)]

	@mcp.call_tool()
	async def call_tool(
	    name: str, arguments: dict
	) -> list[types.TextContent
	          | types.ImageContent
	          | types.EmbeddedResource]:
		ctx = mcp.request_context
		return tools.ToolsFuncs[name](arguments)

	@mcp.list_tools()
	async def list_tools() -> list[types.Tool]:
		return list(tools.ToolsDict.values())

	from custom_server import CustomServerWithOauth2
	routes = CustomServerWithOauth2(logger, mcp)

	import uvicorn
	uvicorn.run(routes, host="127.0.0.1", port=port)
	return 0
