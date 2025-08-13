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
from MCP_Tools import MCP_Tools
import datetime

from settings import Settings

#logger = logging.getLogger("u(vicorn")
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
@click.option(
    "--base-url",
    type=str,
    help="Base URL for the server",
)
@click.option("--debug", is_flag=True, default=False)
@click.option("--no_auth", is_flag=True, default=False)
def main(port: int, log_level: str, json_response: bool, base_url: str,
         debug: bool, no_auth: bool) -> int:
	# Configure logging
	logging.basicConfig(
	    level=getattr(logging, log_level.upper()),
	    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
	)
	settings = Settings()
	settings.port = port
	settings.log_level = log_level
	settings.json_response = json_response
	settings.base_url = base_url
	settings.debug = debug
	settings.no_auth = no_auth

	mcp = Server("mcp-server")
	tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))

	tools = MCP_Tools(mcp)

	# from Tools import

	from Tools.System import SystemTools
	from Tools.FileSystem import FileSystemTools
	from Tools.Memory import MemoryTools
	from Tools.Git import GitTools

	if debug:
		FileSystemTools(tools)
		GitTools(tools)
		MemoryTools(tools)
	else:
		MemoryTools(tools)

	@mcp.call_tool()
	async def call_tool(
	    name: str, arguments: dict
	) -> list[types.TextContent
	          | types.ImageContent
	          | types.EmbeddedResource]:
		ctx = mcp.request_context
		return tools.execute_tool(name, arguments)

	@mcp.list_tools()
	async def list_tools() -> list[types.Tool]:
		return tools.get_tools_list()

	print(settings.__dict__)

	from custom_server import CustomServerWithOauth2
	routes = CustomServerWithOauth2(logger, mcp, settings)

	import uvicorn
	logger.info(f"Starting server on host=0.0.0.0, port={port}")
	uvicorn.run(routes, host="0.0.0.0", port=port, log_level=log_level.lower())
	return 0
