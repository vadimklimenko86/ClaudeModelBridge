import contextlib
import logging
import json
from collections.abc import AsyncIterator
from typing import Self

import anyio
import click
from flask import Flask
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from event_store import InMemoryEventStore

#logger = logging.getLogger("uvicorn")
#logger.setLevel(logging.INFO)
# Configure logging
#logger = logging.getLogger(__name__)
logger = logging.getLogger()
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

	app = Server("mcp-streamable-http-demo")

	@app.call_tool()
	async def call_tool(
	    name: str, arguments: dict
	) -> list[types.TextContent
	          | types.ImageContent
	          | types.EmbeddedResource]:
		ctx = app.request_context

		if name == "echo":
			message = arguments.get("message", "")
			metadata = arguments.get("metadata", {})
			#timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

			response = {
			    "original_message": message,
			    #"timestamp": timestamp,
			    "metadata": metadata,
			    "server_info": {
			        "name": "Custom server",
			        "protocol_version": "2024-11-05",
			        "sdk_version": "1.9.2"
			    }
			}

			return [
			    types.TextContent(
			        type="text",
			        text=f"Echo Response:\n{json.dumps(response, indent=2)}")
			]
		else:
			interval = arguments.get("interval", 1.0)
			count = arguments.get("count", 5)
			caller = arguments.get("caller", "unknown")

			# Send the specified number of notifications with the given interval
			for i in range(count):
				# Include more detailed message for resumability demonstration
				notification_msg = (f"[{i+1}/{count}] Event from '{caller}' - "
				                    f"Use Last-Event-ID to resume if disconnected")
				await ctx.session.send_log_message(
				    level="info",
				    data=notification_msg,
				    logger="notification_stream",
				    # Associates this notification with the original request
				    # Ensures notifications are sent to the correct response stream
				    # Without this, notifications will either go to:
				    # - a standalone SSE stream (if GET request is supported)
				    # - nowhere (if GET request isn't supported)
				    related_request_id=ctx.request_id,
				)
				logger.debug(f"Sent notification {i+1}/{count} for caller: {caller}")
				if i < count - 1:  # Don't wait after the last notification
					await anyio.sleep(interval)

			# This will send a resource notificaiton though standalone SSE
			# established by GET request
			await ctx.session.send_resource_updated(
			    uri=AnyUrl("http:///test_resource"))
			return [
			    types.TextContent(
			        type="text",
			        text=(f"Sent {count} notifications with {interval}s interval"
			              f" for caller: {caller}"),
			    )
			]

	@app.list_tools()
	async def list_tools() -> list[types.Tool]:
		return [
		    types.Tool(name="echo",
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
		               }),
		    types.Tool(
		        name="start-notification-stream",
		        description=(
		            "Sends a stream of notifications with configurable count"
		            " and interval"),
		        inputSchema={
		            "type": "object",
		            "required": ["interval", "count", "caller"],
		            "properties": {
		                "interval": {
		                    "type": "number",
		                    "description":
		                    "Interval between notifications in seconds",
		                },
		                "count": {
		                    "type": "number",
		                    "description": "Number of notifications to send",
		                },
		                "caller": {
		                    "type":
		                    "string",
		                    "description":
		                    ("Identifier of the caller to include in notifications"
		                     ),
		                },
		            },
		        },
		    )
		]

	from starlette.middleware import Middleware
	from starlette.middleware.cors import CORSMiddleware

	class GraphQLRedirect:

		def __init__(self, app: ASGIApp) -> None:
			self.app = app

		async def __call__(self, scope: Scope, receive: Receive,
		                   send: Send) -> None:
			if not scope['path'].endswith("/"):
				path = scope['path']
				scope['path'] = path + "/"
			await self.app(scope, receive, send)

	# Create an ASGI application using the transport
	middleware = [
	    Middleware(CORSMiddleware, allow_origins=['*']),
	    Middleware(GraphQLRedirect)
	]
	starlette_app = Starlette(debug=True, middleware=middleware)
	starlette_app.router.redirect_slashes = False

	from custom_server import customroutes
	routes = customroutes(logger, app, starlette_app)

	import uvicorn
	uvicorn.run(starlette_app, host="127.0.0.1", port=port)
	return 0
