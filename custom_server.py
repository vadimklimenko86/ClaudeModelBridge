import logging
import contextlib
import json
from collections.abc import AsyncIterator

from flask import Flask
from starlette.applications import Starlette
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send
from mcp.server.lowlevel import Server
from event_store import InMemoryEventStore
#logger = logging.getLogger(__name__)


class customroutes:

	def __init__(self, logger: logging.Logger, serverapp: Server,
	             app: Starlette):
		if not isinstance(app, Starlette):
			raise Exception("Unknown app type")
		logger.info("StarletteApp")
		# Create event store for resumability
		# The InMemoryEventStore enables resumability support for StreamableHTTP transport.
		# It stores SSE events with unique IDs, allowing clients to:
		#   1. Receive event IDs for each SSE message
		#   2. Resume streams by sending Last-Event-ID in GET requests
		#   3. Replay missed events after reconnection
		# Note: This in-memory implementation is for demonstration ONLY.
		# For production, use a persistent storage solution.
		event_store = InMemoryEventStore()

		# Create the session manager with our app and event store
		self.session_manager = StreamableHTTPSessionManager(
		    app=serverapp,
		    event_store=event_store,  # Enable resumability
		    json_response=False  #json_response,
		)

		from oauth2_manager import OAuth2Manager

		self.oauth = OAuth2Manager(app, logger)

		from starlette.responses import Response
		from http import HTTPStatus

		# ASGI handler for streamable HTTP connections
		async def handle_streamable_http(scope: Scope, receive: Receive,
		                                 send: Send) -> None:
			request = Request(scope, receive)
			auth_header = request.headers.get('Authorization')
			if not auth_header or not auth_header.startswith('Bearer '):
				response = Response(
				    "Bad Request: No valid session ID provided",
				    status_code=HTTPStatus.UNAUTHORIZED,
				)
				await response(scope, receive, send)
			else:
				await self.session_manager.handle_request(scope, receive, send)

		app.router.mount("/mcp", app=handle_streamable_http)

		@contextlib.asynccontextmanager
		async def lifespan(app: Starlette) -> AsyncIterator[None]:
			"""Context manager for managing session manager lifecycle."""
			async with self.session_manager.run():
				logger.info("Application started with StreamableHTTP session manager!")
				try:
					yield
				finally:
					logger.info("Application shutting down...")

		app.router.lifespan_context = lifespan
