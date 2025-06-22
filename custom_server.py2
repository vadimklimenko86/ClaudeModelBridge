import logging
import contextlib
import json
from typing import Self
from collections.abc import AsyncIterator, Sequence
from starlette.applications import Starlette
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send
from mcp.server.lowlevel import Server
from event_store import InMemoryEventStore
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from starlette.responses import Response
from http import HTTPStatus

import typing
import sys
if sys.version_info >= (3, 10):  # pragma: no cover
	from typing import ParamSpec
else:  # pragma: no cover
	from typing_extensions import ParamSpec

import anyio
import click
import mcp.types as types


class SlashesFixer:
	"""Fix starlette not redirecting to trailing slash"""

	def __init__(self, app: ASGIApp) -> None:
		self.app = app

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		print(f"[SlashesFixer]: {scope['path']}")
		if scope['path'].startswith("/mcp") and not scope['path'].endswith("/"):
			path = scope['path']
			scope['path'] = path + "/"
		await self.app(scope, receive, send)


class CustomServerWithOauth2:

	def __init__(self, logger: logging.Logger, serverapp: Server):

		logger.info("StarletteApp")
		self.inited = False
		
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
		session_manager = StreamableHTTPSessionManager(
		    app=serverapp,
		    event_store=event_store,  # Enable resumability
		    json_response=False  #json_response,
		)

		self.session_manager = session_manager

		from oauth2_manager import OAuth2Manager

		self.oauth = OAuth2Manager(logger)
		#routes=	self.oauth.routes.extends(		[
		#	Mount("/mcp", app=self.handle_streamable_http),
		#	#Mount("/", app=self.handle_streamable_http)
		#])
		routes = []
		#Mount('/', routes = self.oauth.routes),

		routes.extend([Mount("/mcp", app=self.handle_streamable_http)])
		#routes.extend([Mount("/", routes=self.oauth.routes)])

		print(routes)


		
		self.app = Starlette(debug=False,
		                     middleware=[
		                         #Middleware(CORSMiddleware, allow_origins=['*']),
		                         Middleware(SlashesFixer)
		                     ],
		                     routes=routes)
		self.app.router.redirect_slashes = False

		self.app.add_middleware(
				CORSMiddleware,
				allow_origins=["https://claude.ai"],
				allow_credentials=True,
				allow_methods=["GET", "POST", "OPTIONS"],
				allow_headers=["*"],
		)
		
		for route in self.oauth.routes:
			self.app.router.routes.append(route)
		print(self.app.router.routes)
		# ASGI handler for streamable HTTP connections

	async def handle_streamable_http(self, scope: Scope, receive: Receive,
	                                 send: Send) -> None:
		request = Request(scope, receive)
		auth_header = request.headers.get('Authorization') or 'Bearer 123'
		
		if not auth_header or not auth_header.startswith('Bearer '):
			print(f"handle_streamable_http: {scope['path']}, {request.headers}")

			retobj={
				"jsonrpc": "2.0", 
				"error": {
						"code": -32001,
						"message": "Invalid token"
				}
			}
			#response = AuthorizationErrorResponse()
			response = Response(
			    json.dumps(retobj),
			    status_code=HTTPStatus.UNAUTHORIZED,
					headers={"WWW-Authenticate": f"Bearer resource_metadata=\"{request.base_url._url.rstrip('/')}/.well-known/oauth-protected-resource\""}		
			)
			#print(response.headers)
			#content = await request.json()
			#print(content)
			#print(request.form())
			await response(scope, receive, send)
			#await self.session_manager.handle_request(scope, receive, send)
		else:
			#print(f"handle_streamable_http: {scope['path']}")
			await self.session_manager.handle_request(scope, receive, send)

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		scope["app"] = self

		if scope["type"] == "lifespan":
			await self.lifespan(scope, receive, send)
			return

		await self.app(scope, receive, send)

	@contextlib.asynccontextmanager
	async def lifespanInternale(self, app: Starlette) -> AsyncIterator[None]:
		"""Context manager for managing session manager lifecycle."""
		print("Hello, lifespan")
		async with self.session_manager.run():
			print("Application started with StreamableHTTP session manager!")
			try:
				yield
			finally:
				print("Application shutting down...")

	async def lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
		"""
		Handle ASGI lifespan messages, which allows us to manage application
		startup and shutdown events.
		"""
		started = False
		app: typing.Any = scope.get("app")
		await receive()
		try:
			async with self.lifespanInternale(app) as maybe_state:
				if maybe_state is not None:
					if "state" not in scope:
						raise RuntimeError(
						    'The server does not support "state" in the lifespan scope.')
					scope["state"].update(maybe_state)
				await send({"type": "lifespan.startup.complete"})
				started = True
				await receive()
		except BaseException:
			exc_text = ""  #traceback.format_exc()
			if started:
				await send({"type": "lifespan.shutdown.failed", "message": exc_text})
			else:
				await send({"type": "lifespan.startup.failed", "message": exc_text})
			raise
		else:
			await send({"type": "lifespan.shutdown.complete"})
