import logging
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any, Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from http import HTTPStatus

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from event_store import InMemoryEventStore
#from oauth2 import OAuth2Manager
from oauth2_modules import OAuth2Manager


class SlashesMiddleware:
	"""Middleware для добавления trailing slash к путям /mcp"""

	def __init__(self, app: ASGIApp) -> None:
		self.app = app

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		if scope['type'] == 'http' and scope['path'].startswith(
		    "/mcp") and not scope['path'].endswith("/"):
			scope['path'] = scope['path'] + "/"
		await self.app(scope, receive, send)


class CustomServerWithOauth2:
	"""Кастомный сервер MCP с поддержкой OAuth2"""

	def __init__(self, logger: logging.Logger, serverapp: Server, base_url: str):
		self.logger = logger
		self.serverapp = serverapp

		# Создаем event store для поддержки возобновляемости потоков
		# InMemoryEventStore позволяет клиентам:
		#   1. Получать ID событий для каждого SSE сообщения
		#   2. Возобновлять потоки, отправляя Last-Event-ID в GET запросах
		#   3. Переигрывать пропущенные события после переподключения
		# Примечание: эта in-memory реализация только для демонстрации.
		# В продакшене используйте постоянное хранилище (Redis, PostgreSQL и т.д.)
		self.event_store = InMemoryEventStore()

		# Создаем менеджер сессий
		self.session_manager = StreamableHTTPSessionManager(
		    app=serverapp, event_store=self.event_store, json_response=False)

		# Инициализируем OAuth2 менеджер
		self.oauth = OAuth2Manager(logger, issuer=base_url)

		# Настраиваем маршруты
		routes = [
		    Mount("/mcp", app=self.handle_streamable_http, name="mcp"),
		]

		# Настраиваем middleware
		middleware = [
		    Middleware(SlashesMiddleware),
		    Middleware(CORSMiddleware,
		               allow_origins=["https://claude.ai", "http://localhost:*"],
		               allow_credentials=True,
		               allow_methods=["GET", "POST", "OPTIONS"],
		               allow_headers=["*"],
		               expose_headers=["*"])
		]

		# Создаем Starlette приложение
		self.app = Starlette(debug=False, middleware=middleware, routes=routes)

		# Добавляем OAuth2 маршруты
		for route in self.oauth.routes:
			self.app.router.routes.append(route)

		self.logger.info("CustomServerWithOauth2 initialized successfully")

	async def handle_streamable_http(self, scope: Scope, receive: Receive,
	                                 send: Send) -> None:
		"""Обработчик для MCP streamable HTTP соединений"""
		request = Request(scope, receive)

		# Проверяем авторизацию
		auth_header = request.headers.get('Authorization')

		if not auth_header or not auth_header.startswith('Bearer '):
			self.logger.warning(f"Unauthorized request to {scope['path']}")

			# Возвращаем ошибку авторизации с указанием метаданных OAuth2
			error_response = {
			    "jsonrpc": "2.0",
			    "error": {
			        "code": -32001,
			        "message": "Authentication required",
			        "data": {
			            "error": "invalid_token",
			            "error_description": "Bearer token is missing or invalid"
			        }
			    }
			}

			# Формируем URL для метаданных
			base_url = str(request.base_url).rstrip('/')
			if request.headers.get('x-forwarded-host'):
				proto = request.headers.get('x-forwarded-proto', 'https')
				host = request.headers['x-forwarded-host']
				base_url = f"{proto}://{host}"

			response = Response(
			    content=json.dumps(error_response),
			    status_code=HTTPStatus.UNAUTHORIZED,
			    headers={
			        "WWW-Authenticate":
			        f'Bearer realm="MCP API", resource_metadata="{base_url}/.well-known/oauth-protected-resource"',
			        "Content-Type": "application/json"
			    })
			await response(scope, receive, send)
			return

		# Извлекаем токен
		token = auth_header.split(' ', 1)[1]

		# Проверяем токен через OAuth2 менеджер
		if not self.oauth.token_manager.validate_access_token(token)[0]:
			self.logger.warning(f"Invalid token: {token[:10]}...")

			error_response = {
			    "jsonrpc": "2.0",
			    "error": {
			        "code": -32001,
			        "message": "Invalid token",
			        "data": {
			            "error": "invalid_token",
			            "error_description": "The access token is invalid or expired"
			        }
			    }
			}

			response = Response(content=json.dumps(error_response),
			                    status_code=HTTPStatus.UNAUTHORIZED,
			                    headers={"Content-Type": "application/json"})
			await response(scope, receive, send)
			return

		validated_token = self.oauth.token_manager.validate_access_token(token)
		# Проверяем срок действия токена
		#token_data = self.oauth.token_manager.access_tokens[token]
		token_data = validated_token[1]
		import time
		if token_data['expires_at'] < time.time():
			self.logger.warning(f"Expired token: {token[:10]}...")

			error_response = {
			    "jsonrpc": "2.0",
			    "error": {
			        "code": -32001,
			        "message": "Token expired",
			        "data": {
			            "error": "invalid_token",
			            "error_description": "The access token has expired"
			        }
			    }
			}

			response = Response(content=json.dumps(error_response),
			                    status_code=HTTPStatus.UNAUTHORIZED,
			                    headers={"Content-Type": "application/json"})
			await response(scope, receive, send)
			return

		# Токен валиден, передаем запрос в session manager
		# Можно добавить user_id в scope для использования в обработчиках
		scope['user_id'] = token_data['user_id']
		scope['client_id'] = token_data['client_id']
		scope['token_scopes'] = token_data['scope'].split()

		await self.session_manager.handle_request(scope, receive, send)

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		"""ASGI точка входа"""
		scope["app"] = self

		if scope["type"] == "lifespan":
			await self.lifespan(scope, receive, send)
			return

		await self.app(scope, receive, send)

	@contextlib.asynccontextmanager
	async def lifespan_manager(self) -> AsyncIterator[None]:
		"""Контекстный менеджер для управления жизненным циклом приложения"""
		self.logger.info("Starting CustomServerWithOauth2...")

		async with self.session_manager.run():
			self.logger.info("StreamableHTTP session manager started successfully")
			try:
				yield
			finally:
				self.logger.info("Shutting down CustomServerWithOauth2...")

	async def lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
		"""
		Обработка ASGI lifespan сообщений для управления
		событиями запуска и остановки приложения
		"""
		started = False

		message = await receive()
		assert message["type"] == "lifespan.startup"

		try:
			async with self.lifespan_manager():
				await send({"type": "lifespan.startup.complete"})
				started = True

				message = await receive()
				assert message["type"] == "lifespan.shutdown"

		except BaseException as e:
			self.logger.exception("Error during lifespan")
			exc_text = str(e)

			if started:
				await send({"type": "lifespan.shutdown.failed", "message": exc_text})
			else:
				await send({"type": "lifespan.startup.failed", "message": exc_text})
			raise
		else:
			await send({"type": "lifespan.shutdown.complete"})
