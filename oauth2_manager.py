import inspect
import logging
from os import error
import secrets
import base64
import hashlib
import json
from shutil import Error
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.handlers.authorize import Response 

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send
from http import HTTPStatus

class OAuth2Client:
	"""Класс для представления OAuth 2.0 клиента"""

	def __init__(self,
	             client_id: str,
	             client_secret: str,
	             redirect_uris: List[str],
	             name: str,
	             grant_types: List[str] = None,
	             scopes: List[str] = None):
		self.client_id = client_id
		self.client_secret = client_secret
		self.redirect_uris = redirect_uris
		self.name = name
		self.scopes = scopes or ['openid', 'profile', 'email']
		self.grant_types = grant_types or ['']
		self.created_at = datetime.utcnow()


class OAuth2Manager:
	"""Класс для управления OAuth 2.0 авторизацией"""

	def __init__(self, logger: logging.Logger) -> None:
		#self.app = app

		self.logger = logger
		self.initialize()
		# Генерируем RSA ключи для JWT
		self._generate_keys()
		self._register_routes()

		#self.app.router

	def initialize(self):
		self.clients: Dict[str, OAuth2Client] = {
		    "client_1749051312":
		    OAuth2Client(
		        client_id="client_1749051312",
		        client_secret="claude_secret_key_2024",
		        redirect_uris=[
							"https://claude.ai/oauth/callback",
							"https://claude.ai/api/mcp/auth_callback"							
						],
		        name="Claude MCP Client",
		        grant_types=[
		            "authorization_code", "refresh_token", "client_credentials"
		        ],
		    )
		}
		self.routes: list[Route] = []
		self.authorization_codes: Dict[str, dict] = {}
		self.access_tokens: Dict[str, dict] = {}
		self.refresh_tokens: Dict[str, dict] = {}
		self.session = {}
		self.users = {
		    'user@example.com': {
		        'id': '1',
		        'email': 'user@example.com',
		        'name': 'Test User',
		        'password': 'password123'  # В реальности должен быть хеш
		    }
		}

	def _generate_keys(self):
		"""Генерация RSA ключей для подписи JWT"""
		self.private_key = rsa.generate_private_key(public_exponent=65537,
		                                            key_size=2048)
		self.public_key = self.private_key.public_key()

		# Для JWKS
		self.key_id = secrets.token_urlsafe(8)

	def _register_routes(self):
		"""Регистрация всех OAuth 2.0 endpoints"""

		def route3(path: str,
		           methods: list[str] | None = ["GET", "POST"],
		           name: str | None = None) -> Callable:  # type: ignore[type-arg]

			def decorator(func: Callable) -> Callable:  # type: ignore[type-arg]
				#self.routes.append(Mount(path, app=func))
				#self.routes.append(Route(path, endpoint=func, methods=methods))
				#self.app.router.mount(path, app=func, methods=methods)
				return func

			return decorator

		class TestRouteInfo:

			def __init__(self, path: str, endpoint: Callable):
				self.path = path
				self.endpoint = endpoint
				self.methods = ["GET", "POST"]
				self.name = None

			async def __call__(self, scope: Scope, receive: Receive,
			                   send: Send) -> Any:
				import inspect
				import asyncio
				from typing import Dict, Callable, Any, Union

				#print(f"[TestRouteInfo]: {self.path}")
				# Словарь фабрик для создания параметров
				parameter_factories: Dict[str, Callable[[], Any]] = {
				    'scope': lambda: scope,
				    'receive': lambda: receive,
				    'send': lambda: send,
				    'request': lambda: Request(scope, receive, send),
				    'websocket': lambda: WebSocket(scope, receive, send),  # Если нужен WebSocket
				}

				sig = inspect.signature(self.endpoint)
				filtered_kwargs = {}

				# Создаем параметры на основе сигнатуры
				for param_name, param in sig.parameters.items():
					if param_name in parameter_factories:
						filtered_kwargs[param_name] = parameter_factories[param_name]()
					elif param.default is not inspect.Parameter.empty:
						# Параметр имеет значение по умолчанию, пропускаем
						continue
					else:
						raise ValueError(
						    f"Не знаю, как создать обязательный параметр: {param_name}")

				# Вызываем endpoint в зависимости от его типа
				result = await self._call_endpoint(self.endpoint, filtered_kwargs)
				if inspect.isclass(Response):
					await result(scope, receive, send)
				else:
					raise ValueError(
					    f"Неизвестный результат вызова endpoint: {type(result)}")

			async def _call_endpoint(self, endpoint: Callable,
			                         kwargs: Dict[str, Any]) -> Any:
				"""Универсальный вызов endpoint с учетом его типа"""

				import inspect
				import asyncio
				from typing import Dict, Callable, Any, Union

				if inspect.iscoroutinefunction(endpoint):
					# Асинхронная функция
					return await endpoint(**kwargs)

				elif asyncio.iscoroutine(endpoint):
					# Уже корутина
					return await endpoint

				elif callable(endpoint):
					# Обычная синхронная функция
					result = endpoint(**kwargs)

					# Если результат - корутина, ждем её
					if asyncio.iscoroutine(result):
						return await result
					return result

				else:
					raise TypeError(
					    f"endpoint должен быть вызываемым объектом, получен: {type(endpoint)}"
					)

		def route(path: str,
		          methods: list[str] | None = ["GET", "POST"],
		          name: str | None = None) -> Callable:  # type: ignore[type-arg]

			def decorator(func: Callable) -> Callable:  # type: ignore[type-arg]
				#self.routes.append(Mount(path, app=func, methods=methods))
				routeinfo = TestRouteInfo(path, func)
				self.routes.append(Route(path, endpoint=routeinfo, methods=methods))
				#self.app.router.mount(path, app=func, methods=methods)
				return func

			return decorator

		#async def handle_streamable_http(scope: Scope, receive: Receive,send: Send) -> None:
		#	request = Request(scope, receive)
		#	response = Response(
		#		"Bad Request: No valid session ID provided",
		#		status_code=HTTPStatus.UNAUTHORIZED,
		#	)
		#	await response(scope, receive, send)

		# Discovery endpoint
		@route('/oauth/authorize', methods=['OPTIONS'])
		async def authorize_options(request):
				return Response("", headers={
						"Access-Control-Allow-Origin": "*",
						"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
						"Access-Control-Allow-Headers": "Authorization, Content-Type"
				})
		
		@route('/.well-known/oauth-protected-resource')
		async def oauth_metadata2(request):
			return await self.get_authorization_server_metadata(request)

		@route('/.well-known/oauth-authorization-server')
		async def oauth_metadata(request):
			return await self.get_authorization_server_metadata(request)

		# JWKS endpoint
		@route('/.well-known/jwks.json')
		async def jwks(request):
			return self.get_jwks(request)

		# Authorization endpoint
		@route('/oauth/authorize')
		async def authorize(request):
			return await self.handle_authorization_request(request)

		#route('/oauth/authorize', methods=['POST'])
		async def authorize_post(request: Request):
				return await self.handle_authorization_submit(request)
		
		# Token endpoint
		@route('/oauth/token', methods=['POST','GET'])
		async def token(request: Request):
			return await self.handle_token_request(request)

		@route('/oauth/token', methods=['POST'])
		async def token2(request: Request):
			return await self.handle_token_request(request)

		
		@route('/oauth/userinfo')
		async def user_info(request: Request):
			return self.handle_userinfo_request(request)

		@route('/oauth/login_page', methods=['GET'])
		async def login_page(request: Request):
			print('login_page')
			return self.show_login_page(request)

		@route('/oauth/login_page', methods=['POST'])
		async def login_submit(request: Request):
			print('login_submit')
			return await self.handle_login(request)

		@route('/oauth/register', methods=['POST'])
		async def register_client(request: Request):
			return await self.handle_client_registration(request)

	async def get_authorization_server_metadata(self,
	                                            request: Request) -> Response:
		"""RFC 8414 - OAuth 2.0 Authorization Server Metadata"""

		# Use proper external URL instead of localhost
		base_url = request.base_url._url.rstrip('/')
		if '127.0.0.1' in base_url or 'localhost' in base_url:
			# Replace with proper Replit domain or use request headers
			host = request.headers.get('host',
			                           request.headers.get('x-forwarded-host', ''))
			if host:
				scheme = 'https' if request.headers.get(
				    'x-forwarded-proto') == 'https' else 'http'
				base_url = f"{scheme}://{host}"
		#issuer = request.base_url._url.rstrip('/')
		issuer = base_url
		metadata = {


			"issuer": base_url,
			"authorization_endpoint": f"{base_url}/oauth/authorize",
			"token_endpoint": f"{base_url}/oauth/token",
			"jwks_uri": f"{base_url}/.well-known/jwks.json",


			# Поддерживаемые scopes для MCP
			"scopes_supported": [
					"openid",
					"profile", 
					"email",
					"mcp:read",  # Добавляем MCP-специфичные scopes
					"mcp:write"
			],

			# Только код авторизации для MCP (безопаснее)
			"response_types_supported": ["code"],
			"response_modes_supported": ["query"],
			"grant_types_supported": ["authorization_code", "refresh_token"],

			# Обязательно PKCE для MCP
			"code_challenge_methods_supported": ["S256"],

			# Аутентификация клиента
			"token_endpoint_auth_methods_supported": [
					"client_secret_post",
					"client_secret_basic",
					"none"  # Для публичных клиентов
			],
			# JWT подпись
			"id_token_signing_alg_values_supported": ["RS256"],
			"subject_types_supported": ["public"],

			# Поддерживаемые claims
			"claims_supported": [
					"sub", "iss", "aud", "exp", "iat", "nbf", "auth_time",
					"name", "email", "email_verified", "preferred_username"
			],

			# Дополнительные endpoints
			"userinfo_endpoint": f"{base_url}/oauth/userinfo",
			"revocation_endpoint": f"{base_url}/oauth/revoke",  # Для отзыва токенов
			# Опциональные поля для лучшей совместимости
			"token_endpoint_auth_signing_alg_values_supported": ["RS256"],
			"request_object_signing_alg_values_supported": ["RS256"],
			"userinfo_signing_alg_values_supported": ["RS256"],

			# PKCE поддержка (критично для MCP)
			"require_request_uri_registration": False,
			"request_uri_parameter_supported": False,

			# Дополнительная информация
			"service_documentation": f"{base_url}/docs/oauth2",
			"ui_locales_supported": ["en"],
			"claims_locales_supported": ["en"],

			# Настройки времени жизни токенов
			"frontchannel_logout_supported": False,
			"frontchannel_logout_session_supported": False,
			"backchannel_logout_supported": False,
			"backchannel_logout_session_supported": False,
		}
		#response = Response(
		#    json.dumps(metadata),
		#    status_code=HTTPStatus.OK,
		#)

		return JSONResponse(metadata, headers={
			"Content-Type": "application/json",
		})
		#return self.jsonify(metadata)
		#return jsonify(metadata)
	
	def jsonify(self, data, status_code: int = HTTPStatus.OK) -> Response:
		return JSONResponse(data, status_code=status_code, headers={
				"Content-Type": "application/json",
				"Access-Control-Allow-Origin": "*",  # Добавьте CORS
				"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers": "Authorization, Content-Type"
		})
		

	def get_jwks(self, request: Request) -> Response:
		"""JSON Web Key Set endpoint"""
		public_numbers = self.public_key.public_numbers()
		self.logger.error("get_jwks")

		# Конвертируем в base64url
		def int_to_base64url(val):
			val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
			return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')

		jwks = {
		    "keys": [{
		        "kty": "RSA",
		        "use": "sig",
		        "kid": self.key_id,
		        "alg": "RS256",
		        "n": int_to_base64url(public_numbers.n),
		        "e": int_to_base64url(public_numbers.e)
		    }]
		}

		return self.jsonify(jwks)

	async def handle_authorization_request(self, request: Request) -> Response:
		"""Обработка authorization request"""

		formdata = await request.form()
		if formdata:
			return await self.handle_authorization_submit(request)
		
		client_id = request.query_params.get('client_id')
		redirect_uri = request.query_params.get('redirect_uri')
		response_type = request.query_params.get('response_type')
		scope = request.query_params.get('scope', 'openid')
		state = request.query_params.get('state')
		code_challenge = request.query_params.get('code_challenge')
		code_challenge_method = request.query_params.get('code_challenge_method',
		                                                 'S256')

		# Валидация клиента
		if not client_id or client_id not in self.clients:
			return Response(json.dumps({"error": f"invalid_client {client_id}"}),
			                400)

		client = self.clients[client_id]

		# Валидация redirect_uri
		if redirect_uri not in client.redirect_uris:
		    return self.jsonify({"error": "invalid_redirect_uri"}, 400)

		# Валидация response_type
		if response_type not in ['code', 'token', 'id_token']:
			return Response(
			    json.dumps({"error": f"unsupported_response_type {response_type}"}),
			    400)

		# Проверка авторизации пользователя
		if 'user_id' not in self.session:
			# Сохраняем параметры для возврата после логина
			self.session['oauth_params'] = request.query_params
			self.session['user_id'] = client_id
			#return RedirectResponse('login_page')

		# Генерируем authorization code
		auth_code = secrets.token_urlsafe(32)

		self.authorization_codes[auth_code] = {
		    'client_id': client_id,
		    'user_id': self.session['user_id'],
		    'redirect_uri': redirect_uri,
		    'scope': scope,
		    'code_challenge': code_challenge,
		    'code_challenge_method': code_challenge_method,
				#'code_verifier': code_challenge_method,
		    'expires_at': time.time() + 60000,  # 10 минут
		    'used': False
		}

		# Формируем URL для редиректа
		params = {}
		
		if state:
			params['state'] = state


		params['code'] = auth_code
		params['client_id'] = client_id
		params['redirect_uri'] = redirect_uri
		params['code_verifier'] = code_challenge
		
		#params['client_secret'] = client.client_secret
		
		#redirect_uri = "/oauth/token"
		redirect_url = f"{redirect_uri}?{urlencode(params)}"
		self.logger.info(f"Redirecting to: {redirect_url}")
		self.logger.info("=== AUTHORIZATION REQUEST END ===")
		
		#logging.info(f'Redirecting to: {redirect_url}')
		#return RedirectResponse(redirect_url, )
		return RedirectResponse(redirect_url, 307, headers={
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
			"Access-Control-Max-Age": "86400"
		})

		# Показываем страницу согласия
		return self._show_consent_page(client, scope, redirect_uri, state,
		                               code_challenge, code_challenge_method)
	async def handle_authorization_submit(self, request:Request):
		"""Обработка согласия пользователя"""
		if 'user_id' not in self.session:
				return jsonify({"error": "unauthorized"}), 401
		form_data = await request.form()
		client_id =form_data.get('client_id')
		redirect_uri = form_data.get('redirect_uri')
		scope = form_data.get('scope')
		state = form_data.get('state')
		code_challenge = form_data.get('code_challenge')
		code_challenge_method = form_data.get('code_challenge_method')
		consent = form_data.get('consent')

		#if consent != 'approve':
		#		return self._error_redirect(redirect_uri, "access_denied", state)

		# Генерируем authorization code
		auth_code = secrets.token_urlsafe(32)

		self.authorization_codes[auth_code] = {
				'client_id': client_id,
				'user_id': self.session['user_id'],
				'redirect_uri': redirect_uri,
				'scope': scope,
				'code_challenge': code_challenge,
				'code_challenge_method': code_challenge_method,
				'expires_at': time.time() + 60000,  # 10 минут
				'used': False
		}

		# Формируем URL для редиректа
		params = {}
		params = {'code': auth_code, 'client_id': client_id}
		if state:
				params['state'] = state

		#redirect_url = f"{redirect_uri}?{urlencode(params)}"
		redirect_url = f"{redirect_uri}?{urlencode(params)}"
		print(redirect_url)
		
		return RedirectResponse(redirect_url, 302)

	def _authenticate_client(self, client_id: str, client_secret: str) -> bool:
		"""Аутентификация клиента"""
		client = self.clients.get(client_id)
		return client  # and client.client_secret == client_secret

	def _verify_pkce(self, code_verifier: str, code_challenge: str,
	                 method: str) -> bool:
		"""Проверка PKCE"""
		if method == 'plain':
			return code_verifier == code_challenge
		elif method == 'S256':
			challenge = base64.urlsafe_b64encode(
			    hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')
			
			return challenge == code_challenge
		return False

	def _generate_access_token(self, user_id: str, client_id: str,
	                           scope: str) -> str:
		"""Генерация access token"""
		token = secrets.token_urlsafe(32)

		self.access_tokens[token] = {
		    'user_id': user_id,
		    'client_id': client_id,
		    'scope': scope,
		    'expires_at': time.time() + 3600,  # 1 час
		    'token_type': 'Bearer'
		}

		return token

	async def _handle_authorization_code_grant(self, request: Request):
		"""Обработка authorization_code grant"""
		form_data = await request.form()

		
		code = form_data.get('code') or request.query_params.get('code')
		client_id = form_data.get('client_id') or request.query_params.get('client_id')
		client_secret = form_data.get('client_secret') or request.query_params.get('client_secret')
		redirect_uri = form_data.get('redirect_uri') or request.query_params.get('redirect_uri')
		code_verifier = form_data.get('code_verifier') or request.query_params.get('code_verifier')

		#print(f'[handle_authorization_code_grant]: {form_data}')
		# Валидация клиента
		#if not self._authenticate_client(client_id, client_secret):
		#	return self.jsonify({"error": "invalid_client"}, 401)
		#print(f'[handle_authorization_code_grant]: {code}')
		
		# Валидация authorization code
		if code not in self.authorization_codes:
			#print(self.authorization_codes)
			return self.jsonify({"error": "invalid_code"}, 400)

		code_data = self.authorization_codes[code]

		# Проверки
		if code_data['used'] or code_data['expires_at'] < time.time():
			return self.jsonify({"error": "invalid_grant"}, 400)

		if code_data['client_id'] != client_id:
			return self.jsonify({"error": "invalid_grant"}, 400)

		if code_data['redirect_uri'] != redirect_uri:
			return self.jsonify({"error": "invalid_grant"}, 400)

		# PKCE проверка
		if code_data.get('code_challenge'):
			if not code_verifier:
				return self.jsonify({"error": "invalid_request"}, 400)

			if not self._verify_pkce(code_verifier, code_data['code_challenge'],
			                         code_data.get('code_challenge_method', 'plain')):
				return self.jsonify({"error": "invalid_grant"}, 400)

		# Помечаем код как использованный
		code_data['used'] = True

		# Генерируем токены
		access_token = self._generate_access_token(code_data['user_id'], client_id,
		                                           code_data['scope'])

		refresh_token = self._generate_refresh_token(code_data['user_id'],
		                                             client_id, code_data['scope'])

		# ID Token для OpenID Connect
		id_token = None
		if 'openid' in code_data['scope']:
			id_token = self._generate_id_token(request, code_data['user_id'],
			                                   client_id, access_token)

		response = {
		    "access_token": access_token,
		    "token_type": "Bearer",
		    "expires_in": 3600,
		    "refresh_token": refresh_token,
		    "scope": code_data['scope']
		}

		if id_token:
			response["id_token"] = id_token

		return self.jsonify(response)

	async def handle_token_request(self, request: Request) -> Response:
		"""Обработка token request"""
		form_data = await request.form()
		grant_type = form_data.get('grant_type') or 'authorization_code'
		print(f'[handle_token_request]: grant_type={grant_type}')
		#raise Exception(f"{grant_type}")
		#return Response(json.dumps({"error": "unsupported_grant_type"}), 400)
		if grant_type == 'authorization_code':
			return await self._handle_authorization_code_grant(request)
		elif grant_type == 'refresh_token':
			return await self._handle_refresh_token_grant(request)
		else:
			return self.jsonify({"error": "unsupported_grant_type"}, 400)

	def _generate_refresh_token(self, user_id: str, client_id: str,
	                            scope: str) -> str:
		"""Генерация refresh token"""
		token = secrets.token_urlsafe(32)

		self.refresh_tokens[token] = {
		    'user_id': user_id,
		    'client_id': client_id,
		    'scope': scope,
		    'expires_at': time.time() + 86400 * 30,  # 30 дней
		}

		return token

	def _generate_id_token(self, request: Request, user_id: str, client_id: str,
	                       access_token: str) -> str:
		"""Генерация ID token (JWT) для OpenID Connect"""
		# Use proper external URL instead of localhost
		base_url = request.base_url._url.rstrip('/')
		if '127.0.0.1' in base_url or 'localhost' in base_url:
			# Replace with proper Replit domain or use request headers
			host = request.headers.get('host',
			                           request.headers.get('x-forwarded-host', ''))
			if host:
				scheme = 'https' if request.headers.get(
				    'x-forwarded-proto') == 'https' else 'http'
				base_url = f"{scheme}://{host}"
		print("_generate_id_token")
		issuer = base_url
		issuer = request.base_url._url.rstrip('/')
		now = datetime.utcnow()

		payload = {
		    'iss': issuer,
		    'sub': user_id,
		    'aud': client_id,
		    'exp': int((now + timedelta(hours=1)).timestamp()),
		    'iat': int(now.timestamp()),
		    'at_hash': self._calculate_at_hash(access_token)
		}

		# Добавляем пользовательские claims
		user = self.users.get(user_id)
		if user:
			payload['email'] = user.get('email')
			payload['name'] = user.get('name')
			payload['email_verified'] = True

		# Подписываем JWT
		private_key_pem = self.private_key.private_bytes(
		    encoding=serialization.Encoding.PEM,
		    format=serialization.PrivateFormat.PKCS8,
		    encryption_algorithm=serialization.NoEncryption())

		return jwt.encode(payload,
		                  private_key_pem,
		                  algorithm='RS256',
		                  headers={'kid': self.key_id})

	def _calculate_at_hash(self, access_token: str) -> str:
		"""Вычисление at_hash для ID token"""
		digest = hashlib.sha256(access_token.encode()).digest()
		return base64.urlsafe_b64encode(digest[:16]).decode().rstrip('=')

	async def _handle_refresh_token_grant(self, request: Request):
		"""Обработка refresh_token grant"""
		form_data = await request.form()
		refresh_token = form_data.get('refresh_token')
		client_id = form_data.get('client_id')
		client_secret = form_data.get('client_secret')
		scope = form_data.get('scope')

		# Валидация клиента
		if not self._authenticate_client(client_id, client_secret):
			return self.jsonify({"error": "invalid_client"}, 401)

		# Валидация refresh token
		if refresh_token not in self.refresh_tokens:
			return self.jsonify({"error": "invalid_grant"}, 400)

		token_data = self.refresh_tokens[refresh_token]

		if token_data['expires_at'] < time.time():
			return self.jsonify({"error": "invalid_grant"}, 400)

		if token_data['client_id'] != client_id:
			return self.jsonify({"error": "invalid_grant"}, 400)

		# Используем оригинальный scope или новый (если он subset)
		original_scopes = set(token_data['scope'].split())
		requested_scopes = set(scope.split()) if scope else original_scopes

		if not requested_scopes.issubset(original_scopes):
			return self.jsonify({"error": "invalid_scope"}, 400)

		# Генерируем новый access token
		access_token = self._generate_access_token(token_data['user_id'],
		                                           client_id,
		                                           ' '.join(requested_scopes))

		response = {
		    "access_token": access_token,
		    "token_type": "Bearer",
		    "expires_in": 3600,
		    "scope": ' '.join(requested_scopes)
		}

		return self.jsonify(response)

	def handle_userinfo_request(self, request: Request):
		"""Обработка userinfo request"""
		auth_header = request.headers.get('Authorization')

		if not auth_header or not auth_header.startswith('Bearer '):
			return self.jsonify({"error": "invalid_token"}, 401)

		access_token = auth_header.split(' ')[1]

		if access_token not in self.access_tokens:
			return self.jsonify({"error": "invalid_token"}, 401)

		token_data = self.access_tokens[access_token]

		if token_data['expires_at'] < time.time():
			return self.jsonify({"error": "invalid_token"}, 401)

		# Проверяем scope
		scopes = token_data['scope'].split()
		if 'profile' not in scopes and 'email' not in scopes:
			return self.jsonify({"error": "insufficient_scope"}, 403)

		user_id = token_data['user_id']
		user = self.users.get(user_id)

		if not user:
			return self.jsonify({"error": "invalid_token"}, 401)

		# Формируем ответ на основе scope
		userinfo = {"sub": user_id}

		if 'profile' in scopes:
			userinfo["name"] = user.get('name')

		if 'email' in scopes:
			userinfo["email"] = user.get('email')
			userinfo["email_verified"] = True

		return self.jsonify(userinfo)

	async def handle_client_registration(self, request: Request):
		"""Динамическая регистрация клиентов (RFC 7591)"""
		data = await request.form()

		if not data:
			return jsonify({"error": "invalid_request"}), 400

		# Генерируем client_id и client_secret
		client_id = secrets.token_urlsafe(16)
		client_secret = secrets.token_urlsafe(32)

		# Валидация redirect_uris
		redirect_uris = data.get('redirect_uris', [])
		if not redirect_uris:
			return jsonify({"error": "invalid_redirect_uri"}), 400

		# Создаем клиента
		client = OAuth2Client(client_id=client_id,
		                      client_secret=client_secret,
		                      redirect_uris=redirect_uris,
		                      name=data.get('client_name', 'Unknown Client'),
		                      scopes=data.get('scope',
		                                      'openid profile email').split())

		self.clients[client_id] = client

		response = {
		    "client_id": client_id,
		    "client_secret": client_secret,
		    "client_id_issued_at": int(client.created_at.timestamp()),
		    "redirect_uris": redirect_uris,
		    "grant_types": ["authorization_code", "refresh_token"],
		    "response_types": ["code"],
		    "token_endpoint_auth_method": "client_secret_basic"
		}

		return jsonify(response), 201

	def show_login_page(self, request: Request):
		"""Показать страницу логина"""
		login_template = '''
		<!DOCTYPE html>
		<html>
		<head>
				<title>OAuth Login</title>
				<style>
						body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; }
						.form-group { margin-bottom: 15px; }
						label { display: block; margin-bottom: 5px; }
						input[type="email"], input[type="password"] { width: 100%; padding: 8px; }
						button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
						.error { color: red; margin-top: 10px; }
				</style>
		</head>
		<body>
				<h2>OAuth Login</h2>
				<form method="post">
						<div class="form-group">
								<label>Email:</label>
								<input name="email" required>
						</div>
						<div class="form-group">
								<label>Password:</label>
								<input type="password" name="password" required>
						</div>
						<button type="submit">Login</button>
								<div class="error">{{ error }}</div>
				</form>
		</body>
		</html>
		'''

		error = self.session.pop('login_error', None)
		return self.render_template_string(login_template, error=error)

	def render_template_string(self, template: str, error: str = None):
		ret = template.replace("{{ error }}",str(error) if error else "")

		return Response(ret, status_code=HTTPStatus.OK)

	async def handle_login(self, request: Request):
		"""Обработка логина"""
		form_data = await request.form()
		email = form_data.get('email')
		password = form_data.get('password')

		# Простая проверка пользователя (в реальности через БД)
		user = self.users.get(email)
		#if not user or user['password'] != password:
		#	self.session['login_error'] = "Invalid email or password"
		#	return self.show_login_page(request)

		# Сохраняем пользователя в сессии
		#self.session['user_id'] = email

		# Если есть сохраненные OAuth параметры, перенаправляем обратно
		oauth_params = self.session.pop('oauth_params', None)
		if oauth_params:
			retUrl = 'authorize' + '?' + urlencode(oauth_params)
			return RedirectResponse(retUrl)

		return self.jsonify({"message": "Login successful"})

	def _show_consent_page(self, client: OAuth2Client, scope: str,
	                       redirect_uri: str, state: str, code_challenge: str,
	                       code_challenge_method: str):
		"""Показать страницу согласия"""
		consent_template = '''
		<!DOCTYPE html>
		<html>
		<head>
				<title>OAuth Consent</title>
				<style>
						body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; }
						.app-info { background: #f5f5f5; padding: 15px; margin-bottom: 20px; }
						.permissions { margin: 20px 0; }
						.permission { margin: 10px 0; padding: 5px; background: #e8f4f8; }
						.buttons { margin-top: 20px; }
						button { padding: 10px 20px; margin: 5px; border: none; cursor: pointer; }
						.approve { background: #28a745; color: white; }
						.deny { background: #dc3545; color: white; }
				</style>
		</head>
		<body>
				<h2>Authorization Request</h2>
				<div class="app-info">
						<strong>{{ client.name }}</strong> wants to access your account.
				</div>

				<div class="permissions">
						<h3>Permissions requested:</h3>
						{% for scope_item in scopes %}
								<div class="permission">{{ scope_descriptions[scope_item] }}</div>
						{% endfor %}
				</div>

				<form method="post">
						<input type="hidden" name="client_id" value="{{ client.client_id }}">
						<input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
						<input type="hidden" name="scope" value="{{ scope }}">
						<input type="hidden" name="state" value="{{ state }}">
						<input type="hidden" name="code_challenge" value="{{ code_challenge }}">
						<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">

						<div class="buttons">
								<button type="submit" name="consent" value="approve" class="approve">Allow</button>
								<button type="submit" name="consent" value="deny" class="deny">Deny</button>
						</div>
				</form>
		</body>
		</html>
		'''

		scope_descriptions = {
		    'openid': 'Access your identity',
		    'profile': 'Access your profile information',
		    'email': 'Access your email address'
		}

		scopes = scope.split()


		retval=consent_template.replace("{{ client.name }}", client.name)
		retval=retval.replace("{{ client.client_id }}", client.client_id)
		retval=retval.replace("{{ redirect_uri }}", redirect_uri)
		retval=retval.replace("{{ scope }}", scope)
		retval=retval.replace("{{ state }}", state)
		retval=retval.replace("{{ code_challenge }}", code_challenge)
		retval=retval.replace("{{ code_challenge_method }}", code_challenge_method)
		return self.render_template_string(retval,
		                              #scopes=scopes,
		                              #scope_descriptions=scope_descriptions,
		                              #scope=scope,
		                              #redirect_uri=redirect_uri,
		                              #state=state or '',
		                              #code_challenge=code_challenge or '',
		                              #code_challenge_method=code_challenge_method
		                              #or ''
																			)
