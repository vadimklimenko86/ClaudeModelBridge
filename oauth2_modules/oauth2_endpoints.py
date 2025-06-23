"""OAuth 2.0 Endpoints and Routing with SQLite database support"""

import inspect
import secrets
import time
import base64
from typing import Any, Dict, List
from collections.abc import Callable
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from .oauth2_client import OAuth2Client


class OAuth2Endpoints:
	"""Класс для управления endpoints OAuth 2.0 с поддержкой SQLite базы данных"""

	def __init__(self,
	             token_manager,
	             auth_manager,
	             clients: Dict[str, OAuth2Client],
	             users: Dict,
	             private_key,
	             public_key,
	             key_id: str,
	             logger,
	             database=None,
	             issuer: str = None):
		self.token_manager = token_manager
		self.auth_manager = auth_manager
		self.clients = clients
		self.users = users
		self.private_key = private_key
		self.public_key = public_key
		self.key_id = key_id
		self.logger = logger
		self.database = database
		self.routes: List[Route] = []
		self.issuer: str = issuer
		self._register_routes()

	def _get_user(self, user_id: str) -> dict:
		"""Получить пользователя из БД или из памяти"""
		if self.database:
			return self.database.get_user(user_id)
		else:
			return self.users.get(user_id)

	def get_base_url(self, request: Request) -> str:
		"""Получить правильный базовый URL"""
		base_url = str(request.base_url).rstrip('/')

		# Проверяем заголовки для определения реального хоста (для прокси)
		forwarded_host = request.headers.get('x-forwarded-host')
		forwarded_proto = request.headers.get('x-forwarded-proto', 'http')

		if forwarded_host:
			base_url = f"{forwarded_proto}://{forwarded_host}"
		elif 'host' in request.headers:
			# Используем заголовок Host если нет forwarded заголовков
			host = request.headers['host']
			if not (host.startswith('127.0.0.1') or host.startswith('localhost')):
				scheme = 'https' if request.url.scheme == 'https' else forwarded_proto
				base_url = f"{scheme}://{host}"

		return base_url

	def _register_routes(self):
		"""Регистрация всех OAuth 2.0 endpoints"""

		class RouteWrapper:
			"""Обертка для правильной обработки маршрутов"""

			def __init__(self, path: str, endpoint: Callable):
				self.path = path
				self.endpoint = endpoint

			async def __call__(self, scope: Scope, receive: Receive,
			                   send: Send) -> Any:
				request = Request(scope, receive, send)

				# Получаем сигнатуру функции
				sig = inspect.signature(self.endpoint)

				# Если функция принимает request, передаем его
				if 'request' in sig.parameters:
					if inspect.iscoroutinefunction(self.endpoint):
						result = await self.endpoint(request)
					else:
						result = self.endpoint(request)
				else:
					# Вызываем без параметров
					if inspect.iscoroutinefunction(self.endpoint):
						result = await self.endpoint()
					else:
						result = self.endpoint()

				# Обрабатываем результат
				if isinstance(result, Response):
					await result(scope, receive, send)
				else:
					# Если результат не Response, создаем JSONResponse
					response = JSONResponse(result)
					await response(scope, receive, send)

		def route(path: str,
		          methods: list[str] | None = None,
		          name: str | None = None) -> Callable:
			"""Декоратор для регистрации маршрутов"""
			if methods is None:
				methods = ["GET"]

			def decorator(func: Callable) -> Callable:
				wrapper = RouteWrapper(path, func)
				self.routes.append(
				    Route(path, endpoint=wrapper, methods=methods, name=name))
				return func

			return decorator

		# Discovery endpoints
		@route('/.well-known/oauth-protected-resource')
		async def oauth_metadata2(request: Request):
			return await self.get_authorization_server_metadata(request)

		@route('/.well-known/oauth-authorization-server')
		async def oauth_metadata(request: Request):
			return await self.get_authorization_server_metadata(request)

		# JWKS endpoint
		@route('/.well-known/jwks.json')
		async def jwks(request: Request):
			return self.get_jwks(request)

		# Authorization endpoint
		@route('/oauth/authorize', methods=['GET', 'POST'])
		async def authorize(request: Request):
			if request.method == "POST":
				return await self.auth_manager.handle_authorization_submit(request)
			return await self.auth_manager.handle_authorization_request(request)

		# Token endpoint
		@route('/oauth/token', methods=['POST'])
		async def token(request: Request):
			return await self.handle_token_request(request)

		# Userinfo endpoint
		@route('/oauth/userinfo')
		async def user_info(request: Request):
			return self.handle_userinfo_request(request)

		# Login page
		@route('/oauth/login', methods=['GET', 'POST'])
		async def login(request: Request):
			if request.method == "POST":
				return await self.auth_manager.handle_login(request)
			return self.auth_manager.show_login_page(request)

		# Client registration
		@route('/oauth/register', methods=['POST'])
		async def register_client(request: Request):
			return await self.handle_client_registration(request)

		# Revocation endpoint
		@route('/oauth/revoke', methods=['POST'])
		async def revoke_token(request: Request):
			return await self.handle_token_revocation(request)

		# Admin endpoints для управления системой
		@route('/oauth/admin/stats')
		async def admin_stats(request: Request):
			return self.handle_admin_stats(request)

		@route('/oauth/admin/cleanup', methods=['POST'])
		async def admin_cleanup(request: Request):
			return await self.handle_admin_cleanup(request)

	async def get_authorization_server_metadata(
	    self, request: Request) -> JSONResponse:
		"""RFC 8414 - OAuth 2.0 Authorization Server Metadata"""
		base_url = self.issuer or self.get_base_url(request)
		self.logger.warning(f"Base URL: {base_url}")
		metadata = {
		    "issuer":
		    base_url,
		    "authorization_endpoint":
		    f"{base_url}/oauth/authorize",
		    "token_endpoint":
		    f"{base_url}/oauth/token",
		    "jwks_uri":
		    f"{base_url}/.well-known/jwks.json",
		    "userinfo_endpoint":
		    f"{base_url}/oauth/userinfo",
		    "revocation_endpoint":
		    f"{base_url}/oauth/revoke",

		    # Поддерживаемые scopes
		    "scopes_supported":
		    ["openid", "profile", "email", "mcp:read", "mcp:write"],

		    # Типы ответов и режимы
		    "response_types_supported": ["code"],
		    "response_modes_supported": ["query"],
		    "grant_types_supported": ["authorization_code", "refresh_token"],

		    # PKCE - обязательно для безопасности
		    "code_challenge_methods_supported": ["S256", "plain"],

		    # Методы аутентификации клиента
		    "token_endpoint_auth_methods_supported": [
		        "client_secret_post",
		        "client_secret_basic",
		        "none"  # Для публичных клиентов с PKCE
		    ],

		    # Алгоритмы подписи
		    "id_token_signing_alg_values_supported": ["RS256"],
		    "subject_types_supported": ["public"],

		    # Поддерживаемые claims
		    "claims_supported": [
		        "sub", "iss", "aud", "exp", "iat", "nbf", "auth_time", "name",
		        "email", "email_verified", "preferred_username"
		    ],

		    # Дополнительные настройки
		    "request_parameter_supported":
		    False,
		    "request_uri_parameter_supported":
		    False,
		    "require_request_uri_registration":
		    False,

		    # Локализация
		    "ui_locales_supported": ["en", "ru"],
		    "claims_locales_supported": ["en", "ru"],

		    # Настройки logout
		    "frontchannel_logout_supported":
		    False,
		    "frontchannel_logout_session_supported":
		    False,
		    "backchannel_logout_supported":
		    False,
		    "backchannel_logout_session_supported":
		    False,

		    # Дополнительная информация о системе
		    "database_enabled":
		    self.database is not None,
		}

		return JSONResponse(metadata,
		                    headers={
		                        "Content-Type": "application/json",
		                        "Cache-Control": "public, max-age=3600"
		                    })

	def get_jwks(self, request: Request) -> JSONResponse:
		"""JSON Web Key Set endpoint"""
		public_numbers = self.public_key.public_numbers()

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

		return JSONResponse(jwks,
		                    headers={
		                        "Content-Type": "application/json",
		                        "Cache-Control": "public, max-age=3600"
		                    })

	async def handle_token_request(self, request: Request) -> JSONResponse:
		"""Обработка token request"""
		# Получаем параметры из формы
		form_data = await request.form()
		grant_type = form_data.get('grant_type')

		self.logger.info(f"Token request with grant_type: {grant_type}")

		if grant_type == 'authorization_code':
			return await self._handle_authorization_code_grant(request, form_data)
		elif grant_type == 'refresh_token':
			return await self._handle_refresh_token_grant(request, form_data)
		else:
			return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

	async def _handle_authorization_code_grant(self, request: Request,
	                                           form_data) -> JSONResponse:
		"""Обработка authorization_code grant"""
		code = form_data.get('code')
		client_id = form_data.get('client_id')
		client_secret = form_data.get('client_secret')
		redirect_uri = form_data.get('redirect_uri')
		code_verifier = form_data.get('code_verifier')

		# Валидация обязательных параметров
		if not all([code, client_id, redirect_uri]):
			return JSONResponse(
			    {
			        "error": "invalid_request",
			        "error_description": "Missing required parameters"
			    },
			    status_code=400)

		# Валидация authorization code через auth_manager
		code_data = self.auth_manager.get_authorization_code_data(code)
		if not code_data:
			return JSONResponse(
			    {
			        "error": "invalid_grant",
			        "error_description": "Invalid authorization code"
			    },
			    status_code=400)

		# Проверки валидности кода
		if code_data.get('is_used', False):
			return JSONResponse(
			    {
			        "error": "invalid_grant",
			        "error_description": "Authorization code already used"
			    },
			    status_code=400)

		if code_data['expires_at'] < time.time():
			return JSONResponse(
			    {
			        "error": "invalid_grant",
			        "error_description": "Authorization code expired"
			    },
			    status_code=400)

		if code_data['client_id'] != client_id:
			return JSONResponse(
			    {
			        "error": "invalid_grant",
			        "error_description": "Client mismatch"
			    },
			    status_code=400)

		if code_data['redirect_uri'] != redirect_uri:
			return JSONResponse(
			    {
			        "error": "invalid_grant",
			        "error_description": "Redirect URI mismatch"
			    },
			    status_code=400)

		# Проверка клиента (для конфиденциальных клиентов)
		client = self.clients.get(client_id)
		if client and client.client_secret and client.client_secret != client_secret:
			# Только если клиент конфиденциальный и секрет предоставлен
			if client_secret:  # Если секрет предоставлен, он должен быть правильным
				return JSONResponse({"error": "invalid_client"}, status_code=401)

		# PKCE проверка
		if code_data.get('code_challenge'):
			if not code_verifier:
				return JSONResponse(
				    {
				        "error": "invalid_request",
				        "error_description": "Missing code_verifier"
				    },
				    status_code=400)

			if not self.token_manager.verify_pkce(
			    code_verifier, code_data['code_challenge'],
			    code_data.get('code_challenge_method', 'plain')):
				return JSONResponse(
				    {
				        "error": "invalid_grant",
				        "error_description": "Invalid code_verifier"
				    },
				    status_code=400)

		# Помечаем код как использованный
		self.auth_manager.use_authorization_code(code)

		# Генерируем токены
		access_token = self.token_manager.generate_access_token(
		    code_data['user_id'], client_id, code_data['scope'])
		refresh_token = self.token_manager.generate_refresh_token(
		    code_data['user_id'], client_id, code_data['scope'])

		response = {
		    "access_token": access_token,
		    "token_type": "Bearer",
		    "expires_in": 3600,
		    "refresh_token": refresh_token,
		    "scope": code_data['scope']
		}

		# ID Token для OpenID Connect
		if 'openid' in code_data['scope']:
			base_url = self.get_base_url(request)
			id_token = self.token_manager.generate_id_token(request,
			                                                code_data['user_id'],
			                                                client_id, access_token,
			                                                base_url)
			response["id_token"] = id_token

		return JSONResponse(response)

	async def _handle_refresh_token_grant(self, request: Request,
	                                      form_data) -> JSONResponse:
		"""Обработка refresh_token grant"""
		refresh_token = form_data.get('refresh_token')
		client_id = form_data.get('client_id')
		client_secret = form_data.get('client_secret')
		scope = form_data.get('scope')

		if not refresh_token:
			return JSONResponse({"error": "invalid_request"}, status_code=400)

		# Валидация refresh token
		is_valid, token_data = self.token_manager.validate_refresh_token(
		    refresh_token)
		if not is_valid:
			return JSONResponse({"error": "invalid_grant"}, status_code=400)

		# Проверка клиента
		if client_id and token_data['client_id'] != client_id:
			return JSONResponse({"error": "invalid_grant"}, status_code=400)

		# Проверка scope (должен быть подмножеством оригинального)
		original_scopes = set(token_data['scope'].split())
		requested_scopes = set(scope.split()) if scope else original_scopes

		if not requested_scopes.issubset(original_scopes):
			return JSONResponse({"error": "invalid_scope"}, status_code=400)

		# Генерируем новый access token
		access_token = self.token_manager.generate_access_token(
		    token_data['user_id'], token_data['client_id'],
		    ' '.join(requested_scopes))

		response = {
		    "access_token": access_token,
		    "token_type": "Bearer",
		    "expires_in": 3600,
		    "scope": ' '.join(requested_scopes)
		}

		return JSONResponse(response)

	def handle_userinfo_request(self, request: Request) -> JSONResponse:
		"""Обработка userinfo request"""
		auth_header = request.headers.get('Authorization')

		if not auth_header or not auth_header.startswith('Bearer '):
			return JSONResponse({"error": "invalid_token"}, status_code=401)

		access_token = auth_header.split(' ')[1]

		is_valid, token_data = self.token_manager.validate_access_token(
		    access_token)
		if not is_valid:
			return JSONResponse({"error": "invalid_token"}, status_code=401)

		# Проверяем scope
		scopes = token_data['scope'].split()

		user_id = token_data['user_id']
		user = self._get_user(user_id)

		if not user:
			return JSONResponse({"error": "invalid_token"}, status_code=401)

		# Формируем ответ на основе scope
		userinfo = {"sub": user_id}

		if 'profile' in scopes:
			userinfo["name"] = user.get('name')
			userinfo["preferred_username"] = user.get('email')

		if 'email' in scopes:
			userinfo["email"] = user.get('email')
			userinfo["email_verified"] = True

		return JSONResponse(userinfo)

	async def handle_token_revocation(self, request: Request) -> JSONResponse:
		"""Обработка отзыва токена"""
		form_data = await request.form()
		token = form_data.get('token')

		if not token:
			return JSONResponse({}, status_code=200)  # По спецификации всегда 200

		self.token_manager.revoke_token(token)
		return JSONResponse({}, status_code=200)

	async def handle_client_registration(self, request: Request) -> JSONResponse:
		"""Динамическая регистрация клиентов (RFC 7591)"""
		try:
			data = await request.json()
		except:
			return JSONResponse({"error": "invalid_request"}, status_code=400)

		# Валидация redirect_uris
		redirect_uris = data.get('redirect_uris', [])
		if not redirect_uris:
			return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)

		# Генерируем client_id и client_secret
		client_id = f"client_{secrets.token_urlsafe(8)}"
		client_secret = secrets.token_urlsafe(32)

		# Создаем клиента
		client = OAuth2Client(client_id=client_id,
		                      client_secret=client_secret,
		                      redirect_uris=redirect_uris,
		                      name=data.get('client_name', 'Unknown Client'),
		                      grant_types=data.get('grant_types',
		                                           ['authorization_code']),
		                      scopes=data.get('scope',
		                                      'openid profile email').split())

		# Сохраняем клиента
		if self.database:
			success = self.database.create_client(client_id=client_id,
			                                      client_secret=client_secret,
			                                      name=client.name,
			                                      redirect_uris=redirect_uris,
			                                      grant_types=client.grant_types,
			                                      scopes=client.scopes)
			if not success:
				return JSONResponse(
				    {
				        "error": "server_error",
				        "error_description": "Failed to create client"
				    },
				    status_code=500)

		self.clients[client_id] = client

		response = {
		    "client_id": client_id,
		    "client_secret": client_secret,
		    "client_id_issued_at": int(client.created_at.timestamp()),
		    "redirect_uris": redirect_uris,
		    "grant_types": client.grant_types,
		    "response_types": ["code"],
		    "token_endpoint_auth_method": "client_secret_basic",
		    "client_name": client.name,
		    "scope": ' '.join(client.scopes)
		}

		return JSONResponse(response, status_code=201)

	def handle_admin_stats(self, request: Request) -> JSONResponse:
		"""Административная статистика"""
		if self.database:
			stats = self.database.get_stats()
			stats['sessions_count'] = len(self.auth_manager.sessions)
		else:
			token_stats = self.token_manager.get_token_stats()
			auth_stats = self.auth_manager.get_auth_stats()
			stats = {
			    'clients_count': len(self.clients),
			    'users_count': len(self.users),
			    'active_access_tokens': token_stats['active_access_tokens'],
			    'active_refresh_tokens': token_stats['active_refresh_tokens'],
			    'active_authorization_codes':
			    auth_stats['active_authorization_codes'],
			    'sessions_count': auth_stats['active_sessions'],
			    'database_enabled': False
			}

		return JSONResponse({
		    'status': 'success',
		    'stats': stats,
		    'timestamp': time.time()
		})

	async def handle_admin_cleanup(self, request: Request) -> JSONResponse:
		"""Административная очистка устаревших данных"""
		cleaned_tokens = self.token_manager.cleanup_expired_tokens()
		cleaned_codes = self.auth_manager.cleanup_expired_codes()

		total_cleaned = cleaned_tokens + cleaned_codes

		return JSONResponse({
		    'status': 'success',
		    'cleaned': {
		        'tokens': cleaned_tokens,
		        'authorization_codes': cleaned_codes,
		        'total': total_cleaned
		    },
		    'timestamp': time.time()
		})
