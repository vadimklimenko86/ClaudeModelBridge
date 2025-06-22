import inspect
import logging
import secrets
import base64
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs
from collections.abc import Callable
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse, RedirectResponse, Response
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
		self.grant_types = grant_types or ['authorization_code']
		self.created_at = datetime.utcnow()


class OAuth2Manager:
	"""Класс для управления OAuth 2.0 авторизацией"""

	def __init__(self, logger: logging.Logger) -> None:
		self.logger = logger
		self.initialize()
		# Генерируем RSA ключи для JWT
		self._generate_keys()
		self._register_routes()

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
								"authorization_code", "refresh_token"
						],
				)
		}
		self.routes: list[Route] = []
		self.authorization_codes: Dict[str, dict] = {}
		self.access_tokens: Dict[str, dict] = {}
		self.refresh_tokens: Dict[str, dict] = {}
		# Временное хранилище для сессий (в продакшене использовать Redis или базу данных)
		self.sessions: Dict[str, dict] = {}
		self.users = {
				'user@example.com': {
						'id': 'user@example.com',
						'email': 'user@example.com',
						'name': 'Test User',
						'password_hash': hashlib.sha256('password123'.encode()).hexdigest()  # В реальности использовать bcrypt
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

		class RouteWrapper:
			"""Обертка для правильной обработки маршрутов"""
			def __init__(self, path: str, endpoint: Callable):
				self.path = path
				self.endpoint = endpoint

			async def __call__(self, scope: Scope, receive: Receive, send: Send) -> Any:
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

		def route(path: str, methods: list[str] | None = None, name: str | None = None) -> Callable:
			"""Декоратор для регистрации маршрутов"""
			if methods is None:
				methods = ["GET"]
				
			def decorator(func: Callable) -> Callable:
				wrapper = RouteWrapper(path, func)
				self.routes.append(Route(path, endpoint=wrapper, methods=methods, name=name))
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
				return await self.handle_authorization_submit(request)
			return await self.handle_authorization_request(request)

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
				return await self.handle_login(request)
			return self.show_login_page(request)

		# Client registration
		@route('/oauth/register', methods=['POST'])
		async def register_client(request: Request):
			return await self.handle_client_registration(request)

		# Revocation endpoint
		@route('/oauth/revoke', methods=['POST'])
		async def revoke_token(request: Request):
			return await self.handle_token_revocation(request)

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

	async def get_authorization_server_metadata(self, request: Request) -> JSONResponse:
		"""RFC 8414 - OAuth 2.0 Authorization Server Metadata"""
		base_url = self.get_base_url(request)
		
		metadata = {
			"issuer": base_url,
			"authorization_endpoint": f"{base_url}/oauth/authorize",
			"token_endpoint": f"{base_url}/oauth/token",
			"jwks_uri": f"{base_url}/.well-known/jwks.json",
			"userinfo_endpoint": f"{base_url}/oauth/userinfo",
			"revocation_endpoint": f"{base_url}/oauth/revoke",
			
			# Поддерживаемые scopes
			"scopes_supported": [
					"openid",
					"profile", 
					"email",
					"mcp:read",
					"mcp:write"
			],

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
					"sub", "iss", "aud", "exp", "iat", "nbf", "auth_time",
					"name", "email", "email_verified", "preferred_username"
			],

			# Дополнительные настройки
			"request_parameter_supported": False,
			"request_uri_parameter_supported": False,
			"require_request_uri_registration": False,
			
			# Локализация
			"ui_locales_supported": ["en", "ru"],
			"claims_locales_supported": ["en", "ru"],

			# Настройки logout
			"frontchannel_logout_supported": False,
			"frontchannel_logout_session_supported": False,
			"backchannel_logout_supported": False,
			"backchannel_logout_session_supported": False,
		}
		
		return JSONResponse(metadata, headers={
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

		return JSONResponse(jwks, headers={
			"Content-Type": "application/json",
			"Cache-Control": "public, max-age=3600"
		})

	def get_or_create_session(self, request: Request) -> Tuple[str, dict]:
		"""Получить или создать сессию"""
		session_id = request.cookies.get('session_id')
		
		if not session_id or session_id not in self.sessions:
			session_id = secrets.token_urlsafe(32)
			self.sessions[session_id] = {
				'created_at': time.time(),
				'data': {}
			}
			
		return session_id, self.sessions[session_id]['data']

	async def handle_authorization_request(self, request: Request) -> Response:
		"""Обработка authorization request"""
		session_id, session_data = self.get_or_create_session(request)
		
		client_id = request.query_params.get('client_id')
		redirect_uri = request.query_params.get('redirect_uri')
		response_type = request.query_params.get('response_type')
		scope = request.query_params.get('scope', 'openid')
		state = request.query_params.get('state')
		code_challenge = request.query_params.get('code_challenge')
		code_challenge_method = request.query_params.get('code_challenge_method', 'S256')

		# Валидация обязательных параметров
		if not all([client_id, redirect_uri, response_type]):
			return JSONResponse(
				{"error": "invalid_request", "error_description": "Missing required parameters"},
				status_code=400
			)

		# Валидация клиента
		if client_id not in self.clients:
			return JSONResponse(
				{"error": "invalid_client", "error_description": "Unknown client"},
				status_code=400
			)

		client = self.clients[client_id]

		# Валидация redirect_uri
		if redirect_uri not in client.redirect_uris:
			return JSONResponse(
				{"error": "invalid_redirect_uri", "error_description": "Redirect URI not registered"},
				status_code=400
			)

		# Валидация response_type
		if response_type != 'code':
			return self._error_redirect(redirect_uri, "unsupported_response_type", state)

		# Проверка авторизации пользователя
		if 'user_id' not in session_data:
			# Сохраняем OAuth параметры в сессии
			session_data['oauth_params'] = dict(request.query_params)
			
			# Перенаправляем на страницу логина
			response = RedirectResponse(url='/oauth/login', status_code=302)
			response.set_cookie('session_id', session_id, httponly=True, secure=True, samesite='lax')
			return response

		# Пользователь авторизован, генерируем authorization code
		auth_code = secrets.token_urlsafe(32)

		self.authorization_codes[auth_code] = {
				'client_id': client_id,
				'user_id': session_data['user_id'],
				'redirect_uri': redirect_uri,
				'scope': scope,
				'code_challenge': code_challenge,
				'code_challenge_method': code_challenge_method,
				'expires_at': time.time() + 600,  # 10 минут
				'used': False
		}

		# Формируем URL для редиректа
		params = {'code': auth_code}
		if state:
			params['state'] = state

		redirect_url = f"{redirect_uri}?{urlencode(params)}"
		
		self.logger.info(f"Authorization successful, redirecting to: {redirect_url}")
		
		return RedirectResponse(url=redirect_url, status_code=302)

	async def handle_authorization_submit(self, request: Request) -> Response:
		"""Обработка согласия пользователя"""
		session_id, session_data = self.get_or_create_session(request)
		
		if 'user_id' not in session_data:
			return JSONResponse({"error": "unauthorized"}, status_code=401)
			
		form_data = await request.form()
		consent = form_data.get('consent')
		
		# Получаем сохраненные OAuth параметры
		oauth_params = session_data.get('oauth_params', {})
		
		if not oauth_params:
			return JSONResponse({"error": "invalid_request"}, status_code=400)
		
		client_id = oauth_params.get('client_id')
		redirect_uri = oauth_params.get('redirect_uri')
		state = oauth_params.get('state')
		
		if consent != 'approve':
			return self._error_redirect(redirect_uri, "access_denied", state)

		# Используем сохраненные параметры для генерации кода
		auth_code = secrets.token_urlsafe(32)
		
		self.authorization_codes[auth_code] = {
			'client_id': client_id,
			'user_id': session_data['user_id'],
			'redirect_uri': redirect_uri,
			'scope': oauth_params.get('scope', 'openid'),
			'code_challenge': oauth_params.get('code_challenge'),
			'code_challenge_method': oauth_params.get('code_challenge_method', 'S256'),
			'expires_at': time.time() + 600,
			'used': False
		}

		# Очищаем OAuth параметры из сессии
		session_data.pop('oauth_params', None)

		# Формируем URL для редиректа
		params = {'code': auth_code}
		if state:
			params['state'] = state

		redirect_url = f"{redirect_uri}?{urlencode(params)}"
		return RedirectResponse(url=redirect_url, status_code=302)

	def _error_redirect(self, redirect_uri: str, error: str, state: Optional[str] = None) -> Response:
		"""Редирект с ошибкой"""
		params = {'error': error}
		if state:
			params['state'] = state
		error_url = f"{redirect_uri}?{urlencode(params)}"
		return RedirectResponse(url=error_url, status_code=302)

	def _verify_pkce(self, code_verifier: str, code_challenge: str, method: str) -> bool:
		"""Проверка PKCE"""
		if not code_verifier or not code_challenge:
			return False
			
		if method == 'plain':
			return code_verifier == code_challenge
		elif method == 'S256':
			# SHA256 hash of verifier
			challenge = base64.urlsafe_b64encode(
					hashlib.sha256(code_verifier.encode()).digest()
			).decode().rstrip('=')
			return challenge == code_challenge
		return False

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
			return JSONResponse(
				{"error": "unsupported_grant_type"},
				status_code=400
			)

	async def _handle_authorization_code_grant(self, request: Request, form_data) -> JSONResponse:
		"""Обработка authorization_code grant"""
		code = form_data.get('code')
		client_id = form_data.get('client_id')
		client_secret = form_data.get('client_secret')
		redirect_uri = form_data.get('redirect_uri')
		code_verifier = form_data.get('code_verifier')

		# Валидация обязательных параметров
		if not all([code, client_id, redirect_uri]):
			return JSONResponse(
				{"error": "invalid_request", "error_description": "Missing required parameters"},
				status_code=400
			)

		# Валидация authorization code
		if code not in self.authorization_codes:
			return JSONResponse({"error": "invalid_grant", "error_description": "Invalid authorization code"}, status_code=400)

		code_data = self.authorization_codes[code]

		# Проверки валидности кода
		if code_data['used']:
			return JSONResponse({"error": "invalid_grant", "error_description": "Authorization code already used"}, status_code=400)
			
		if code_data['expires_at'] < time.time():
			return JSONResponse({"error": "invalid_grant", "error_description": "Authorization code expired"}, status_code=400)

		if code_data['client_id'] != client_id:
			return JSONResponse({"error": "invalid_grant", "error_description": "Client mismatch"}, status_code=400)

		if code_data['redirect_uri'] != redirect_uri:
			return JSONResponse({"error": "invalid_grant", "error_description": "Redirect URI mismatch"}, status_code=400)

		# Проверка клиента (для конфиденциальных клиентов)
		client = self.clients.get(client_id)
		if client and client.client_secret and client.client_secret != client_secret:
			# Только если клиент конфиденциальный и секрет предоставлен
			if client_secret:  # Если секрет предоставлен, он должен быть правильным
				return JSONResponse({"error": "invalid_client"}, status_code=401)

		# PKCE проверка
		if code_data.get('code_challenge'):
			if not code_verifier:
				return JSONResponse({"error": "invalid_request", "error_description": "Missing code_verifier"}, status_code=400)

			if not self._verify_pkce(code_verifier, code_data['code_challenge'], code_data.get('code_challenge_method', 'plain')):
				return JSONResponse({"error": "invalid_grant", "error_description": "Invalid code_verifier"}, status_code=400)

		# Помечаем код как использованный
		code_data['used'] = True

		# Генерируем токены
		access_token = self._generate_access_token(code_data['user_id'], client_id, code_data['scope'])
		refresh_token = self._generate_refresh_token(code_data['user_id'], client_id, code_data['scope'])

		response = {
				"access_token": access_token,
				"token_type": "Bearer",
				"expires_in": 3600,
				"refresh_token": refresh_token,
				"scope": code_data['scope']
		}

		# ID Token для OpenID Connect
		if 'openid' in code_data['scope']:
			id_token = self._generate_id_token(request, code_data['user_id'], client_id, access_token)
			response["id_token"] = id_token

		return JSONResponse(response)

	async def _handle_refresh_token_grant(self, request: Request, form_data) -> JSONResponse:
		"""Обработка refresh_token grant"""
		refresh_token = form_data.get('refresh_token')
		client_id = form_data.get('client_id')
		client_secret = form_data.get('client_secret')
		scope = form_data.get('scope')

		if not refresh_token:
			return JSONResponse({"error": "invalid_request"}, status_code=400)

		# Валидация refresh token
		if refresh_token not in self.refresh_tokens:
			return JSONResponse({"error": "invalid_grant"}, status_code=400)

		token_data = self.refresh_tokens[refresh_token]

		if token_data['expires_at'] < time.time():
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
		access_token = self._generate_access_token(
			token_data['user_id'],
			token_data['client_id'],
			' '.join(requested_scopes)
		)

		response = {
				"access_token": access_token,
				"token_type": "Bearer",
				"expires_in": 3600,
				"scope": ' '.join(requested_scopes)
		}

		return JSONResponse(response)

	def _generate_access_token(self, user_id: str, client_id: str, scope: str) -> str:
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

	def _generate_refresh_token(self, user_id: str, client_id: str, scope: str) -> str:
		"""Генерация refresh token"""
		token = secrets.token_urlsafe(32)

		self.refresh_tokens[token] = {
				'user_id': user_id,
				'client_id': client_id,
				'scope': scope,
				'expires_at': time.time() + 86400 * 30,  # 30 дней
		}

		return token

	def _generate_id_token(self, request: Request, user_id: str, client_id: str, access_token: str) -> str:
		"""Генерация ID token (JWT) для OpenID Connect"""
		base_url = self.get_base_url(request)
		now = datetime.utcnow()

		payload = {
				'iss': base_url,
				'sub': user_id,
				'aud': client_id,
				'exp': int((now + timedelta(hours=1)).timestamp()),
				'iat': int(now.timestamp()),
				'auth_time': int(now.timestamp()),
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
				encryption_algorithm=serialization.NoEncryption()
		)

		return jwt.encode(
			payload,
			private_key_pem,
			algorithm='RS256',
			headers={'kid': self.key_id}
		)

	def _calculate_at_hash(self, access_token: str) -> str:
		"""Вычисление at_hash для ID token"""
		digest = hashlib.sha256(access_token.encode()).digest()
		return base64.urlsafe_b64encode(digest[:16]).decode().rstrip('=')

	def handle_userinfo_request(self, request: Request) -> JSONResponse:
		"""Обработка userinfo request"""
		auth_header = request.headers.get('Authorization')

		if not auth_header or not auth_header.startswith('Bearer '):
			return JSONResponse({"error": "invalid_token"}, status_code=401)

		access_token = auth_header.split(' ')[1]

		if access_token not in self.access_tokens:
			return JSONResponse({"error": "invalid_token"}, status_code=401)

		token_data = self.access_tokens[access_token]

		if token_data['expires_at'] < time.time():
			return JSONResponse({"error": "invalid_token"}, status_code=401)

		# Проверяем scope
		scopes = token_data['scope'].split()
		
		user_id = token_data['user_id']
		user = self.users.get(user_id)

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
		token_type_hint = form_data.get('token_type_hint')

		if not token:
			return JSONResponse({}, status_code=200)  # По спецификации всегда 200

		# Пытаемся отозвать как access token
		if token in self.access_tokens:
			del self.access_tokens[token]
		# Или как refresh token
		elif token in self.refresh_tokens:
			del self.refresh_tokens[token]

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
		client = OAuth2Client(
			client_id=client_id,
			client_secret=client_secret,
			redirect_uris=redirect_uris,
			name=data.get('client_name', 'Unknown Client'),
			grant_types=data.get('grant_types', ['authorization_code']),
			scopes=data.get('scope', 'openid profile email').split()
		)

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

	def show_login_page(self, request: Request) -> Response:
		"""Показать страницу логина"""
		session_id, session_data = self.get_or_create_session(request)
		error = session_data.get('login_error')
		
		html = f'''
		<!DOCTYPE html>
		<html lang="ru">
		<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Вход в систему</title>
				<style>
						body {{
								font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
								background: #f5f5f5;
								display: flex;
								justify-content: center;
								align-items: center;
								height: 100vh;
								margin: 0;
						}}
						.login-container {{
								background: white;
								padding: 2rem;
								border-radius: 8px;
								box-shadow: 0 2px 10px rgba(0,0,0,0.1);
								width: 100%;
								max-width: 400px;
						}}
						h2 {{
								margin: 0 0 1.5rem 0;
								color: #333;
								text-align: center;
						}}
						.form-group {{
								margin-bottom: 1rem;
						}}
						label {{
								display: block;
								margin-bottom: 0.5rem;
								color: #555;
								font-weight: 500;
						}}
						input[type="email"],
						input[type="password"] {{
								width: 100%;
								padding: 0.75rem;
								border: 1px solid #ddd;
								border-radius: 4px;
								font-size: 1rem;
								transition: border-color 0.2s;
						}}
						input[type="email"]:focus,
						input[type="password"]:focus {{
								outline: none;
								border-color: #007cba;
						}}
						button {{
								width: 100%;
								padding: 0.75rem;
								background: #007cba;
								color: white;
								border: none;
								border-radius: 4px;
								font-size: 1rem;
								font-weight: 500;
								cursor: pointer;
								transition: background 0.2s;
						}}
						button:hover {{
								background: #005a87;
						}}
						.error {{
								color: #d73502;
								margin-top: 1rem;
								padding: 0.75rem;
								background: #fef2f2;
								border-radius: 4px;
								font-size: 0.875rem;
						}}
						.info {{
								margin-top: 1rem;
								padding: 0.75rem;
								background: #e3f2fd;
								border-radius: 4px;
								font-size: 0.875rem;
								color: #1976d2;
						}}
				</style>
		</head>
		<body>
				<div class="login-container">
						<h2>Вход в систему OAuth</h2>
						<form method="post">
								<div class="form-group">
										<label for="email">Email:</label>
										<input type="email" id="email" name="email" required value="user@example.com">
								</div>
								<div class="form-group">
										<label for="password">Пароль:</label>
										<input type="password" id="password" name="password" required>
								</div>
								<button type="submit">Войти</button>
								{f'<div class="error">{error}</div>' if error else ''}
								<div class="info">
										Для тестирования используйте:<br>
										Email: user@example.com<br>
										Пароль: password123
								</div>
						</form>
				</div>
		</body>
		</html>
		'''
		
		response = Response(content=html, media_type="text/html")
		response.set_cookie('session_id', session_id, httponly=True, secure=True, samesite='lax')
		return response

	async def handle_login(self, request: Request) -> Response:
		"""Обработка логина"""
		session_id, session_data = self.get_or_create_session(request)
		
		form_data = await request.form()
		email = form_data.get('email')
		password = form_data.get('password')

		# Проверка пользователя
		user = self.users.get(email)
		if not user or hashlib.sha256(password.encode()).hexdigest() != user['password_hash']:
			session_data['login_error'] = "Неверный email или пароль"
			return RedirectResponse(url='/oauth/login', status_code=302)

		# Сохраняем пользователя в сессии
		session_data['user_id'] = email
		session_data.pop('login_error', None)

		# Если есть сохраненные OAuth параметры, показываем страницу согласия
		oauth_params = session_data.get('oauth_params')
		if oauth_params:
			# Показываем страницу согласия
			client = self.clients.get(oauth_params.get('client_id'))
			if client:
				return self._show_consent_page(request, client, oauth_params)
			
		# Иначе просто показываем успешный вход
		return Response(
			content="Вход выполнен успешно",
			media_type="text/plain"
		)

	def _show_consent_page(self, request: Request, client: OAuth2Client, oauth_params: dict) -> Response:
		"""Показать страницу согласия"""
		session_id, _ = self.get_or_create_session(request)
		
		scope = oauth_params.get('scope', 'openid')
		scopes = scope.split()
		
		scope_descriptions = {
				'openid': 'Доступ к вашей идентичности',
				'profile': 'Доступ к информации профиля',
				'email': 'Доступ к вашему email адресу',
				'mcp:read': 'Чтение данных MCP',
				'mcp:write': 'Запись данных MCP'
		}
		
		scope_items_html = ''.join([
			f'<div class="permission">{scope_descriptions.get(s, s)}</div>'
			for s in scopes
		])
		
		html = f'''
		<!DOCTYPE html>
		<html lang="ru">
		<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Запрос авторизации</title>
				<style>
						body {{
								font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
								background: #f5f5f5;
								display: flex;
								justify-content: center;
								align-items: center;
								min-height: 100vh;
								margin: 0;
								padding: 1rem;
						}}
						.consent-container {{
								background: white;
								padding: 2rem;
								border-radius: 8px;
								box-shadow: 0 2px 10px rgba(0,0,0,0.1);
								width: 100%;
								max-width: 500px;
						}}
						h2 {{
								margin: 0 0 1.5rem 0;
								color: #333;
						}}
						.app-info {{
								background: #f8f9fa;
								padding: 1rem;
								border-radius: 4px;
								margin-bottom: 1.5rem;
						}}
						.app-info strong {{
								color: #007cba;
						}}
						.permissions {{
								margin: 1.5rem 0;
						}}
						.permissions h3 {{
								margin: 0 0 1rem 0;
								color: #555;
								font-size: 1.1rem;
						}}
						.permission {{
								margin: 0.5rem 0;
								padding: 0.75rem;
								background: #e3f2fd;
								border-radius: 4px;
								color: #1565c0;
						}}
						.buttons {{
								display: flex;
								gap: 1rem;
								margin-top: 2rem;
						}}
						button {{
								flex: 1;
								padding: 0.75rem 1.5rem;
								border: none;
								border-radius: 4px;
								font-size: 1rem;
								font-weight: 500;
								cursor: pointer;
								transition: background 0.2s;
						}}
						.approve {{
								background: #28a745;
								color: white;
						}}
						.approve:hover {{
								background: #218838;
						}}
						.deny {{
								background: #dc3545;
								color: white;
						}}
						.deny:hover {{
								background: #c82333;
						}}
				</style>
		</head>
		<body>
				<div class="consent-container">
						<h2>Запрос на авторизацию</h2>
						<div class="app-info">
								<strong>{client.name}</strong> запрашивает доступ к вашей учетной записи.
						</div>

						<div class="permissions">
								<h3>Запрашиваемые разрешения:</h3>
								{scope_items_html}
						</div>

						<form method="post" action="/oauth/authorize">
								<div class="buttons">
										<button type="submit" name="consent" value="approve" class="approve">Разрешить</button>
										<button type="submit" name="consent" value="deny" class="deny">Отклонить</button>
								</div>
						</form>
				</div>
		</body>
		</html>
		'''
		
		response = Response(content=html, media_type="text/html")
		response.set_cookie('session_id', session_id, httponly=True, secure=True, samesite='lax')
		return response
