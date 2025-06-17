import logging
import secrets
import base64
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.handlers.authorize import Response, RedirectResponse
from starlette.applications import Starlette
from starlette.requests import Request
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

	def __init__(self, app: Starlette, logger: logging.Logger) -> None:
		self.app = app

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
		        redirect_uris=["https://claude.ai/oauth/callback"],
		        name="",
		        grant_types=[
		            "authorization_code", "refresh_token", "client_credentials"
		        ],
		    )
		}

		self.authorization_codes: Dict[str, dict] = {}
		self.access_tokens: Dict[str, dict] = {}
		self.refresh_tokens: Dict[str, dict] = {}
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

		def route(path: str,
		          methods: list[str] | None = None,
		          name: str | None = None) -> Callable:  # type: ignore[type-arg]

			def decorator(func: Callable) -> Callable:  # type: ignore[type-arg]
				self.app.router.mount(path, app=func)
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
		@route('/.well-known/oauth-authorization-server')
		async def oauth_metadata(scope: Scope, receive: Receive, send: Send):

			request = Request(scope, receive)
			response = self.get_authorization_server_metadata(request)
			await response(scope, receive, send)

		# JWKS endpoint
		@route('/.well-known/jwks.json')
		async def jwks(scope: Scope, receive: Receive, send: Send):
			request = Request(scope, receive)
			response = self.get_jwks(request)
			await response(scope, receive, send)

		# Authorization endpoint
		@route('/oauth/authorize')
		async def authorize(scope: Scope, receive: Receive, send: Send):
			request = Request(scope, receive)
			response = self.handle_authorization_request(request)
			await response(scope, receive, send)

		# Token endpoint
		@route('/oauth/token', methods=['POST'])
		async def token(scope: Scope, receive: Receive, send: Send):
			request = Request(scope, receive)
			response = await self.handle_token_request(request)
			await response(scope, receive, send)

	def get_authorization_server_metadata(self, request: Request) -> Response:
		"""RFC 8414 - OAuth 2.0 Authorization Server Metadata"""

		issuer = request.base_url._url.rstrip('/')
		metadata = {
		    "issuer":
		    issuer,
		    "authorization_endpoint":
		    f"{issuer}/oauth/authorize",
		    "token_endpoint":
		    f"{issuer}/oauth/token",
		    "userinfo_endpoint":
		    f"{issuer}/oauth/userinfo",
		    "jwks_uri":
		    f"{issuer}/.well-known/jwks.json",
		    "registration_endpoint":
		    f"{issuer}/oauth/register",
		    "scopes_supported": ["openid", "profile", "email"],
		    "response_types_supported": ["code", "id_token", "token"],
		    "response_modes_supported": ["query", "fragment", "form_post"],
		    "grant_types_supported":
		    ["authorization_code", "implicit", "refresh_token"],
		    "subject_types_supported": ["public"],
		    "id_token_signing_alg_values_supported": ["RS256"],
		    "token_endpoint_auth_methods_supported":
		    ["client_secret_basic", "client_secret_post"],
		    "claims_supported":
		    ["sub", "iss", "aud", "exp", "iat", "name", "email"],
		    "code_challenge_methods_supported": ["S256", "plain"]
		}
		response = Response(
		    json.dumps(metadata),
		    status_code=HTTPStatus.OK,
		)
		return response
		#return jsonify(metadata)

	def jsonify(self, data, status_code: int = HTTPStatus.OK) -> Response:
		response = Response(
		    json.dumps(data),
		    status_code=status_code,
		)
		return response

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

	def handle_authorization_request(self, request: Request) -> Response:
		"""Обработка authorization request"""
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
		#if redirect_uri not in client.redirect_uris:
		#    return jsonify({"error": "invalid_redirect_uri"}), 400

		# Валидация response_type
		if response_type not in ['code', 'token', 'id_token']:
			#return self._error_redirect(redirect_uri, "unsupported_response_type",state)
			return Response(
			    json.dumps({"error": f"unsupported_response_type {response_type}"}),
			    400)

		# Проверка авторизации пользователя
		#if 'user_id' not in self.session:
		#	# Сохраняем параметры для возврата после логина
		#	session['oauth_params'] = request.query_params.to_dict()
		#	return RedirectResponse('login_page')

		# Генерируем authorization code
		auth_code = secrets.token_urlsafe(32)

		self.authorization_codes[auth_code] = {
		    'client_id': client_id,
		    'user_id': client_id,  #session['user_id'],
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

		logging.info(f'Redirecting to: {redirect_url}')
		return RedirectResponse(redirect_url)
		#return Response(redirect_uri, HTTPStatus.TEMPORARY_REDIRECT)

		# Показываем страницу согласия
		return self._show_consent_page(client, scope, redirect_uri, state,
		                               code_challenge, code_challenge_method)

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
		code = form_data.get('code')
		client_id = form_data.get('client_id')
		client_secret = form_data.get('client_secret')
		redirect_uri = form_data.get('redirect_uri')
		code_verifier = form_data.get('code_verifier')

		# Валидация клиента
		if not self._authenticate_client(client_id, client_secret):
			return self.jsonify({"error": "invalid_client"}, 401)

		# Валидация authorization code
		if code not in self.authorization_codes:
			return self.jsonify({"error": "invalid_grant"}, 400)

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
			                         code_data.get('code_challenge_method', 'S256')):
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
		grant_type = form_data.get('grant_type')
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
