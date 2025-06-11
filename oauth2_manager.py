import logging
import secrets
import base64
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
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
	             scopes: List[str] = None):
		self.client_id = client_id
		self.client_secret = client_secret
		self.redirect_uris = redirect_uris
		self.name = name
		self.scopes = scopes or ['openid', 'profile', 'email']
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
		    "client_1749051312": {
		        "client_secret":
		        "claude_secret_key_2024",
		        "redirect_uris": [
		            "https://claude.ai/oauth/callback",
		            "http://localhost:8080/callback",
		            "http://localhost:5000/oauth/callback",
		            "urn:ietf:wg:oauth:2.0:oob"
		        ],
		        "grant_types":
		        ["authorization_code", "refresh_token", "client_credentials"],
		        "response_types": ["code"],
		        "scope":
		        "mcp:tools mcp:resources mcp:prompts system:read system:monitor read write admin claudeai"
		    },
		    "ij9PlHfJpoD8mQftZrNwxA": {
		        "client_secret":
		        "claude_secret_key_2024",
		        "redirect_uris": [
		            "https://claude.ai/oauth/callback",
		            "http://localhost:8080/callback",
		            "http://localhost:5000/oauth/callback",
		            "urn:ietf:wg:oauth:2.0:oob"
		        ],
		        "grant_types":
		        ["authorization_code", "refresh_token", "client_credentials"],
		        "response_types": ["code"],
		        "scope":
		        "mcp:tools mcp:resources mcp:prompts system:read system:monitor read write admin claudeai"
		    }
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
		#@route('/.well-known/oauth-authorization-server')
		async def oauth_metadata(scope: Scope, receive: Receive, send: Send):
			self.logger.info("/.well-known/oauth-authorization-server")
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
		@route('/authorize')
		async def authorize(scope: Scope, receive: Receive, send: Send):
			request = Request(scope, receive)
			response = self.handle_authorization_request(request)
			await response(scope, receive, send)

		# Token endpoint
		@route('/token', methods=['POST'])
		async def token(scope: Scope, receive: Receive, send: Send):
			request = Request(scope, receive)
			response = self.handle_token_request(request)
			await response(scope, receive, send)

	def get_authorization_server_metadata(self, request: Request) -> Response:
		"""RFC 8414 - OAuth 2.0 Authorization Server Metadata"""

		issuer = request.url._url.rstrip('/')
		self.logger.info(f"issuer: {issuer}")
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

	def jsonify(self, data) -> Response:
		response = Response(
		    json.dumps(data),
		    status_code=HTTPStatus.OK,
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
		#	return redirect(url_for('login_page'))

		# Генерируем authorization code
		auth_code = secrets.token_urlsafe(32)

		self.authorization_codes[auth_code] = {
		    'client_id': client_id,
		    #'user_id': session['user_id'],
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

	def handle_token_request(self, request: Request) -> Response:
		"""Обработка token request"""
		grant_type = request.form.get('grant_type')
		throw Exception(f"{grant_type")
		return Response(json.dumps({"error": "unsupported_grant_type"}), 400)
		#if grant_type == 'authorization_code':
		#		return self._handle_authorization_code_grant()
		#elif grant_type == 'refresh_token':
		#		return self._handle_refresh_token_grant()
		#else:
		#		return jsonify({"error": "unsupported_grant_type"}), 400
