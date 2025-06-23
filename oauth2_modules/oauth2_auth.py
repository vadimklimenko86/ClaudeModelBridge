"""OAuth 2.0 Authorization and Authentication"""

import secrets
import time
import hashlib
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode
from starlette.requests import Request
from starlette.responses import Response, JSONResponse, RedirectResponse

from .oauth2_client import OAuth2Client


class OAuth2AuthManager:
	"""Класс для управления авторизацией и аутентификацией"""

	def __init__(self, clients: Dict[str, OAuth2Client], users: Dict):
		self.clients = clients
		self.users = users
		self.authorization_codes: Dict[str, dict] = {}
		# Временное хранилище для сессий (в продакшене использовать Redis или базу данных)
		self.sessions: Dict[str, dict] = {}

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

	def _error_redirect(self, redirect_uri: str, error: str, state: Optional[str] = None) -> Response:
		"""Редирект с ошибкой"""
		params = {'error': error}
		if state:
			params['state'] = state
		error_url = f"{redirect_uri}?{urlencode(params)}"
		return RedirectResponse(url=error_url, status_code=302)

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
