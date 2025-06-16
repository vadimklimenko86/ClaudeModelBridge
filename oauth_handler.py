import logging
import secrets
import base64
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify, redirect, render_template_string, session, url_for
from starlette.applications import Starlette


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


class OAuth2Handler:
    """Полная реализация OAuth 2.0 Authorization Server"""

    def __init__(self, app: Flask):
        self.app = app
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

        # Генерируем RSA ключи для JWT
        self._generate_keys()

        # Пользователи (в реальном приложении это должно быть в БД)
        self.users = {
            'user@example.com': {
                'id': '1',
                'email': 'user@example.com',
                'name': 'Test User',
                'password': 'password123'  # В реальности должен быть хеш
            }
        }

        if app:
            self.init_app(app)

    def _generate_keys(self):
        """Генерация RSA ключей для подписи JWT"""
        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=2048)
        self.public_key = self.private_key.public_key()

        # Для JWKS
        self.key_id = secrets.token_urlsafe(8)

    def init_app(self, app: Flask):
        """Инициализация Flask приложения с OAuth endpoints"""
        self.app = app
        self._register_routes()

    def _register_routes(self):
        """Регистрация всех OAuth 2.0 endpoints"""

        # Discovery endpoint
        @self.app.route('/.well-known/oauth-authorization-server')
        def oauth_metadata():
            return self.get_authorization_server_metadata()

        # JWKS endpoint
        @self.app.route('/.well-known/jwks.json')
        def jwks():
            return self.get_jwks()

        # Authorization endpoint
        @self.app.route('/oauth/authorize')
        def authorize():
            return self.handle_authorization_request()

        # Authorization form submission
        @self.app.route('/oauth/authorize', methods=['POST'])
        def authorize_post():
            return self.handle_authorization_submit()

        # Token endpoint
        @self.app.route('/oauth/token', methods=['POST'])
        def token():
            return self.handle_token_request()

        # Userinfo endpoint
        @self.app.route('/oauth/userinfo')
        def userinfo():
            return self.handle_userinfo_request()

        # Client registration endpoint
        @self.app.route('/oauth/register', methods=['POST'])
        def register_client():
            return self.handle_client_registration()

        # Login page
        @self.app.route('/login')
        def login_page():
            return self.show_login_page()

        # Login form submission
        @self.app.route('/login', methods=['POST'])
        def login_submit():
            return self.handle_login()

    def get_authorization_server_metadata(self):
        """RFC 8414 - OAuth 2.0 Authorization Server Metadata"""
        issuer = request.url_root.rstrip('/')

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

        return jsonify(metadata)

    def get_jwks(self):
        """JSON Web Key Set endpoint"""
        public_numbers = self.public_key.public_numbers()

        # Конвертируем в base64url
        def int_to_base64url(val):
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
            return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip(
                '=')

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

        return jsonify(jwks)

    def handle_authorization_request(self):
        """Обработка authorization request"""
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type')
        scope = request.args.get('scope', 'openid')
        state = request.args.get('state')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method',
                                                 'S256')

        # Валидация клиента
        if not client_id or client_id not in self.clients:
            return jsonify({"error": "invalid_client"}), 400

        client = self.clients[client_id]

        # Валидация redirect_uri
        #if redirect_uri not in client.redirect_uris:
        #    return jsonify({"error": "invalid_redirect_uri"}), 400

        # Валидация response_type
        if response_type not in ['code', 'token', 'id_token']:
            return self._error_redirect(redirect_uri,
                                        "unsupported_response_type", state)

        # Проверка авторизации пользователя
        if 'user_id' not in session:
            # Сохраняем параметры для возврата после логина
            session['oauth_params'] = request.args.to_dict()
            return redirect(url_for('login_page'))

        # Генерируем authorization code
        auth_code = secrets.token_urlsafe(32)

        self.authorization_codes[auth_code] = {
            'client_id': client_id,
            'user_id': client_id,#session['user_id'],
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

        return redirect(redirect_url)

        # Показываем страницу согласия
        return self._show_consent_page(client, scope, redirect_uri, state,
                                       code_challenge, code_challenge_method)

    def handle_authorization_submit(self):
        """Обработка согласия пользователя"""
        if 'user_id' not in session:
            return jsonify({"error": "unauthorized"}), 401

        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        scope = request.form.get('scope')
        state = request.form.get('state')
        code_challenge = request.form.get('code_challenge')
        code_challenge_method = request.form.get('code_challenge_method')
        consent = request.form.get('consent')

        if consent != 'approve':
            return self._error_redirect(redirect_uri, "access_denied", state)

        # Генерируем authorization code
        auth_code = secrets.token_urlsafe(32)

        self.authorization_codes[auth_code] = {
            'client_id': client_id,
            'user_id': client_id,#session['user_id'],
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
        return redirect(redirect_url)

    def handle_token_request(self):
        """Обработка token request"""
        grant_type = request.form.get('grant_type')

        if grant_type == 'authorization_code':
            return self._handle_authorization_code_grant()
        elif grant_type == 'refresh_token':
            return self._handle_refresh_token_grant()
        else:
            return jsonify({"error": "unsupported_grant_type"}), 400

    def _handle_authorization_code_grant(self):
        """Обработка authorization_code grant"""
        code = request.form.get('code')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        redirect_uri = request.form.get('redirect_uri')
        code_verifier = request.form.get('code_verifier')

        # Валидация клиента
        if not self._authenticate_client(client_id, client_secret):
            return jsonify({"error": "invalid_client"}), 401

        # Валидация authorization code
        if code not in self.authorization_codes:
            return jsonify({"error": "invalid_grant"}), 400

        code_data = self.authorization_codes[code]

        # Проверки
        if code_data['used'] or code_data['expires_at'] < time.time():
            return jsonify({"error": "invalid_grant"}), 400

        if code_data['client_id'] != client_id:
            return jsonify({"error": "invalid_grant"}), 400

        if code_data['redirect_uri'] != redirect_uri:
            return jsonify({"error": "invalid_grant"}), 400

        # PKCE проверка
        if code_data.get('code_challenge'):
            if not code_verifier:
                return jsonify({"error": "invalid_request"}), 400

            if not self._verify_pkce(
                    code_verifier, code_data['code_challenge'],
                    code_data.get('code_challenge_method', 'S256')):
                return jsonify({"error": "invalid_grant"}), 400

        # Помечаем код как использованный
        code_data['used'] = True

        # Генерируем токены
        access_token = self._generate_access_token(code_data['user_id'],
                                                   client_id,
                                                   code_data['scope'])

        refresh_token = self._generate_refresh_token(code_data['user_id'],
                                                     client_id,
                                                     code_data['scope'])

        # ID Token для OpenID Connect
        id_token = None
        if 'openid' in code_data['scope']:
            id_token = self._generate_id_token(code_data['user_id'], client_id,
                                               access_token)

        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": code_data['scope']
        }

        if id_token:
            response["id_token"] = id_token

        return jsonify(response)

    def _handle_refresh_token_grant(self):
        """Обработка refresh_token grant"""
        refresh_token = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        scope = request.form.get('scope')

        # Валидация клиента
        if not self._authenticate_client(client_id, client_secret):
            return jsonify({"error": "invalid_client"}), 401

        # Валидация refresh token
        if refresh_token not in self.refresh_tokens:
            return jsonify({"error": "invalid_grant"}), 400

        token_data = self.refresh_tokens[refresh_token]

        if token_data['expires_at'] < time.time():
            return jsonify({"error": "invalid_grant"}), 400

        if token_data['client_id'] != client_id:
            return jsonify({"error": "invalid_grant"}), 400

        # Используем оригинальный scope или новый (если он subset)
        original_scopes = set(token_data['scope'].split())
        requested_scopes = set(scope.split()) if scope else original_scopes

        if not requested_scopes.issubset(original_scopes):
            return jsonify({"error": "invalid_scope"}), 400

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

        return jsonify(response)

    def handle_userinfo_request(self):
        """Обработка userinfo request"""
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "invalid_token"}), 401

        access_token = auth_header.split(' ')[1]

        if access_token not in self.access_tokens:
            return jsonify({"error": "invalid_token"}), 401

        token_data = self.access_tokens[access_token]

        if token_data['expires_at'] < time.time():
            return jsonify({"error": "invalid_token"}), 401

        # Проверяем scope
        scopes = token_data['scope'].split()
        if 'profile' not in scopes and 'email' not in scopes:
            return jsonify({"error": "insufficient_scope"}), 403

        user_id = token_data['user_id']
        user = self.users.get(user_id)

        if not user:
            return jsonify({"error": "invalid_token"}), 401

        # Формируем ответ на основе scope
        userinfo = {"sub": user_id}

        if 'profile' in scopes:
            userinfo["name"] = user.get('name')

        if 'email' in scopes:
            userinfo["email"] = user.get('email')
            userinfo["email_verified"] = True

        return jsonify(userinfo)

    def handle_client_registration(self):
        """Динамическая регистрация клиентов (RFC 7591)"""
        data = request.get_json()

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

    def show_login_page(self):
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
                    <input type="email" name="email" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Login</button>
                {% if error %}
                    <div class="error">{{ error }}</div>
                {% endif %}
            </form>
        </body>
        </html>
        '''

        error = session.pop('login_error', None)
        return render_template_string(login_template, error=error)

    def handle_login(self):
        """Обработка логина"""
        email = request.form.get('email')
        password = request.form.get('password')

        # Простая проверка пользователя (в реальности через БД)
        user = self.users.get(email)
        if not user or user['password'] != password:
            session['login_error'] = "Invalid email or password"
            return redirect(url_for('login_page'))

        # Сохраняем пользователя в сессии
        session['user_id'] = email

        # Если есть сохраненные OAuth параметры, перенаправляем обратно
        oauth_params = session.pop('oauth_params', None)
        if oauth_params:
            return redirect(
                url_for('authorize') + '?' + urlencode(oauth_params))

        return jsonify({"message": "Login successful"})

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

        return render_template_string(
            consent_template,
            client=client,
            scopes=scopes,
            scope_descriptions=scope_descriptions,
            scope=scope,
            redirect_uri=redirect_uri,
            state=state or '',
            code_challenge=code_challenge or '',
            code_challenge_method=code_challenge_method or '')

    def _authenticate_client(self, client_id: str, client_secret: str) -> bool:
        """Аутентификация клиента"""
        client = self.clients.get(client_id)
        return client and client.client_secret == client_secret

    def _verify_pkce(self, code_verifier: str, code_challenge: str,
                     method: str) -> bool:
        """Проверка PKCE"""
        if method == 'plain':
            return code_verifier == code_challenge
        elif method == 'S256':
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(
                    code_verifier.encode()).digest()).decode().rstrip('=')
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

    def _generate_id_token(self, user_id: str, client_id: str,
                           access_token: str) -> str:
        """Генерация ID token (JWT) для OpenID Connect"""
        issuer = request.url_root.rstrip('/')
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

    def _error_redirect(self,
                        redirect_uri: str,
                        error: str,
                        state: str = None) -> str:
        """Редирект с ошибкой"""
        params = {'error': error}
        if state:
            params['state'] = state

        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        return redirect(redirect_url)

    def register_client(self,
                        client_id: str,
                        client_secret: str,
                        redirect_uris: List[str],
                        name: str,
                        scopes: List[str] = None) -> OAuth2Client:
        """Программная регистрация клиента"""
        client = OAuth2Client(client_id, client_secret, redirect_uris, name,
                              scopes)
        self.clients[client_id] = client
        return client
