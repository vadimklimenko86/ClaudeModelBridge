"""OAuth 2.0 Manager - главный класс для управления OAuth 2.0"""

import hashlib
import logging
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa

from .oauth2_client import OAuth2Client
from .oauth2_tokens import OAuth2TokenManager
from .oauth2_auth import OAuth2AuthManager
from .oauth2_endpoints import OAuth2Endpoints


class OAuth2Manager:
	"""Главный класс для управления OAuth 2.0 авторизацией"""

	def __init__(self, logger: logging.Logger) -> None:
		self.logger = logger
		self.initialize()
		# Генерируем RSA ключи для JWT
		self._generate_keys()
		# Инициализируем компоненты
		self._initialize_components()

	def initialize(self):
		"""Инициализация данных"""
		# Клиенты OAuth 2.0
		self.clients = {
			"client_1749051312": OAuth2Client(
				client_id="client_1749051312",
				client_secret="claude_secret_key_2024",
				redirect_uris=[
					"https://claude.ai/oauth/callback",
					"https://claude.ai/api/mcp/auth_callback"							
				],
				name="Claude MCP Client",
				grant_types=["authorization_code", "refresh_token"],
			)
		}
		
		# Пользователи (в продакшене использовать базу данных)
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
		self.private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048
		)
		self.public_key = self.private_key.public_key()

		# Для JWKS
		self.key_id = secrets.token_urlsafe(8)

	def _initialize_components(self):
		"""Инициализация компонентов системы"""
		# Инициализируем менеджер токенов
		self.token_manager = OAuth2TokenManager(
			self.private_key, 
			self.public_key, 
			self.key_id
		)
		
		# Инициализируем менеджер авторизации
		self.auth_manager = OAuth2AuthManager(
			self.clients,
			self.users
		)
		
		# Инициализируем endpoints
		self.endpoints = OAuth2Endpoints(
			self.token_manager,
			self.auth_manager,
			self.clients,
			self.users,
			self.private_key,
			self.public_key,
			self.key_id,
			self.logger
		)

	@property
	def routes(self):
		"""Возвращает маршруты для интеграции с приложением"""
		return self.endpoints.routes

	def add_client(self, client: OAuth2Client):
		"""Добавить нового клиента"""
		self.clients[client.client_id] = client
		self.logger.info(f"Added OAuth2 client: {client.name} ({client.client_id})")

	def remove_client(self, client_id: str):
		"""Удалить клиента"""
		if client_id in self.clients:
			client_name = self.clients[client_id].name
			del self.clients[client_id]
			self.logger.info(f"Removed OAuth2 client: {client_name} ({client_id})")

	def add_user(self, user_id: str, user_data: dict):
		"""Добавить нового пользователя"""
		self.users[user_id] = user_data
		self.logger.info(f"Added user: {user_id}")

	def remove_user(self, user_id: str):
		"""Удалить пользователя"""
		if user_id in self.users:
			del self.users[user_id]
			self.logger.info(f"Removed user: {user_id}")

	def get_client(self, client_id: str) -> OAuth2Client:
		"""Получить клиента по ID"""
		return self.clients.get(client_id)

	def get_user(self, user_id: str) -> dict:
		"""Получить пользователя по ID"""
		return self.users.get(user_id)

	def revoke_all_user_tokens(self, user_id: str):
		"""Отозвать все токены пользователя"""
		# Отзываем access tokens
		tokens_to_revoke = []
		for token, token_data in self.token_manager.access_tokens.items():
			if token_data['user_id'] == user_id:
				tokens_to_revoke.append(token)
		
		for token in tokens_to_revoke:
			del self.token_manager.access_tokens[token]

		# Отзываем refresh tokens
		tokens_to_revoke = []
		for token, token_data in self.token_manager.refresh_tokens.items():
			if token_data['user_id'] == user_id:
				tokens_to_revoke.append(token)
		
		for token in tokens_to_revoke:
			del self.token_manager.refresh_tokens[token]

		self.logger.info(f"Revoked all tokens for user: {user_id}")

	def get_stats(self) -> dict:
		"""Получить статистику системы"""
		return {
			'clients_count': len(self.clients),
			'users_count': len(self.users),
			'active_access_tokens': len(self.token_manager.access_tokens),
			'active_refresh_tokens': len(self.token_manager.refresh_tokens),
			'active_authorization_codes': len(self.auth_manager.authorization_codes),
			'active_sessions': len(self.auth_manager.sessions)
		}
