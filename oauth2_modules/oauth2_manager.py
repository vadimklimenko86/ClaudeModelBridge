"""OAuth 2.0 Manager - главный класс для управления OAuth 2.0 с поддержкой SQLite"""

import hashlib
import logging
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa

from .oauth2_client import OAuth2Client
from .oauth2_tokens import OAuth2TokenManager
from .oauth2_auth import OAuth2AuthManager
from .oauth2_endpoints import OAuth2Endpoints
from .oauth2_database import OAuth2Database


class OAuth2Manager:
	"""Главный класс для управления OAuth 2.0 авторизацией с поддержкой SQLite базы данных"""

	def __init__(self,
	             logger: logging.Logger,
	             db_url: str = None,
	             use_database: bool = True,
	             issuer: str = None) -> None:
		self.logger = logger
		self.use_database = use_database
		self.issuer: str = issuer

		# Инициализируем базу данных если требуется
		if self.use_database:
			self.database = OAuth2Database(db_url, logger)
			self.logger.info(f"OAuth2 database initialized at: {db_url}")
		else:
			self.database = None
			self.logger.info("OAuth2 running in memory-only mode")

		# Инициализируем компоненты
		self.initialize()
		self._generate_keys()
		self._initialize_components()

		# Создаем тестовые данные если база данных пуста
		if self.use_database:
			self._ensure_test_data()

	def initialize(self):
		"""Инициализация данных"""
		if self.use_database:
			# Загружаем клиентов из базы данных
			self.clients = {}
			db_clients = self.database.list_clients()
			for client_data in db_clients:
				client = OAuth2Client(
				    client_id=client_data['client_id'],
				    client_secret=client_data['client_secret'],
				    redirect_uris=client_data['redirect_uris'],
				    name=client_data['name'],
				    grant_types=client_data['grant_types'],
				)
				self.clients[client.client_id] = client

			# Пользователи загружаются динамически из БД
			self.users = {}  # Совместимость со старым кодом
		else:
			# Резервный режим в памяти
			self.clients = {
			    "client_1749051312":
			    OAuth2Client(
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
			        'password_hash':
			        hashlib.sha256('password123'.encode()).hexdigest()
			    }
			}

	def _ensure_test_data(self):
		"""Создание тестовых данных если база данных пуста"""
		# Проверяем есть ли клиенты
		if not self.database.list_clients():
			# Создаем тестового клиента
			self.database.create_client(
			    client_id="client_1749051312",
			    client_secret="claude_secret_key_2024",
			    name="Claude MCP Client",
			    redirect_uris=[
			        "https://claude.ai/oauth/callback",
			        "https://claude.ai/api/mcp/auth_callback"
			    ],
			    grant_types=["authorization_code", "refresh_token"],
			    scopes=["openid", "profile", "email"])

			# Загружаем созданного клиента
			client_data = self.database.get_client("client_1749051312")
			if client_data:
				client = OAuth2Client(
				    client_id=client_data['client_id'],
				    client_secret=client_data['client_secret'],
				    redirect_uris=client_data['redirect_uris'],
				    name=client_data['name'],
				    grant_types=client_data['grant_types'],
				)
				self.clients[client.client_id] = client

		# Проверяем есть ли пользователи
		if not self.database.list_users():
			# Создаем тестового пользователя
			self.database.create_user(user_id="user@example.com",
			                          email="user@example.com",
			                          name="Test User",
			                          password_hash=hashlib.sha256(
			                              'password123'.encode()).hexdigest())
			self.logger.info(
			    "Created test user: user@example.com (password: password123)")

	def _generate_keys(self):
		"""Генерация RSA ключей для подписи JWT"""
		self.private_key = rsa.generate_private_key(public_exponent=65537,
		                                            key_size=2048)
		self.public_key = self.private_key.public_key()

		# Для JWKS
		self.key_id = secrets.token_urlsafe(8)

	def _initialize_components(self):
		"""Инициализация компонентов системы"""
		# Инициализируем менеджер токенов
		self.token_manager = OAuth2TokenManager(
		    self.private_key,
		    self.public_key,
		    self.key_id,
		    self.database  # Передаем ссылку на базу данных
		)

		# Инициализируем менеджер авторизации
		self.auth_manager = OAuth2AuthManager(
		    self.clients,
		    self.users,
		    self.database  # Передаем ссылку на базу данных
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
		    self.logger,
		    self.database,  # Передаем ссылку на базу данных
		    self.issuer)

	@property
	def routes(self):
		"""Возвращает маршруты для интеграции с приложением"""
		return self.endpoints.routes

	def add_client(self, client: OAuth2Client):
		"""Добавить нового клиента"""
		if self.use_database:
			success = self.database.create_client(client_id=client.client_id,
			                                      client_secret=client.client_secret,
			                                      name=client.name,
			                                      redirect_uris=client.redirect_uris,
			                                      grant_types=client.grant_types,
			                                      scopes=getattr(
			                                          client, 'scopes', []))
			if success:
				self.clients[client.client_id] = client
				self.logger.info(
				    f"Added OAuth2 client to database: {client.name} ({client.client_id})"
				)
			else:
				self.logger.error(f"Failed to add OAuth2 client: {client.client_id}")
		else:
			self.clients[client.client_id] = client
			self.logger.info(
			    f"Added OAuth2 client: {client.name} ({client.client_id})")

	def remove_client(self, client_id: str):
		"""Удалить клиента"""
		if self.use_database:
			success = self.database.delete_client(client_id)
			if success and client_id in self.clients:
				client_name = self.clients[client_id].name
				del self.clients[client_id]
				self.logger.info(
				    f"Removed OAuth2 client from database: {client_name} ({client_id})"
				)
		else:
			if client_id in self.clients:
				client_name = self.clients[client_id].name
				del self.clients[client_id]
				self.logger.info(f"Removed OAuth2 client: {client_name} ({client_id})")

	def add_user(self, user_id: str, email: str, name: str, password_hash: str):
		"""Добавить нового пользователя"""
		if self.use_database:
			success = self.database.create_user(user_id=user_id,
			                                    email=email,
			                                    name=name,
			                                    password_hash=password_hash)
			if success:
				self.logger.info(f"Added user to database: {user_id}")
			else:
				self.logger.error(f"Failed to add user: {user_id}")
		else:
			user_data = {
			    'id': user_id,
			    'email': email,
			    'name': name,
			    'password_hash': password_hash
			}
			self.users[user_id] = user_data
			self.logger.info(f"Added user: {user_id}")

	def remove_user(self, user_id: str):
		"""Удалить пользователя"""
		if self.use_database:
			# Сначала отзываем все токены пользователя
			self.revoke_all_user_tokens(user_id)
			# Деактивируем пользователя
			success = self.database.deactivate_user(user_id)
			if success:
				self.logger.info(f"Deactivated user: {user_id}")
		else:
			if user_id in self.users:
				# Отзываем токены
				self.revoke_all_user_tokens(user_id)
				del self.users[user_id]
				self.logger.info(f"Removed user: {user_id}")

	def get_client(self, client_id: str) -> OAuth2Client:
		"""Получить клиента по ID"""
		if self.use_database and client_id not in self.clients:
			# Попытаемся загрузить из базы данных
			client_data = self.database.get_client(client_id)
			if client_data:
				client = OAuth2Client(
				    client_id=client_data['client_id'],
				    client_secret=client_data['client_secret'],
				    redirect_uris=client_data['redirect_uris'],
				    name=client_data['name'],
				    grant_types=client_data['grant_types'],
				)
				self.clients[client_id] = client
				return client

		return self.clients.get(client_id)

	def get_user(self, user_id: str) -> dict:
		"""Получить пользователя по ID"""
		if self.use_database:
			return self.database.get_user(user_id)
		else:
			return self.users.get(user_id)

	def get_user_by_email(self, email: str) -> dict:
		"""Получить пользователя по email"""
		if self.use_database:
			return self.database.get_user_by_email(email)
		else:
			for user in self.users.values():
				if user.get('email') == email:
					return user
			return None

	def revoke_all_user_tokens(self, user_id: str):
		"""Отозвать все токены пользователя"""
		revoked_count = self.token_manager.revoke_all_user_tokens(user_id)
		self.logger.info(f"Revoked {revoked_count} tokens for user: {user_id}")

	def cleanup_expired_data(self):
		"""Очистка истекших данных"""
		# Очищаем токены
		tokens_cleaned = self.token_manager.cleanup_expired_tokens()

		# Очищаем коды авторизации если используется база данных
		if self.use_database:
			total_cleaned = self.database.cleanup_expired_tokens()
			self.logger.info(
			    f"Cleaned up {total_cleaned} expired entries from database")
		else:
			self.logger.info(
			    f"Cleaned up {tokens_cleaned} expired tokens from memory")

	def get_stats(self) -> dict:
		"""Получить статистику системы"""
		if self.use_database:
			db_stats = self.database.get_stats()
			return {
			    'clients_count': db_stats['clients_count'],
			    'users_count': db_stats['active_users'],
			    'active_access_tokens': db_stats['active_access_tokens'],
			    'active_refresh_tokens': db_stats['active_refresh_tokens'],
			    'active_authorization_codes': db_stats['active_authorization_codes'],
			    'database_enabled': True,
			    'database_path': self.database.db_path if self.database else None
			}
		else:
			token_stats = self.token_manager.get_token_stats()
			return {
			    'clients_count':
			    len(self.clients),
			    'users_count':
			    len(self.users),
			    'active_access_tokens':
			    token_stats['active_access_tokens'],
			    'active_refresh_tokens':
			    token_stats['active_refresh_tokens'],
			    'active_authorization_codes':
			    len(getattr(self.auth_manager, 'authorization_codes', {})),
			    'database_enabled':
			    False,
			    'database_path':
			    None
			}

	def export_data(self) -> dict:
		"""Экспорт данных (для миграции или бэкапа)"""
		if self.use_database:
			return {
			    'clients': self.database.list_clients(),
			    'users': self.database.list_users(),
			    'stats': self.get_stats(),
			    'export_timestamp': time.time()
			}
		else:
			return {
			    'clients': [{
			        'client_id': client.client_id,
			        'name': client.name,
			        'redirect_uris': client.redirect_uris,
			        'grant_types': client.grant_types
			    } for client in self.clients.values()],
			    'users':
			    list(self.users.values()),
			    'stats':
			    self.get_stats(),
			    'export_timestamp':
			    time.time()
			}

	def get_user_activity(self, user_id: str) -> dict:
		"""Получение активности пользователя"""
		if not self.get_user(user_id):
			return {'error': 'User not found'}

		tokens = self.token_manager.get_user_tokens(user_id)

		return {
		    'user_id': user_id,
		    'active_access_tokens_count': len(tokens['access_tokens']),
		    'active_refresh_tokens_count': len(tokens['refresh_tokens']),
		    'access_tokens': tokens['access_tokens'],
		    'refresh_tokens': tokens['refresh_tokens'],
		    'database_enabled': tokens['database_enabled']
		}
