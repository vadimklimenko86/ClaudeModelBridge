"""OAuth 2.0 Token management with SQLite database support"""

import secrets
import time
import hashlib
import base64
import jwt
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from cryptography.hazmat.primitives import serialization
from starlette.requests import Request


class OAuth2TokenManager:
	"""Класс для управления токенами OAuth 2.0 с поддержкой SQLite базы данных"""

	def __init__(self, private_key, public_key, key_id: str, database=None):
		self.private_key = private_key
		self.public_key = public_key
		self.key_id = key_id
		self.database = database
		
		# Резервные хранилища токенов (для совместимости без БД)
		if not self.database:
			self.access_tokens: Dict[str, dict] = {}
			self.refresh_tokens: Dict[str, dict] = {}

	def generate_access_token(self, user_id: str, client_id: str, scope: str) -> str:
		"""Генерация access token"""
		token = secrets.token_urlsafe(32)
		expires_at = time.time() + 3600  # 1 час

		token_data = {
			'user_id': user_id,
			'client_id': client_id,
			'scope': scope,
			'expires_at': expires_at,
			'token_type': 'Bearer'
		}

		# Сохраняем в базу данных или в память
		if self.database:
			self.database.save_access_token(
				token=token,
				user_id=user_id,
				client_id=client_id,
				scope=scope,
				expires_at=expires_at,
				token_type='Bearer'
			)
		else:
			self.access_tokens[token] = token_data

		return token

	def generate_refresh_token(self, user_id: str, client_id: str, scope: str) -> str:
		"""Генерация refresh token"""
		token = secrets.token_urlsafe(32)
		expires_at = time.time() + 86400 * 30  # 30 дней

		token_data = {
			'user_id': user_id,
			'client_id': client_id,
			'scope': scope,
			'expires_at': expires_at,
		}

		# Сохраняем в базу данных или в память
		if self.database:
			self.database.save_refresh_token(
				token=token,
				user_id=user_id,
				client_id=client_id,
				scope=scope,
				expires_at=expires_at
			)
		else:
			self.refresh_tokens[token] = token_data

		return token

	def generate_id_token(self, request: Request, user_id: str, client_id: str, 
						 access_token: str, base_url: str, users: Dict = None) -> str:
		"""Генерация ID token (JWT) для OpenID Connect"""
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

		# Получаем пользовательские данные
		user = None
		if self.database:
			user = self.database.get_user(user_id)
		elif users:
			user = users.get(user_id)

		# Добавляем пользовательские claims
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

	def validate_access_token(self, token: str) -> Tuple[bool, Dict]:
		"""Валидация access token"""
		if self.database:
			# Проверяем в базе данных
			token_data = self.database.get_access_token(token)
			if token_data:
				return True, token_data
			return False, {}
		else:
			# Проверяем в памяти (резервный вариант)
			if token not in self.access_tokens:
				return False, {}

			token_data = self.access_tokens[token]

			if token_data['expires_at'] < time.time():
				return False, {}

			return True, token_data

	def validate_refresh_token(self, token: str) -> Tuple[bool, Dict]:
		"""Валидация refresh token"""
		if self.database:
			# Проверяем в базе данных
			token_data = self.database.get_refresh_token(token)
			if token_data:
				return True, token_data
			return False, {}
		else:
			# Проверяем в памяти (резервный вариант)
			if token not in self.refresh_tokens:
				return False, {}

			token_data = self.refresh_tokens[token]

			if token_data['expires_at'] < time.time():
				return False, {}

			return True, token_data

	def revoke_token(self, token: str) -> bool:
		"""Отзыв токена"""
		revoked = False
		
		if self.database:
			# Пытаемся отозвать в базе данных
			if self.database.revoke_access_token(token):
				revoked = True
			elif self.database.revoke_refresh_token(token):
				revoked = True
		else:
			# Пытаемся отозвать в памяти (резервный вариант)
			if token in self.access_tokens:
				del self.access_tokens[token]
				revoked = True
			elif token in self.refresh_tokens:
				del self.refresh_tokens[token]
				revoked = True

		return revoked

	def revoke_all_user_tokens(self, user_id: str) -> int:
		"""Отзыв всех токенов пользователя"""
		if self.database:
			return self.database.revoke_all_user_tokens(user_id)
		else:
			# Резервный вариант в памяти
			revoked_count = 0
			
			# Отзываем access tokens
			tokens_to_revoke = []
			for token, token_data in self.access_tokens.items():
				if token_data['user_id'] == user_id:
					tokens_to_revoke.append(token)
			
			for token in tokens_to_revoke:
				del self.access_tokens[token]
				revoked_count += 1

			# Отзываем refresh tokens
			tokens_to_revoke = []
			for token, token_data in self.refresh_tokens.items():
				if token_data['user_id'] == user_id:
					tokens_to_revoke.append(token)
			
			for token in tokens_to_revoke:
				del self.refresh_tokens[token]
				revoked_count += 1

			return revoked_count

	def cleanup_expired_tokens(self) -> int:
		"""Очистка истекших токенов"""
		if self.database:
			return self.database.cleanup_expired_tokens()
		else:
			# Резервный вариант в памяти
			current_time = time.time()
			cleaned_count = 0
			
			# Очищаем истекшие access tokens
			expired_access = [
				token for token, data in self.access_tokens.items() 
				if data['expires_at'] <= current_time
			]
			for token in expired_access:
				del self.access_tokens[token]
				cleaned_count += 1
			
			# Очищаем истекшие refresh tokens
			expired_refresh = [
				token for token, data in self.refresh_tokens.items() 
				if data['expires_at'] <= current_time
			]
			for token in expired_refresh:
				del self.refresh_tokens[token]
				cleaned_count += 1
			
			return cleaned_count

	def get_token_stats(self) -> Dict:
		"""Получение статистики токенов"""
		if self.database:
			stats = self.database.get_stats()
			return {
				'active_access_tokens': stats['active_access_tokens'],
				'active_refresh_tokens': stats['active_refresh_tokens'],
				'database_enabled': True
			}
		else:
			current_time = time.time()
			active_access = sum(
				1 for data in self.access_tokens.values() 
				if data['expires_at'] > current_time
			)
			active_refresh = sum(
				1 for data in self.refresh_tokens.values() 
				if data['expires_at'] > current_time
			)
			
			return {
				'active_access_tokens': active_access,
				'active_refresh_tokens': active_refresh,
				'database_enabled': False
			}

	def verify_pkce(self, code_verifier: str, code_challenge: str, method: str) -> bool:
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

	def get_user_tokens(self, user_id: str) -> Dict:
		"""Получение всех активных токенов пользователя"""
		if self.database:
			# Реализация через прямые SQL запросы для получения токенов пользователя
			# (можно добавить соответствующие методы в oauth2_database.py)
			return {
				'access_tokens': [],  # Здесь можно реализовать запрос к БД
				'refresh_tokens': [],  # Здесь можно реализовать запрос к БД
				'database_enabled': True
			}
		else:
			current_time = time.time()
			
			access_tokens = [
				{
					'token': token[:10] + '...',  # Маскируем токен
					'expires_at': data['expires_at'],
					'client_id': data['client_id'],
					'scope': data['scope']
				}
				for token, data in self.access_tokens.items()
				if data['user_id'] == user_id and data['expires_at'] > current_time
			]
			
			refresh_tokens = [
				{
					'token': token[:10] + '...',  # Маскируем токен
					'expires_at': data['expires_at'],
					'client_id': data['client_id'],
					'scope': data['scope']
				}
				for token, data in self.refresh_tokens.items()
				if data['user_id'] == user_id and data['expires_at'] > current_time
			]
			
			return {
				'access_tokens': access_tokens,
				'refresh_tokens': refresh_tokens,
				'database_enabled': False
			}
