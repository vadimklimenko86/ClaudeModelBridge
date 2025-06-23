"""OAuth 2.0 Token management"""

import secrets
import time
import hashlib
import base64
import jwt
from datetime import datetime, timedelta
from typing import Dict, Tuple
from cryptography.hazmat.primitives import serialization
from starlette.requests import Request


class OAuth2TokenManager:
	"""Класс для управления токенами OAuth 2.0"""

	def __init__(self, private_key, public_key, key_id: str):
		self.private_key = private_key
		self.public_key = public_key
		self.key_id = key_id
		
		# Хранилища токенов
		self.access_tokens: Dict[str, dict] = {}
		self.refresh_tokens: Dict[str, dict] = {}

	def generate_access_token(self, user_id: str, client_id: str, scope: str) -> str:
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

	def generate_refresh_token(self, user_id: str, client_id: str, scope: str) -> str:
		"""Генерация refresh token"""
		token = secrets.token_urlsafe(32)

		self.refresh_tokens[token] = {
			'user_id': user_id,
			'client_id': client_id,
			'scope': scope,
			'expires_at': time.time() + 86400 * 30,  # 30 дней
		}

		return token

	def generate_id_token(self, request: Request, user_id: str, client_id: str, 
						 access_token: str, base_url: str, users: Dict) -> str:
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

		# Добавляем пользовательские claims
		user = users.get(user_id)
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
		if token not in self.access_tokens:
			return False, {}

		token_data = self.access_tokens[token]

		if token_data['expires_at'] < time.time():
			return False, {}

		return True, token_data

	def validate_refresh_token(self, token: str) -> Tuple[bool, Dict]:
		"""Валидация refresh token"""
		if token not in self.refresh_tokens:
			return False, {}

		token_data = self.refresh_tokens[token]

		if token_data['expires_at'] < time.time():
			return False, {}

		return True, token_data

	def revoke_token(self, token: str) -> bool:
		"""Отзыв токена"""
		revoked = False
		
		# Пытаемся отозвать как access token
		if token in self.access_tokens:
			del self.access_tokens[token]
			revoked = True
		
		# Или как refresh token
		elif token in self.refresh_tokens:
			del self.refresh_tokens[token]
			revoked = True

		return revoked

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
