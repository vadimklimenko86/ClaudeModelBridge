"""OAuth 2.0 Client representation"""

from datetime import datetime
from typing import List


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
