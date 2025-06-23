"""OAuth 2.0 Modules Package

Модульная система для OAuth 2.0 авторизации, разделенная на логические компоненты:

- oauth2_client: Класс OAuth2Client для представления клиентов
- oauth2_tokens: OAuth2TokenManager для управления токенами
- oauth2_auth: OAuth2AuthManager для авторизации и аутентификации  
- oauth2_endpoints: OAuth2Endpoints для обработки HTTP endpoints
- oauth2_manager: OAuth2Manager - главный класс, объединяющий все компоненты

Пример использования:
    from oauth2_modules import OAuth2Manager
    
    oauth_manager = OAuth2Manager(logger)
    routes = oauth_manager.routes
"""

from .oauth2_client import OAuth2Client
from .oauth2_tokens import OAuth2TokenManager
from .oauth2_auth import OAuth2AuthManager
from .oauth2_endpoints import OAuth2Endpoints
from .oauth2_manager import OAuth2Manager

__all__ = [
    'OAuth2Client',
    'OAuth2TokenManager', 
    'OAuth2AuthManager',
    'OAuth2Endpoints',
    'OAuth2Manager'
]

__version__ = '1.0.0'
