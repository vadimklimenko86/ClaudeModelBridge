"""OAuth 2.0 Modules Package

Модульная система для OAuth 2.0 авторизации с поддержкой SQLite базы данных:

- oauth2_client: Класс OAuth2Client для представления клиентов
- oauth2_database: OAuth2Database для работы с SQLite базой данных
- oauth2_tokens: OAuth2TokenManager для управления токенами с поддержкой БД
- oauth2_auth: OAuth2AuthManager для авторизации и аутентификации  
- oauth2_endpoints: OAuth2Endpoints для обработки HTTP endpoints
- oauth2_manager: OAuth2Manager - главный класс, объединяющий все компоненты

Пример использования с базой данных:
    from oauth2_modules import OAuth2Manager
    
    # С базой данных (по умолчанию)
    oauth_manager = OAuth2Manager(logger, db_path="oauth2.db", use_database=True)
    
    # Без базы данных (только в памяти)
    oauth_manager = OAuth2Manager(logger, use_database=False)
    
    routes = oauth_manager.routes

Прямое использование базы данных:
    from oauth2_modules import OAuth2Database
    
    db = OAuth2Database("oauth2.db", logger)
    db.create_user("user1", "user1@example.com", "User One", "password_hash")
"""

from .oauth2_client import OAuth2Client
from .oauth2_database import OAuth2Database
from .oauth2_tokens import OAuth2TokenManager
from .oauth2_auth import OAuth2AuthManager
from .oauth2_endpoints import OAuth2Endpoints
from .oauth2_manager import OAuth2Manager

__all__ = [
    'OAuth2Client',
    'OAuth2Database',
    'OAuth2TokenManager', 
    'OAuth2AuthManager',
    'OAuth2Endpoints',
    'OAuth2Manager'
]

__version__ = '2.0.0'
