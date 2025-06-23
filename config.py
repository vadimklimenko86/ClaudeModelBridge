"""
Конфигурация для RemoteMCP сервера
"""

import os
from typing import List, Dict, Any


class Config:
    """Базовая конфигурация"""
    
    # Сервер
    HOST: str = os.getenv("MCP_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("MCP_PORT", "8000"))
    DEBUG: bool = os.getenv("MCP_DEBUG", "false").lower() == "true"
    
    # OAuth2
    OAUTH2_ISSUER_URL: str = os.getenv("OAUTH2_ISSUER_URL", "http://localhost:8000")
    OAUTH2_TOKEN_EXPIRY: int = int(os.getenv("OAUTH2_TOKEN_EXPIRY", "3600"))  # 1 час
    OAUTH2_REFRESH_TOKEN_EXPIRY: int = int(os.getenv("OAUTH2_REFRESH_TOKEN_EXPIRY", "2592000"))  # 30 дней
    OAUTH2_AUTH_CODE_EXPIRY: int = int(os.getenv("OAUTH2_AUTH_CODE_EXPIRY", "600"))  # 10 минут
    
    # Безопасность
    SECRET_KEY: str = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "https://claude.ai,http://localhost:*").split(",")
    
    # Event Store
    MAX_EVENTS_PER_STREAM: int = int(os.getenv("MAX_EVENTS_PER_STREAM", "100"))
    
    # Клиенты OAuth2 (в продакшене загружать из БД)
    OAUTH2_CLIENTS: Dict[str, Dict[str, Any]] = {
        "client_1749051312": {
            "client_secret": os.getenv("CLAUDE_CLIENT_SECRET", "claude_secret_key_2024"),
            "redirect_uris": [
                "https://claude.ai/oauth/callback",
                "https://claude.ai/api/mcp/auth_callback"
            ],
            "name": "Claude MCP Client",
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid", "profile", "email", "mcp:read", "mcp:write"]
        }
    }
    
    # Пользователи (в продакшене использовать БД)
    DEFAULT_USERS: Dict[str, Dict[str, Any]] = {
        "user@example.com": {
            "password": "password123",  # В продакшене хешировать!
            "name": "Test User",
            "roles": ["user", "admin"]
        }
    }
    
    # Логирование
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # MCP
    MCP_SERVER_NAME: str = os.getenv("MCP_SERVER_NAME", "remote-mcp-server")
    MCP_SERVER_VERSION: str = "1.0.0"


class DevelopmentConfig(Config):
    """Конфигурация для разработки"""
    DEBUG = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    """Конфигурация для продакшена"""
    DEBUG = False
    
    # В продакшене требуем явное указание секретного ключа
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in production")
    
    # Более строгие CORS настройки
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://claude.ai").split(",")
    
    # Отключаем тестовых пользователей
    DEFAULT_USERS = {}


class TestConfig(Config):
    """Конфигурация для тестирования"""
    TESTING = True
    SECRET_KEY = "test_secret_key"
    OAUTH2_TOKEN_EXPIRY = 60  # Короткий срок для тестов


# Выбор конфигурации на основе переменной окружения
config_name = os.getenv("MCP_ENV", "development")

configs = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "test": TestConfig
}

# Текущая конфигурация
current_config = configs.get(config_name, DevelopmentConfig)()
