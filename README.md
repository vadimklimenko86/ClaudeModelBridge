# RemoteMCP - OAuth2-защищенный MCP сервер

## Описание

RemoteMCP - это реализация Model Context Protocol (MCP) сервера с поддержкой OAuth2 авторизации для безопасного удаленного доступа.

## Компоненты

### 1. OAuth2 Manager (`oauth2.py`)
- Полная реализация OAuth2/OpenID Connect провайдера
- Поддержка Authorization Code Flow с PKCE
- JWT токены для OpenID Connect
- Встроенная поддержка для Claude MCP клиента

### 2. Custom Server (`custom_server.py`)
- Интеграция MCP сервера с OAuth2
- Поддержка StreamableHTTP транспорта
- CORS middleware для веб-клиентов
- Проверка и валидация токенов

### 3. Event Store (`event_store.py`)
- In-memory хранилище событий для поддержки возобновляемых потоков
- Позволяет клиентам переподключаться и получать пропущенные события
- Ограничение на количество событий для эффективного использования памяти

### 4. MCP Tools (`MCP_Tools.py`)
- Система регистрации и управления MCP инструментами
- Автоматическая генерация JSON Schema из Python типов
- Поддержка Annotated типов для документации параметров

## Использование

### Настройка OAuth2 клиента

По умолчанию настроен клиент для Claude:
```python
client_id = "client_1749051312"
client_secret = "claude_secret_key_2024"
redirect_uris = [
    "https://claude.ai/oauth/callback",
    "https://claude.ai/api/mcp/auth_callback"
]
```

### Регистрация MCP инструментов

```python
from MCP_Tools import MCP_Tools
from typing import Annotated

tools = MCP_Tools(server_app)

@tools.register_tool("get_time", "Получить текущее время")
def get_time(
    timezone: Annotated[str, "Временная зона (например, UTC, Europe/Moscow)"] = "UTC"
):
    # Реализация
    return f"Текущее время в {timezone}: ..."

@tools.register_simple_tool("hello", "Простое приветствие")
def hello():
    return "Привет от MCP сервера!"
```

### Запуск сервера

```python
import logging
from mcp.server.lowlevel import Server
from custom_server import CustomServerWithOauth2

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Создание MCP сервера
mcp_server = Server("my-mcp-server")

# Создание OAuth2-защищенного сервера
server = CustomServerWithOauth2(logger, mcp_server)

# Запуск с помощью ASGI сервера (например, uvicorn)
# uvicorn main:server --host 0.0.0.0 --port 8000
```

## Безопасность

- Все пароли хешируются (в продакшене использовать bcrypt)
- Поддержка PKCE для защиты от атак перехвата кода
- JWT токены с RSA подписью
- Автоматическая проверка срока действия токенов
- CORS настроен только для разрешенных доменов

## Продакшен рекомендации

1. **Хранилище сессий**: Заменить in-memory хранилище на Redis или базу данных
2. **Event Store**: Использовать постоянное хранилище (PostgreSQL, MongoDB)
3. **Пароли**: Использовать bcrypt вместо SHA256
4. **HTTPS**: Обязательно использовать HTTPS в продакшене
5. **Клиенты**: Хранить OAuth2 клиентов в базе данных
6. **Ключи**: Хранить RSA ключи в безопасном хранилище (HSM, Vault)

## Лицензия

MIT
