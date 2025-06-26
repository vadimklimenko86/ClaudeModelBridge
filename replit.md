# RemoteMCP - OAuth2-защищенный MCP сервер

## Overview

RemoteMCP - это реализация Model Context Protocol (MCP) сервера с поддержкой OAuth2 авторизации для безопасного удаленного доступа. Система построена на Python с использованием Starlette/FastAPI для веб-части и включает модульную архитектуру для OAuth2, систему хранения событий и инструменты для работы с файловой системой и памятью.

## System Architecture

### Backend Architecture
- **Framework**: Python 3.11+ с использованием Starlette/FastAPI
- **MCP Server**: Низкоуровневый MCP сервер с поддержкой StreamableHTTP транспорта
- **OAuth2 System**: Модульная система авторизации с SQLite базой данных
- **Event Store**: Система хранения событий для возобновляемых потоков
- **Admin Panel**: Веб-интерфейс для администрирования

### Frontend Architecture
- **Admin Interface**: HTML/CSS/JS с Bootstrap 5 и Font Awesome
- **Templates**: Jinja2 шаблоны для серверного рендеринга
- **Static Assets**: CSS и JavaScript для интерактивности

### Модульная структура OAuth2
- `oauth2_client.py` - Представление OAuth2 клиентов
- `oauth2_database.py` - Управление PostgreSQL базой данных
- `oauth2_tokens.py` - Управление токенами доступа
- `oauth2_auth.py` - Авторизация и аутентификация
- `oauth2_endpoints.py` - HTTP endpoints для OAuth2
- `oauth2_manager.py` - Главный класс координации

## Key Components

### 1. OAuth2 Manager
- Полная реализация OAuth2/OpenID Connect провайдера
- Поддержка Authorization Code Flow с PKCE
- JWT токены для OpenID Connect
- Встроенная поддержка для Claude MCP клиента
- SQLite база данных для хранения клиентов, пользователей и токенов

### 2. Custom Server
- Интеграция MCP сервера с OAuth2
- Поддержка StreamableHTTP транспорта
- CORS middleware для веб-клиентов
- Проверка и валидация токенов

### 3. Event Store
- In-memory и persistent (SQLite) хранилище событий
- Поддержка возобновляемых потоков для MCP клиентов
- Конфигурируемые лимиты на количество событий
- Автоматическая очистка старых событий
- Система миграций и резервного копирования

### 4. MCP Tools System
- Система регистрации и управления MCP инструментами
- Автоматическая генерация JSON Schema из Python типов
- Поддержка Annotated типов для документации параметров
- Встроенные инструменты: FileSystem, Memory, System

### 5. Admin Panel
- Веб-интерфейс для мониторинга и управления
- Аутентификация администраторов
- Мониторинг системных ресурсов
- Управление пользователями и инструментами
- Просмотр логов и статистики

## Data Flow

### OAuth2 Authorization Flow
1. Клиент инициирует авторизацию через `/oauth/authorize`
2. Пользователь аутентифицируется через форму входа
3. Сервер генерирует authorization code
4. Клиент обменивает код на access token через `/oauth/token`
5. Токен используется для доступа к MCP endpoints

### MCP Communication Flow
1. Клиент подключается к `/mcp/` endpoint с access token
2. Сервер создает SSE поток для двунаправленной связи
3. События сохраняются в Event Store с уникальными ID
4. Клиент может возобновить поток используя Last-Event-ID

### Tool Execution Flow
1. MCP клиент отправляет запрос на выполнение инструмента
2. Сервер валидирует права доступа через OAuth2
3. Инструмент выполняется с параметрами
4. Результат возвращается через MCP протокол

## External Dependencies

### Core Dependencies
- **mcp** - Model Context Protocol implementation
- **starlette** - ASGI web framework
- **uvicorn** - ASGI server
- **pyjwt** - JWT token handling
- **cryptography** - Cryptographic operations
- **aiosqlite** - Async SQLite support

### Optional Dependencies
- **openai** - For AI-powered memory embeddings
- **numpy** - For vector operations in memory system
- **psutil** - For system monitoring
- **redis** - For session storage (production)

### Frontend Dependencies
- **Bootstrap 5** - UI framework
- **Font Awesome** - Icons
- **Chart.js** - Data visualization

## Deployment Strategy

### Development Environment
- SQLite для всех данных (OAuth2, Events, Memory)
- In-memory event store для быстрого тестирования
- Встроенный uvicorn сервер
- Отладочное логирование

### Production Environment
- PostgreSQL для основных данных OAuth2 (используется)
- Redis для сессий и кэширования (опционально)
- Gunicorn с uvicorn workers
- Reverse proxy (nginx)
- SSL/TLS терминация
- Мониторинг и логирование

### Configuration Management
- Environment variables для секретов
- Конфигурационные файлы для настроек
- Система миграций для обновлений схемы
- Автоматическое создание тестовых данных

### Security Considerations
- JWT токены с короткими сроками жизни
- PKCE для защиты authorization code flow
- CSRF protection для админ-панели
- Rate limiting для API endpoints
- Безопасное хранение секретов

## Changelog

- June 26, 2025: Initial setup
- June 26, 2025: Migrated OAuth2Database from SQLite to PostgreSQL - всё SQLite заменено на PostgreSQL в классе OAuth2Database для хранения клиентов, пользователей и токенов
- June 26, 2025: Migrated MemorySystem from SQLite to PostgreSQL - полностью заменена SQLite база данных на PostgreSQL в классе MemorySystem для хранения воспоминаний, эмбеддингов и метаданных. Удален файл InternalStorage/memory.db

## User Preferences

Preferred communication style: Simple, everyday language.