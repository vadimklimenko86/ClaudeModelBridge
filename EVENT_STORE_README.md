# Event Store с постоянным хранением

Система хранения событий для поддержки возобновляемости потоков в MCP (Model Context Protocol) с полной поддержкой постоянного хранения.

## 🏗️ Архитектура

### Основные компоненты

- **`event_store.py`** - Основные классы хранилища (InMemory + Persistent)
- **`event_store_config.py`** - Система конфигурации для различных окружений
- **`event_store_migrations.py`** - Утилиты управления, бэкапы, миграции
- **`example_event_store.py`** - Примеры использования и демонстрация

### Типы хранилищ

#### 1. InMemoryEventStore
- Для разработки и тестирования
- Быстрый доступ к данным
- Данные теряются при перезапуске

#### 2. PersistentEventStore
- Для продакшн использования
- SQLite база данных
- Hybrid кэширование в памяти
- Автоматическая очистка старых событий

## 🚀 Быстрый старт

### Базовое использование

```python
from event_store import create_event_store
from event_store_config import get_config

# Получаем конфигурацию
config = get_config("production")

# Создаем хранилище
store = create_event_store(
    persistent=config.persistent,
    db_path=config.db_path,
    max_events_per_stream=config.max_events_per_stream
)

# Сохраняем событие
event_id = await store.store_event("stream_1", {
    "method": "tools/call",
    "params": {"name": "calculator", "args": {"a": 5, "b": 3}}
})

# Переигрываем события после определенного ID
async def handle_event(event_message):
    print(f"Событие: {event_message.message}")

await store.replay_events_after(last_event_id, handle_event)
```

### Запуск демонстрации

```bash
python example_event_store.py
```

## ⚙️ Конфигурация

### Предустановленные конфигурации

```python
from event_store_config import get_config

# Для разработки (in-memory)
config = get_config("development")

# Для тестирования (SQLite в памяти)
config = get_config("testing")

# Для продакшена (файловая SQLite)
config = get_config("production")

# Из переменных окружения
config = get_config("from_env")
```

### Переменные окружения

```bash
EVENT_STORE_PERSISTENT=true
EVENT_STORE_DB_PATH=InternalStorage/events.db
EVENT_STORE_MAX_EVENTS=1000
EVENT_STORE_RETENTION_DAYS=30
EVENT_STORE_CACHE_SIZE=100
EVENT_STORE_BACKUP_ENABLED=true
EVENT_STORE_BACKUP_INTERVAL=24
EVENT_STORE_BACKUP_RETENTION=7
```

## 🛠️ Управление и обслуживание

### Создание бэкапов

```python
from event_store_migrations import EventStoreManager

manager = EventStoreManager("InternalStorage/events.db")

# Создать бэкап
backup_path = manager.create_backup()

# Восстановить из бэкапа
manager.restore_from_backup("path/to/backup.db")

# Очистить старые бэкапы
deleted_count = manager.cleanup_old_backups(retention_days=7)
```

### Получение статистики

```python
# Базовая статистика
stats = store.get_stream_stats()
print(f"Потоки: {stats}")

# Детальная статистика (для PersistentEventStore)
db_info = store.get_database_info()
print(f"Размер БД: {db_info['database_size_mb']} MB")

# Расширенная статистика
detailed_stats = manager.get_database_stats()
```

### Валидация целостности

```python
validation = manager.validate_database()

if validation['valid']:
    print("✅ База данных валидна")
else:
    print("❌ Ошибки:")
    for error in validation['errors']:
        print(f"  - {error}")
```

### Экспорт и импорт

```python
# Экспорт всех событий
count = manager.export_events("backup.json")

# Экспорт с фильтрацией
count = manager.export_events(
    "filtered.json",
    stream_id="specific_stream",
    start_date="2024-01-01T00:00:00",
    end_date="2024-12-31T23:59:59"
)

# Импорт событий
count = manager.import_events("backup.json")
```

## 🔧 Возможности постоянного хранения

### Преимущества PersistentEventStore

1. **Надежность** - данные сохраняются между перезапусками
2. **Производительность** - hybrid кэширование для быстрого доступа
3. **Масштабируемость** - автоматическая очистка старых событий
4. **Мониторинг** - детальная статистика и валидация
5. **Безопасность** - автоматические бэкапы и восстановление

### Hybrid архитектура

- **Кэш в памяти**: последние N событий для быстрого доступа
- **SQLite база**: постоянное хранение всех событий
- **Автоматическая синхронизация**: между кэшем и БД
- **Graceful fallback**: при недоступности кэша обращение к БД

### Схема базы данных

```sql
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    message_json TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для производительности
CREATE INDEX idx_stream_timestamp ON events(stream_id, timestamp);
CREATE INDEX idx_timestamp ON events(timestamp);
```

## 📈 Мониторинг и метрики

### Доступные метрики

- Общее количество событий
- События по потокам
- Временные рамки (первое/последнее событие)
- Размер базы данных
- Производительность операций
- Статистика кэша

### Автоматическое обслуживание

```python
from event_store_migrations import run_maintenance_tasks

# Запуск задач обслуживания
results = await run_maintenance_tasks(
    "InternalStorage/events.db",
    config.__dict__
)

print(f"Результаты: {results}")
```

## 🔒 Безопасность и надежность

### Обработка ошибок

- Graceful handling отключений БД
- Автоматическое восстановление соединений
- Fallback к кэшу при проблемах с БД
- Детальное логирование всех операций

### Целостность данных

- Транзакционная безопасность
- Валидация JSON сообщений
- Проверка целостности SQLite
- Автоматическое обнаружение повреждений

### Бэкапы

- Автоматическое создание по расписанию
- Ротация старых бэкапов
- Инкрементальные копии
- Быстрое восстановление

## 📋 Требования

### Зависимости

```txt
aiosqlite>=0.19.0    # Асинхронный SQLite
mcp>=0.1.0           # Model Context Protocol
```

### Минимальные ресурсы

- **RAM**: 100MB для кэша (настраивается)
- **Диск**: зависит от количества событий (~1KB на событие)
- **CPU**: минимальные требования для SQLite операций

## 🧪 Тестирование

Для тестирования используйте конфигурацию "testing":

```python
config = get_config("testing")  # SQLite в памяти
store = create_event_store(**config.__dict__)
```

## 🚀 Производительность

### Оптимизации

- Индексы базы данных для быстрого поиска
- Кэширование последних событий в памяти
- Batch операции для массовых вставок
- Асинхронные операции с БД

### Рекомендации для продакшена

- Устанавливайте `memory_cache_size` на основе доступной RAM
- Настройте `retention_days` согласно требованиям
- Включите автоматические бэкапы
- Мониторьте размер базы данных

---

## 📚 Дополнительные ресурсы

- [MCP Specification](https://modelcontextprotocol.io/)
- [SQLite Documentation](https://sqlite.org/docs.html)
- [Примеры использования](example_event_store.py)