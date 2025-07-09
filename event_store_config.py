"""
Конфигурация для Event Store с поддержкой различных окружений.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class EventStoreConfig:
    """Конфигурация для хранилища событий."""
    
    # Основные настройки
    persistent: bool = True
    db_path: str = "InternalStorage/events.db"
    
    # Ограничения хранения
    max_events_per_stream: int = 1000
    retention_days: int = 30
    memory_cache_size: int = 100
    
    # Производительность
    cleanup_interval_events: int = 100
    batch_size: int = 50
    
    # Резервное копирование
    backup_enabled: bool = True
    backup_interval_hours: int = 24
    backup_retention_days: int = 7
    
    @classmethod
    def from_env(cls) -> "EventStoreConfig":
        """Создает конфигурацию из переменных окружения."""
        return cls(
            persistent=os.getenv("EVENT_STORE_PERSISTENT", "true").lower() == "true",
            db_path=os.getenv("EVENT_STORE_DB_PATH", "InternalStorage/events.db"),
            max_events_per_stream=int(os.getenv("EVENT_STORE_MAX_EVENTS", "1000")),
            retention_days=int(os.getenv("EVENT_STORE_RETENTION_DAYS", "30")),
            memory_cache_size=int(os.getenv("EVENT_STORE_CACHE_SIZE", "100")),
            cleanup_interval_events=int(os.getenv("EVENT_STORE_CLEANUP_INTERVAL", "100")),
            batch_size=int(os.getenv("EVENT_STORE_BATCH_SIZE", "50")),
            backup_enabled=os.getenv("EVENT_STORE_BACKUP_ENABLED", "true").lower() == "true",
            backup_interval_hours=int(os.getenv("EVENT_STORE_BACKUP_INTERVAL", "24")),
            backup_retention_days=int(os.getenv("EVENT_STORE_BACKUP_RETENTION", "7"))
        )
    
    @classmethod
    def development(cls) -> "EventStoreConfig":
        """Конфигурация для разработки."""
        return cls(
            persistent=False,  # Используем in-memory для разработки
            max_events_per_stream=100,
            retention_days=7,
            memory_cache_size=50,
            backup_enabled=False
        )
    
    @classmethod
    def testing(cls) -> "EventStoreConfig":
        """Конфигурация для тестирования."""
        return cls(
            persistent=True,
            db_path=":memory:",  # Использует SQLite в памяти
            max_events_per_stream=50,
            retention_days=1,
            memory_cache_size=25,
            cleanup_interval_events=10,
            backup_enabled=False
        )
    
    @classmethod
    def production(cls) -> "EventStoreConfig":
        """Конфигурация для продакшена."""
        return cls(
            persistent=True,
            db_path="InternalStorage/production_events.db",
            max_events_per_stream=5000,
            retention_days=90,
            memory_cache_size=500,
            cleanup_interval_events=500,
            backup_enabled=True,
            backup_interval_hours=6,
            backup_retention_days=30
        )
    
    def get_db_path(self) -> Path:
        """Возвращает полный путь к базе данных."""
        if self.db_path == ":memory:":
            return Path(":memory:")
        return Path(self.db_path).resolve()
    
    def validate(self) -> list[str]:
        """Валидирует конфигурацию и возвращает список ошибок."""
        errors = []
        
        if self.max_events_per_stream <= 0:
            errors.append("max_events_per_stream должен быть больше 0")
        
        if self.retention_days <= 0:
            errors.append("retention_days должен быть больше 0")
        
        if self.memory_cache_size <= 0:
            errors.append("memory_cache_size должен быть больше 0")
        
        if self.cleanup_interval_events <= 0:
            errors.append("cleanup_interval_events должен быть больше 0")
        
        if self.batch_size <= 0:
            errors.append("batch_size должен быть больше 0")
        
        if self.backup_enabled:
            if self.backup_interval_hours <= 0:
                errors.append("backup_interval_hours должен быть больше 0")
            if self.backup_retention_days <= 0:
                errors.append("backup_retention_days должен быть больше 0")
        
        # Проверяем возможность создания директории для БД
        if self.persistent and self.db_path != ":memory:":
            try:
                db_path = self.get_db_path()
                db_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Не удается создать директорию для БД: {e}")
        
        return errors


# Предустановленные конфигурации
CONFIG_PRESETS = {
    "development": EventStoreConfig.development(),
    "testing": EventStoreConfig.testing(),
    "production": EventStoreConfig.production(),
    "from_env": EventStoreConfig.from_env()
}


def get_config(preset: str = "from_env") -> EventStoreConfig:
    """
    Получить конфигурацию по имени пресета.
    
    Args:
        preset: Имя пресета ("development", "testing", "production", "from_env")
        
    Returns:
        EventStoreConfig: Объект конфигурации
        
    Raises:
        ValueError: Если пресет не найден
    """
    if preset not in CONFIG_PRESETS:
        available = ", ".join(CONFIG_PRESETS.keys())
        raise ValueError(f"Неизвестный пресет '{preset}'. Доступные: {available}")
    
    config = CONFIG_PRESETS[preset]
    
    # Валидируем конфигурацию
    errors = config.validate()
    if errors:
        raise ValueError(f"Некорректная конфигурация: {'; '.join(errors)}")
        return config
