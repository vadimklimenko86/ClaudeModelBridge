"""
Event store с поддержкой постоянного хранения для возобновляемости потоков.

Включает как in-memory реализацию для тестирования, так и persistent реализацию
на основе SQLite для продакшен использования.

ИСПРАВЛЕНА ПРОБЛЕМА СЕРИАЛИЗАЦИИ JSONRPCMessage.
"""

import json
import logging
import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from uuid import uuid4

from mcp.server.streamable_http import (
    EventCallback,
    EventId,
    EventMessage,
    EventStore,
    StreamId,
)
from mcp.types import JSONRPCMessage

logger = logging.getLogger(__name__)


def serialize_jsonrpc_message(message) -> str:
    """
    Безопасно сериализует JSONRPCMessage в JSON строку.
    
    Args:
        message: JSONRPCMessage объект или любой сериализуемый объект
        
    Returns:
        str: JSON строка
    """
    try:
        # Если это уже строка или базовый тип
        if isinstance(message, str):
            return message
        
        # Если это JSONRPCMessage, пытаемся получить его данные
        if hasattr(message, 'model_dump'):
            # Pydantic v2 модель
            return json.dumps(message.model_dump())
        elif hasattr(message, 'dict'):
            # Pydantic v1 модель
            return json.dumps(message.dict())
        elif hasattr(message, '__dict__'):
            # Обычный объект с атрибутами
            return json.dumps(message.__dict__)
        else:
            # Пытаемся сериализовать как есть
            return json.dumps(message)
            
    except Exception as e:
        # Fallback: преобразуем в строку и оборачиваем в JSON
        logger.warning(f"Не удалось сериализовать message: {e}, используем строковое представление")
        return json.dumps({"raw_message": str(message), "type": str(type(message))})


def deserialize_jsonrpc_message(message_json: str):
    """
    Десериализует JSON строку обратно в объект.
    
    Args:
        message_json: JSON строка
        
    Returns:
        Десериализованный объект
    """
    try:
        return json.loads(message_json)
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка десериализации JSON: {e}")
        return {"error": "Invalid JSON", "raw": message_json}


@dataclass
class EventEntry:
    """Представляет запись события в хранилище."""
    event_id: EventId
    stream_id: StreamId
    message: JSONRPCMessage
    timestamp: Optional[datetime] = None


class InMemoryEventStore(EventStore):
    """
    Простая in-memory реализация интерфейса EventStore для поддержки возобновляемости.
    
    Эта реализация предназначена в основном для примеров и тестирования,
    не для продакшен использования, где следует использовать постоянное хранилище.
    
    Реализация хранит только последние N событий для каждого потока
    для эффективного использования памяти.
    """

    def __init__(self, max_events_per_stream: int = 100):
        """
        Инициализация хранилища событий.
        
        Args:
            max_events_per_stream: Максимальное количество событий для хранения на поток
        """
        self.max_events_per_stream = max_events_per_stream
        # Для хранения последних N событий на поток
        self.streams: dict[StreamId, deque[EventEntry]] = {}
        # event_id -> EventEntry для быстрого поиска
        self.event_index: dict[EventId, EventEntry] = {}
        
        logger.info(f"InMemoryEventStore initialized with max_events_per_stream={max_events_per_stream}")

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage) -> EventId:
        """
        Сохраняет событие с сгенерированным ID.
        
        Args:
            stream_id: Идентификатор потока
            message: JSONRPC сообщение для сохранения
            
        Returns:
            EventId: Уникальный идентификатор сохраненного события
        """
        event_id = str(uuid4())
        event_entry = EventEntry(
            event_id=event_id,
            stream_id=stream_id,
            message=message,
            timestamp=datetime.now()
        )

        # Получаем или создаем deque для этого потока
        if stream_id not in self.streams:
            self.streams[stream_id] = deque(maxlen=self.max_events_per_stream)
            logger.debug(f"Created new stream queue for stream_id={stream_id}")

        # Если deque заполнен, самое старое событие будет автоматически удалено
        # Нужно также удалить его из event_index
        if len(self.streams[stream_id]) == self.max_events_per_stream:
            oldest_event = self.streams[stream_id][0]
            self.event_index.pop(oldest_event.event_id, None)
            logger.debug(f"Removed oldest event {oldest_event.event_id} from stream {stream_id}")

        # Добавляем новое событие
        self.streams[stream_id].append(event_entry)
        self.event_index[event_id] = event_entry
        
        logger.debug(f"Stored event {event_id} for stream {stream_id}")

        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> Optional[StreamId]:
        """
        Переигрывает события, произошедшие после указанного ID события.
        
        Args:
            last_event_id: ID последнего полученного клиентом события
            send_callback: Callback функция для отправки событий клиенту
            
        Returns:
            StreamId если событие найдено и события были переиграны, None в противном случае
        """
        if last_event_id not in self.event_index:
            logger.warning(f"Event ID {last_event_id} not found in store")
            return None

        # Получаем поток и находим события после последнего
        last_event = self.event_index[last_event_id]
        stream_id = last_event.stream_id
        stream_events = self.streams.get(stream_id, deque())
        
        if not stream_events:
            logger.warning(f"Stream {stream_id} not found or empty")
            return None

        # События в deque уже в хронологическом порядке
        found_last = False
        replayed_count = 0
        
        for event in stream_events:
            if found_last:
                await send_callback(EventMessage(event.message, event.event_id))
                replayed_count += 1
            elif event.event_id == last_event_id:
                found_last = True
        
        logger.info(f"Replayed {replayed_count} events for stream {stream_id} after event {last_event_id}")

        return stream_id

    def get_stream_stats(self) -> dict[str, int]:
        """
        Получить статистику по потокам.
        
        Returns:
            Словарь с количеством событий для каждого потока
        """
        return {stream_id: len(events) for stream_id, events in self.streams.items()}

    def clear_stream(self, stream_id: StreamId) -> int:
        """
        Очистить все события для конкретного потока.
        
        Args:
            stream_id: Идентификатор потока для очистки
            
        Returns:
            Количество удаленных событий
        """
        if stream_id not in self.streams:
            return 0
            
        events = self.streams[stream_id]
        count = len(events)
        
        # Удаляем все события из индекса
        for event in events:
            self.event_index.pop(event.event_id, None)
            
        # Очищаем поток
        events.clear()
        
        logger.info(f"Cleared {count} events from stream {stream_id}")
        return count

    def clear_all(self) -> int:
        """
        Очистить все события из хранилища.
        
        Returns:
            Общее количество удаленных событий
        """
        total_count = sum(len(events) for events in self.streams.values())
        
        self.streams.clear()
        self.event_index.clear()
        
        logger.info(f"Cleared all {total_count} events from store")
        return total_count


class PersistentEventStore(EventStore):
    """
    Постоянное хранилище событий на основе SQLite для продакшен использования.
    
    Особенности:
    - Сохраняет события между перезапусками
    - Автоматическая очистка старых событий
    - Поддержка транзакций
    - Индексы для быстрого поиска
    - Hybrid подход: кэш в памяти + постоянное хранение
    - ИСПРАВЛЕНА сериализация JSONRPCMessage
    """

    def __init__(
        self,
        db_path: str = "InternalStorage/events.db",
        max_events_per_stream: int = 1000,
        retention_days: int = 30,
        memory_cache_size: int = 100
    ):
        """
        Инициализация постоянного хранилища событий.
        
        Args:
            db_path: Путь к файлу базы данных SQLite
            max_events_per_stream: Максимальное количество событий на поток
            retention_days: Количество дней для хранения событий
            memory_cache_size: Размер кэша в памяти для быстрого доступа
        """
        self.db_path = Path(db_path)
        self.max_events_per_stream = max_events_per_stream
        self.retention_days = retention_days
        self.memory_cache_size = memory_cache_size
        
        # Кэш последних событий в памяти для быстрого доступа
        self.memory_cache: dict[StreamId, deque[EventEntry]] = {}
        self.event_index: dict[EventId, EventEntry] = {}
        
        # Создаем директорию если не существует
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Инициализируем базу данных
        self._init_database()
        
        # Загружаем последние события в кэш
        self._load_recent_events_to_cache()
        
        logger.info(f"PersistentEventStore initialized: db={db_path}, retention={retention_days}d")

    def _init_database(self):
        """Инициализация схемы базы данных."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Создаем таблицу событий
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL,
                    message_json TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Создаем индексы для быстрого поиска
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_timestamp ON events(stream_id, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON events(created_at)")
            
            # Создаем таблицу метаданных
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            logger.debug("Database schema initialized")

    def _load_recent_events_to_cache(self):
        """Загружает последние события в кэш памяти для быстрого доступа."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Получаем список всех потоков
            cursor.execute("SELECT DISTINCT stream_id FROM events")
            streams = [row[0] for row in cursor.fetchall()]
            
            for stream_id in streams:
                # Загружаем последние события для каждого потока
                cursor.execute("""
                    SELECT event_id, stream_id, message_json, timestamp
                    FROM events
                    WHERE stream_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (stream_id, self.memory_cache_size))
                
                events = []
                for row in cursor.fetchall():
                    event_id, stream_id, message_json, timestamp_str = row
                    
                    # ИСПРАВЛЕНИЕ: Используем безопасную десериализацию
                    try:
                        message = deserialize_jsonrpc_message(message_json)
                    except Exception as e:
                        logger.error(f"Ошибка десериализации события {event_id}: {e}")
                        message = {"error": "deserialization_failed", "raw": message_json}
                    
                    timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else None
                    
                    event_entry = EventEntry(
                        event_id=event_id,
                        stream_id=stream_id,
                        message=message,
                        timestamp=timestamp
                    )
                    events.append(event_entry)
                    self.event_index[event_id] = event_entry
                
                # Добавляем в кэш в правильном порядке (старые -> новые)
                events.reverse()
                self.memory_cache[stream_id] = deque(events, maxlen=self.memory_cache_size)
        
        total_cached = sum(len(cache) for cache in self.memory_cache.values())
        logger.info(f"Loaded {total_cached} recent events to memory cache")

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage) -> EventId:
        """
        Сохраняет событие в постоянное хранилище и кэш.
        
        Args:
            stream_id: Идентификатор потока
            message: JSONRPC сообщение для сохранения
            
        Returns:
            EventId: Уникальный идентификатор сохраненного события
        """
        event_id = str(uuid4())
        timestamp = datetime.now()
        
        # ИСПРАВЛЕНИЕ: Используем безопасную сериализацию
        try:
            message_json = serialize_jsonrpc_message(message)
        except Exception as e:
            logger.error(f"Критическая ошибка сериализации message: {e}")
            # Создаем минимальный JSON с информацией об ошибке
            message_json = json.dumps({
                "error": "serialization_failed",
                "original_type": str(type(message)),
                "timestamp": timestamp.isoformat(),
                "event_id": event_id
            })
        
        # Сохраняем в базу данных
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events (event_id, stream_id, message_json, timestamp)
                VALUES (?, ?, ?, ?)
            """, (event_id, stream_id, message_json, timestamp.isoformat()))
            conn.commit()
        
        # Добавляем в кэш памяти
        event_entry = EventEntry(
            event_id=event_id,
            stream_id=stream_id,
            message=message,  # В кэше храним оригинальный объект
            timestamp=timestamp
        )
        
        if stream_id not in self.memory_cache:
            self.memory_cache[stream_id] = deque(maxlen=self.memory_cache_size)
        
        # Удаляем из индекса старое событие, если кэш переполнен
        if len(self.memory_cache[stream_id]) == self.memory_cache_size:
            oldest_event = self.memory_cache[stream_id][0]
            self.event_index.pop(oldest_event.event_id, None)
        
        self.memory_cache[stream_id].append(event_entry)
        self.event_index[event_id] = event_entry
        
        logger.debug(f"Stored event {event_id} for stream {stream_id} (persistent)")
        
        # Периодическая очистка старых событий
        if len(self.event_index) % 100 == 0:
            await self._cleanup_old_events()
        
        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> Optional[StreamId]:
        """
        Переигрывает события, произошедшие после указанного ID события.
        
        Сначала ищет в кэше памяти, если не найдено - обращается к базе данных.
        
        Args:
            last_event_id: ID последнего полученного клиентом события
            send_callback: Callback функция для отправки событий клиенту
            
        Returns:
            StreamId если событие найдено и события были переиграны, None в противном случае
        """
        # Сначала пытаемся найти в кэше памяти
        if last_event_id in self.event_index:
            return await self._replay_from_cache(last_event_id, send_callback)
        
        # Если не в кэше, ищем в базе данных
        return await self._replay_from_database(last_event_id, send_callback)

    async def _replay_from_cache(self, last_event_id: EventId, send_callback: EventCallback) -> Optional[StreamId]:
        """Переигрывает события из кэша памяти."""
        last_event = self.event_index[last_event_id]
        stream_id = last_event.stream_id
        stream_events = self.memory_cache.get(stream_id, deque())
        
        if not stream_events:
            logger.warning(f"Stream {stream_id} not found in cache")
            return None

        found_last = False
        replayed_count = 0
        
        for event in stream_events:
            if found_last:
                await send_callback(EventMessage(event.message, event.event_id))
                replayed_count += 1
            elif event.event_id == last_event_id:
                found_last = True
        
        logger.info(f"Replayed {replayed_count} events from cache for stream {stream_id}")
        return stream_id

    async def _replay_from_database(self, last_event_id: EventId, send_callback: EventCallback) -> Optional[StreamId]:
        """Переигрывает события из базы данных."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Находим последнее событие
            cursor.execute("""
                SELECT stream_id, timestamp FROM events WHERE event_id = ?
            """, (last_event_id,))
            
            result = cursor.fetchone()
            if not result:
                logger.warning(f"Event ID {last_event_id} not found in database")
                return None
            
            stream_id, last_timestamp = result
            
            # Получаем все события после указанного времени
            cursor.execute("""
                SELECT event_id, message_json FROM events
                WHERE stream_id = ? AND timestamp > ?
                ORDER BY timestamp
            """, (stream_id, last_timestamp))
            
            replayed_count = 0
            for row in cursor.fetchall():
                event_id, message_json = row
                
                # ИСПРАВЛЕНИЕ: Используем безопасную десериализацию
                try:
                    message = deserialize_jsonrpc_message(message_json)
                except Exception as e:
                    logger.error(f"Ошибка десериализации при replay события {event_id}: {e}")
                    message = {"error": "deserialization_failed", "raw": message_json}
                
                await send_callback(EventMessage(message, event_id))
                replayed_count += 1
            
            logger.info(f"Replayed {replayed_count} events from database for stream {stream_id}")
            return stream_id

    def get_stream_stats(self) -> dict[str, int]:
        """
        Получить статистику по потокам из базы данных.
        
        Returns:
            Словарь с количеством событий для каждого потока
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT stream_id, COUNT(*) as event_count
                FROM events
                GROUP BY stream_id
            """)
            
            return {stream_id: count for stream_id, count in cursor.fetchall()}

    def clear_stream(self, stream_id: StreamId) -> int:
        """
        Очистить все события для конкретного потока.
        
        Args:
            stream_id: Идентификатор потока для очистки
            
        Returns:
            Количество удаленных событий
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Подсчитываем количество событий перед удалением
            cursor.execute("SELECT COUNT(*) FROM events WHERE stream_id = ?", (stream_id,))
            count = cursor.fetchone()[0]
            
            # Удаляем из базы данных
            cursor.execute("DELETE FROM events WHERE stream_id = ?", (stream_id,))
            conn.commit()
        
        # Очищаем кэш
        if stream_id in self.memory_cache:
            for event in self.memory_cache[stream_id]:
                self.event_index.pop(event.event_id, None)
            del self.memory_cache[stream_id]
        
        logger.info(f"Cleared {count} events from stream {stream_id} (persistent)")
        return count

    def clear_all(self) -> int:
        """
        Очистить все события из хранилища.
        
        Returns:
            Общее количество удаленных событий
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Подсчитываем общее количество событий
            cursor.execute("SELECT COUNT(*) FROM events")
            total_count = cursor.fetchone()[0]
            
            # Удаляем все события
            cursor.execute("DELETE FROM events")
            conn.commit()
        
        # Очищаем кэш
        self.memory_cache.clear()
        self.event_index.clear()
        
        logger.info(f"Cleared all {total_count} events from persistent store")
        return total_count

    async def _cleanup_old_events(self):
        """Очищает старые события согласно настройкам retention."""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Подсчитываем количество событий для удаления
            cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff_date.isoformat(),))
            old_count = cursor.fetchone()[0]
            
            if old_count > 0:
                # Удаляем старые события
                cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date.isoformat(),))
                
                # Очищаем события превышающие лимит на поток
                cursor.execute("""
                    DELETE FROM events
                    WHERE event_id NOT IN (
                        SELECT event_id FROM events
                        WHERE stream_id = events.stream_id
                        ORDER BY timestamp DESC
                        LIMIT ?
                    )
                """, (self.max_events_per_stream,))
                
                conn.commit()
                logger.info(f"Cleaned up {old_count} old events from persistent store")

    def get_database_info(self) -> dict:
        """Получить информацию о состоянии базы данных."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Общая статистика
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT stream_id) FROM events")
            total_streams = cursor.fetchone()[0]
            
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events")
            time_range = cursor.fetchone()
            
            # Размер файла базы данных
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
            
            return {
                "database_path": str(self.db_path),
                "database_size_mb": round(db_size / 1024 / 1024, 2),
                "total_events": total_events,
                "total_streams": total_streams,
                "oldest_event": time_range[0],
                "newest_event": time_range[1],
                "cache_size": len(self.event_index),
                "retention_days": self.retention_days
            }


# Фабричная функция для создания хранилища
def create_event_store(persistent: bool = True, **kwargs) -> EventStore:
    """
    Создает экземпляр хранилища событий.
    
    Args:
        persistent: Если True, создает постоянное хранилище, иначе in-memory
        **kwargs: Дополнительные параметры для конструктора
        
    Returns:
        EventStore: Экземпляр хранилища событий
    """
    if persistent:
        return PersistentEventStore(**kwargs)
    else:
        return InMemoryEventStore(**kwargs)
