"""
In-memory event store для демонстрации функциональности возобновляемости потоков.

Это простая реализация, предназначенная для примеров и тестирования,
не для продакшен использования, где требуется постоянное хранилище данных.
"""

import logging
from collections import deque
from dataclasses import dataclass
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


@dataclass
class EventEntry:
	"""Представляет запись события в хранилище."""
	event_id: EventId
	stream_id: StreamId
	message: JSONRPCMessage


class InMemoryEventStore(EventStore):
	"""
	Простая in-memory реализация интерфейса EventStore для поддержки возобновляемости.
	
	Эта реализация предназначена в основном для примеров и тестирования,
	не для продакшен использования, где следует использовать постоянное хранилище
	(например, Redis, PostgreSQL, MongoDB).
	
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
			message=message
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
