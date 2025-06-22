"""
Тесты для InMemoryEventStore
"""

import pytest
import asyncio
from typing import List
from event_store import InMemoryEventStore, EventEntry
from mcp.server.streamable_http import EventMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest


@pytest.fixture
def event_store():
    """Создание экземпляра InMemoryEventStore"""
    return InMemoryEventStore(max_events_per_stream=5)


@pytest.fixture
def sample_message():
    """Пример JSONRPC сообщения"""
    return JSONRPCRequest(
        jsonrpc="2.0",
        id="test-1",
        method="test_method",
        params={"key": "value"}
    )


class TestEventStorage:
    """Тесты хранения событий"""
    
    @pytest.mark.asyncio
    async def test_store_event(self, event_store, sample_message):
        """Тест сохранения события"""
        stream_id = "test-stream"
        event_id = await event_store.store_event(stream_id, sample_message)
        
        assert event_id is not None
        assert event_id in event_store.event_index
        assert stream_id in event_store.streams
        assert len(event_store.streams[stream_id]) == 1
        
    @pytest.mark.asyncio
    async def test_store_multiple_events(self, event_store):
        """Тест сохранения нескольких событий"""
        stream_id = "test-stream"
        messages = []
        event_ids = []
        
        for i in range(3):
            message = JSONRPCRequest(
                jsonrpc="2.0",
                id=f"test-{i}",
                method="test_method",
                params={"index": i}
            )
            messages.append(message)
            event_id = await event_store.store_event(stream_id, message)
            event_ids.append(event_id)
        
        assert len(event_store.streams[stream_id]) == 3
        assert all(eid in event_store.event_index for eid in event_ids)
        
    @pytest.mark.asyncio
    async def test_max_events_per_stream(self, event_store):
        """Тест ограничения количества событий на поток"""
        stream_id = "test-stream"
        event_ids = []
        
        # Сохраняем больше событий, чем максимум (5)
        for i in range(10):
            message = JSONRPCRequest(
                jsonrpc="2.0",
                id=f"test-{i}",
                method="test_method",
                params={"index": i}
            )
            event_id = await event_store.store_event(stream_id, message)
            event_ids.append(event_id)
        
        # Должно остаться только последние 5
        assert len(event_store.streams[stream_id]) == 5
        
        # Первые 5 событий должны быть удалены
        for i in range(5):
            assert event_ids[i] not in event_store.event_index
            
        # Последние 5 должны остаться
        for i in range(5, 10):
            assert event_ids[i] in event_store.event_index


class TestEventReplay:
    """Тесты переигрывания событий"""
    
    @pytest.mark.asyncio
    async def test_replay_events_after(self, event_store):
        """Тест переигрывания событий после указанного ID"""
        stream_id = "test-stream"
        event_ids = []
        replayed_events = []
        
        # Сохраняем несколько событий
        for i in range(5):
            message = JSONRPCRequest(
                jsonrpc="2.0",
                id=f"test-{i}",
                method="test_method",
                params={"index": i}
            )
            event_id = await event_store.store_event(stream_id, message)
            event_ids.append(event_id)
        
        # Callback для сбора переигранных событий
        async def collect_events(event: EventMessage):
            replayed_events.append(event)
        
        # Переигрываем события после второго
        result_stream_id = await event_store.replay_events_after(
            event_ids[1], 
            collect_events
        )
        
        assert result_stream_id == stream_id
        assert len(replayed_events) == 3  # События 2, 3, 4
        
        # Проверяем, что события идут в правильном порядке
        for i, event in enumerate(replayed_events):
            expected_index = i + 2
            assert event.data.params["index"] == expected_index
            
    @pytest.mark.asyncio
    async def test_replay_nonexistent_event(self, event_store):
        """Тест переигрывания с несуществующим ID события"""
        replayed_events = []
        
        async def collect_events(event: EventMessage):
            replayed_events.append(event)
        
        result = await event_store.replay_events_after(
            "nonexistent-id",
            collect_events
        )
        
        assert result is None
        assert len(replayed_events) == 0
        
    @pytest.mark.asyncio
    async def test_replay_last_event(self, event_store):
        """Тест переигрывания после последнего события"""
        stream_id = "test-stream"
        event_ids = []
        replayed_events = []
        
        # Сохраняем несколько событий
        for i in range(3):
            message = JSONRPCRequest(
                jsonrpc="2.0",
                id=f"test-{i}",
                method="test_method",
                params={"index": i}
            )
            event_id = await event_store.store_event(stream_id, message)
            event_ids.append(event_id)
        
        async def collect_events(event: EventMessage):
            replayed_events.append(event)
        
        # Переигрываем после последнего события
        result = await event_store.replay_events_after(
            event_ids[-1],
            collect_events
        )
        
        assert result == stream_id
        assert len(replayed_events) == 0  # Нет событий после последнего


class TestStreamManagement:
    """Тесты управления потоками"""
    
    def test_get_stream_stats(self, event_store):
        """Тест получения статистики потоков"""
        # Изначально пусто
        stats = event_store.get_stream_stats()
        assert len(stats) == 0
        
        # Добавляем события в разные потоки
        asyncio.run(event_store.store_event("stream1", JSONRPCRequest(
            jsonrpc="2.0", id="1", method="test"
        )))
        asyncio.run(event_store.store_event("stream1", JSONRPCRequest(
            jsonrpc="2.0", id="2", method="test"
        )))
        asyncio.run(event_store.store_event("stream2", JSONRPCRequest(
            jsonrpc="2.0", id="3", method="test"
        )))
        
        stats = event_store.get_stream_stats()
        assert stats["stream1"] == 2
        assert stats["stream2"] == 1
        
    def test_clear_stream(self, event_store):
        """Тест очистки потока"""
        stream_id = "test-stream"
        
        # Добавляем события
        for i in range(3):
            asyncio.run(event_store.store_event(stream_id, JSONRPCRequest(
                jsonrpc="2.0", id=f"{i}", method="test"
            )))
        
        # Проверяем, что события есть
        assert len(event_store.streams[stream_id]) == 3
        
        # Очищаем поток
        count = event_store.clear_stream(stream_id)
        assert count == 3
        assert len(event_store.streams[stream_id]) == 0
        
        # События должны быть удалены из индекса
        assert all(
            entry.stream_id != stream_id 
            for entry in event_store.event_index.values()
        )
        
    def test_clear_nonexistent_stream(self, event_store):
        """Тест очистки несуществующего потока"""
        count = event_store.clear_stream("nonexistent")
        assert count == 0
        
    def test_clear_all(self, event_store):
        """Тест очистки всех событий"""
        # Добавляем события в разные потоки
        for stream in ["stream1", "stream2", "stream3"]:
            for i in range(2):
                asyncio.run(event_store.store_event(stream, JSONRPCRequest(
                    jsonrpc="2.0", id=f"{stream}-{i}", method="test"
                )))
        
        # Проверяем, что события есть
        assert len(event_store.streams) == 3
        assert len(event_store.event_index) == 6
        
        # Очищаем все
        count = event_store.clear_all()
        assert count == 6
        assert len(event_store.streams) == 0
        assert len(event_store.event_index) == 0


class TestMultipleStreams:
    """Тесты работы с несколькими потоками"""
    
    @pytest.mark.asyncio
    async def test_independent_streams(self, event_store):
        """Тест независимости потоков"""
        # Добавляем события в разные потоки
        event_id1 = await event_store.store_event("stream1", JSONRPCRequest(
            jsonrpc="2.0", id="1", method="method1"
        ))
        event_id2 = await event_store.store_event("stream2", JSONRPCRequest(
            jsonrpc="2.0", id="2", method="method2"
        ))
        
        # Потоки должны быть независимы
        assert len(event_store.streams["stream1"]) == 1
        assert len(event_store.streams["stream2"]) == 1
        
        # События должны быть в правильных потоках
        entry1 = event_store.event_index[event_id1]
        entry2 = event_store.event_index[event_id2]
        
        assert entry1.stream_id == "stream1"
        assert entry2.stream_id == "stream2"
        assert entry1.message.method == "method1"
        assert entry2.message.method == "method2"
