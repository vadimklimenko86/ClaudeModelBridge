from MCP_Tools import MCP_Tools
import mcp.types as types
import datetime
import os
import logging
import json
import asyncio
import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Annotated, Any
from pathlib import Path
import psycopg2
import psycopg2.extras
import threading
import hashlib

# Попытка импорта OpenAI (опционально)
try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Попытка импорта numpy для векторных операций
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# Константы для системы памяти
MAX_DEPTH = 5
#SIMILARITY_THRESHOLD = 0.7
SIMILARITY_THRESHOLD = 0.2
DECAY_FACTOR = 0.99
REINFORCEMENT_FACTOR = 1.1
EMBEDDING_DIMENSION = 1536  # Для text-embedding-3-small


@dataclass
class MemoryNode:
    """Узел памяти с векторным представлением"""
    id: Optional[int] = None
    content: str = ""
    summary: str = ""
    importance: float = 1.0
    access_count: int = 0
    timestamp: Optional[datetime.datetime] = None
    embedding: Optional[List[float]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now(datetime.timezone.utc)
        if self.metadata is None:
            self.metadata = {}


class MemorySystem:
    """Система рекурсивной памяти"""

    def __init__(self, db_url: str = None):
        self.db_url = db_url or os.environ.get("DATABASE_URL")
        if not self.db_url:
            raise ValueError("DATABASE_URL not found in environment variables")
        self.lock = threading.RLock()
        self.logger = logging.getLogger('MemorySystem')
        self._setup_database()

        # Настройка OpenAI клиента если доступен
        self.openai_client = None
        if HAS_OPENAI:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                self.openai_client = openai.OpenAI(api_key=api_key)
                self.logger.info("OpenAI client initialized")
            else:
                self.logger.warning("OPENAI_API_KEY not found in environment")

    def _setup_database(self):
        """Инициализация базы данных PostgreSQL"""
        try:
            with psycopg2.connect(self.db_url) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS memories (
                            id SERIAL PRIMARY KEY,
                            content TEXT NOT NULL,
                            summary TEXT,
                            importance REAL DEFAULT 1.0,
                            access_count INTEGER DEFAULT 0,
                            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                            embedding_json TEXT,
                            metadata_json TEXT,
                            content_hash TEXT UNIQUE
                        )
                    """)

                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_importance ON memories(importance DESC)
                    """)

                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_timestamp ON memories(timestamp DESC)
                    """)

                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_content_hash ON memories(content_hash)
                    """)
                    
                    conn.commit()
                    self.logger.info("PostgreSQL database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize PostgreSQL database: {e}")
            raise

    def _get_embedding_sync(self, text: str) -> Optional[List[float]]:
        """Синхронная версия получения эмбеддинга"""
        if not self.openai_client:
            self.logger.warning(
                "OpenAI client not available, using simple hash-based embedding"
            )
            return self._simple_embedding(text)

        try:
            response = self.openai_client.embeddings.create(
                model="text-embedding-3-small", input=text)
            return response.data[0].embedding
        except Exception as e:
            self.logger.error(f"Failed to get OpenAI embedding: {e}")
            return self._simple_embedding(text)

    async def _get_embedding(self, text: str) -> Optional[List[float]]:
        """Получение эмбеддинга текста через OpenAI API"""
        if not self.openai_client:
            self.logger.warning(
                "OpenAI client not available, using simple hash-based embedding"
            )
            return self._simple_embedding(text)

        try:
            response = await asyncio.to_thread(
                self.openai_client.embeddings.create,
                model="text-embedding-3-small",
                input=text)
            return response.data[0].embedding
        except Exception as e:
            self.logger.error(f"Failed to get OpenAI embedding: {e}")
            return self._simple_embedding(text)

    def _simple_embedding(self, text: str) -> List[float]:
        """Простое эмбеддинг на основе хеша (fallback)"""
        # Создаем детерминированный вектор на основе хеша текста
        hash_obj = hashlib.md5(text.encode())
        hash_bytes = hash_obj.digest()

        # Преобразуем в вектор фиксированной размерности
        embedding = []
        for i in range(min(EMBEDDING_DIMENSION, len(hash_bytes) * 8)):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(hash_bytes):
                bit_val = (hash_bytes[byte_idx] >> bit_idx) & 1
                embedding.append(float(bit_val))
            else:
                embedding.append(0.0)

        # Дополняем до нужной размерности
        while len(embedding) < EMBEDDING_DIMENSION:
            embedding.append(0.0)

        # Нормализуем
        if HAS_NUMPY:
            embedding = np.array(embedding)
            norm = np.linalg.norm(embedding)
            if norm > 0:
                embedding = embedding / norm
            return embedding.tolist()
        else:
            # Простая нормализация без numpy
            norm = sum(x * x for x in embedding)**0.5
            if norm > 0:
                embedding = [x / norm for x in embedding]
            return embedding

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """Вычисление косинусной схожести между векторами"""
        if not HAS_NUMPY:
            # Простая реализация без numpy
            dot_product = sum(x * y for x, y in zip(a, b))
            norm_a = sum(x * x for x in a)**0.5
            norm_b = sum(x * x for x in b)**0.5

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot_product / (norm_a * norm_b)
        else:
            # Используем numpy для более точных вычислений
            a_array = np.array(a, dtype=np.float64)
            b_array = np.array(b, dtype=np.float64)
            return float(
                np.dot(a_array, b_array) /
                (np.linalg.norm(a_array) * np.linalg.norm(b_array)))

    def _content_hash(self, content: str) -> str:
        """Создание хеша содержимого для проверки дубликатов"""
        return hashlib.sha256(content.encode()).hexdigest()

    def add_memory_sync(self,
                        content: str,
                        importance: float = 1.0,
                        metadata: Optional[Dict[str, Any]] = None) -> int:
        """Синхронная версия добавления воспоминания"""
        if not content.strip():
            raise ValueError("Содержимое памяти не может быть пустым")

        content_hash = self._content_hash(content)
        embedding = self._get_embedding_sync(content)

        if not embedding:
            raise RuntimeError("Не удалось создать эмбеддинг для содержимого")

        # Создание краткого резюме (первые 100 символов)
        summary = content[:100] + "..." if len(content) > 100 else content

        memory_node = MemoryNode(content=content,
                                 summary=summary,
                                 importance=importance,
                                 embedding=embedding,
                                 metadata=metadata or {})

        with self.lock:
            try:
                with psycopg2.connect(self.db_url) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO memories (content, summary, importance, access_count, timestamp, embedding_json, metadata_json, content_hash)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
                        """,
                            (memory_node.content, memory_node.summary,
                             memory_node.importance, memory_node.access_count,
                             memory_node.timestamp,
                             json.dumps(memory_node.embedding, ensure_ascii=False),
                             json.dumps(memory_node.metadata,
                                        ensure_ascii=False), content_hash))
                        memory_id = cursor.fetchone()[0]
                        conn.commit()

                self.logger.info(f"Memory added with ID: {memory_id}")
                return memory_id

            except psycopg2.IntegrityError:
                self.logger.warning(
                    f"Memory with this content already exists: {content[:50]}..."
                )
                # Возвращаем ID существующей записи
                with psycopg2.connect(self.db_url) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "SELECT id FROM memories WHERE content_hash = %s",
                            (content_hash, ))
                        result = cursor.fetchone()
                        return result[0] if result else -1

    async def add_memory(self,
                         content: str,
                         importance: float = 1.0,
                         metadata: Optional[Dict[str, Any]] = None) -> int:
        """Добавление новой записи в память"""
        return await asyncio.to_thread(self.add_memory_sync, content,
                                       importance, metadata)

    def search_memories_sync(
            self,
            query: str,
            limit: int = 10,
            min_similarity: float = SIMILARITY_THRESHOLD
    ) -> List[Dict[str, Any]]:
        """Синхронная версия поиска воспоминаний"""
        if not query.strip():
            return []

        query_embedding = self._get_embedding_sync(query)
        if not query_embedding:
            self.logger.error("Failed to create embedding for query")
            return []

        with self.lock:
            with psycopg2.connect(self.db_url) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, content, summary, importance, access_count, timestamp, embedding_json, metadata_json
                        FROM memories 
                        ORDER BY importance DESC, timestamp DESC
                    """)

                    results = []
                    for row in cursor.fetchall():
                        memory_id, content, summary, importance, access_count, timestamp, embedding_json, metadata_json = row

                        try:
                            embedding = json.loads(
                                embedding_json) if embedding_json else []
                            metadata = json.loads(
                                metadata_json) if metadata_json else {}

                            if embedding:
                                similarity = self._cosine_similarity(
                                    query_embedding, embedding)

                                if similarity >= min_similarity:
                                    # Обновляем счетчик доступа и важность
                                    new_access_count = access_count + 1
                                    new_importance = importance * REINFORCEMENT_FACTOR

                                    cursor.execute(
                                        """
                                        UPDATE memories 
                                        SET access_count = %s, importance = %s
                                        WHERE id = %s
                                    """, (new_access_count, new_importance,
                                          memory_id))

                                    results.append({
                                        'id': memory_id,
                                        'content': content,
                                        'summary': summary,
                                        'importance': new_importance,
                                        'access_count': new_access_count,
                                        'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                                        'similarity': similarity,
                                        'metadata': metadata
                                    })
                        except (json.JSONDecodeError, Exception) as e:
                            self.logger.warning(
                                f"Error processing memory {memory_id}: {e}")
                            continue

                    conn.commit()
                    # Сортируем по схожести и ограничиваем результат
                    results.sort(key=lambda x: x['similarity'], reverse=True)
                    return results[:limit]

    async def search_memories(
            self,
            query: str,
            limit: int = 10,
            min_similarity: float = SIMILARITY_THRESHOLD
    ) -> List[Dict[str, Any]]:
        """Поиск воспоминаний по запросу"""
        return await asyncio.to_thread(self.search_memories_sync, query, limit,
                                       min_similarity)

    def get_all_memories_sync(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Синхронная версия получения всех воспоминаний"""
        with self.lock:
            with psycopg2.connect(self.db_url) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT id, content, summary, importance, access_count, timestamp, metadata_json
                        FROM memories 
                        ORDER BY importance DESC, timestamp DESC
                        LIMIT %s
                    """, (limit, ))

                    results = []
                    for row in cursor.fetchall():
                        memory_id, content, summary, importance, access_count, timestamp, metadata_json = row
                        try:
                            metadata = json.loads(
                                metadata_json) if metadata_json else {}
                            results.append({
                                'id': memory_id,
                                'content': content,
                                'summary': summary,
                                'importance': importance,
                                'access_count': access_count,
                                'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                                'metadata': metadata
                            })
                        except json.JSONDecodeError:
                            results.append({
                                'id': memory_id,
                                'content': content,
                                'summary': summary,
                                'importance': importance,
                                'access_count': access_count,
                                'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                                'metadata': {}
                            })

                    return results

    async def get_all_memories(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получение всех воспоминаний"""
        return await asyncio.to_thread(self.get_all_memories_sync, limit)

    def delete_memory_sync(self, memory_id: int) -> bool:
        """Синхронная версия удаления воспоминания"""
        with self.lock:
            with psycopg2.connect(self.db_url) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM memories WHERE id = %s",
                                          (memory_id, ))
                    deleted = cursor.rowcount > 0
                    conn.commit()

                    if deleted:
                        self.logger.info(f"Memory {memory_id} deleted")
                    else:
                        self.logger.warning(
                            f"Memory {memory_id} not found for deletion")

                    return deleted

    async def delete_memory(self, memory_id: int) -> bool:
        """Удаление воспоминания по ID"""
        return await asyncio.to_thread(self.delete_memory_sync, memory_id)

    def cleanup_old_memories_sync(self,
                                  max_age_days: int = 30,
                                  max_count: int = 1000) -> int:
        """Синхронная версия очистки старых воспоминаний"""
        cutoff_date = datetime.datetime.now(
            datetime.timezone.utc) - datetime.timedelta(days=max_age_days)

        with self.lock:
            with psycopg2.connect(self.db_url) as conn:
                with conn.cursor() as cursor:
                    # Сначала применяем decay к старым воспоминаниям
                    cursor.execute(
                        """
                        UPDATE memories 
                        SET importance = importance * %s
                        WHERE timestamp < %s
                    """, (DECAY_FACTOR, cutoff_date))

                    # Удаляем самые неважные записи, если их слишком много
                    cursor.execute("SELECT COUNT(*) FROM memories")
                    total_count = cursor.fetchone()[0]

                    deleted_count = 0
                    if total_count > max_count:
                        delete_count = total_count - max_count
                        cursor.execute(
                            """
                            DELETE FROM memories 
                            WHERE id IN (
                                SELECT id FROM memories 
                                ORDER BY importance ASC, access_count ASC 
                                LIMIT %s
                            )
                        """, (delete_count, ))
                        deleted_count = cursor.rowcount
                        
                    conn.commit()
                    self.logger.info(f"Cleaned up {deleted_count} old memories")
                    return deleted_count

    async def cleanup_old_memories(self,
                                   max_age_days: int = 30,
                                   max_count: int = 1000) -> int:
        """Очистка старых и неважных воспоминаний"""
        return await asyncio.to_thread(self.cleanup_old_memories_sync,
                                       max_age_days, max_count)


class MemoryTools:
    """Инструменты для работы с памятью в MCP"""

    def __init__(self, mcp: MCP_Tools) -> None:
        self.tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))
        self.memory_system = MemorySystem()
        self.logger = logging.getLogger('MemoryTools')

        # Настройка логирования
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        self._register_tools(mcp)
        self.logger.info("MemoryTools initialized")

    def _safe_run_async(self, coro):
        """Безопасный запуск асинхронного кода в MCP контексте"""
        try:
            # Проверяем, есть ли активный event loop
            loop = asyncio.get_running_loop()
            # Создаем задачу в текущем loop
            future = asyncio.ensure_future(coro, loop=loop)
            # Ждем выполнения с таймаутом
            timeout = 30  # 30 секунд таймаут
            start_time = time.time()
            while not future.done() and (time.time() - start_time) < timeout:
                time.sleep(0.01)

            if future.done():
                return future.result()
            else:
                future.cancel()
                raise TimeoutError("Async operation timed out")

        except RuntimeError:
            # Если нет активного loop, используем синхронные версии
            self.logger.info("No active event loop, using sync versions")
            return None
        except Exception as e:
            self.logger.error(f"Error in async execution: {e}")
            raise

    def _register_tools(self, mcp: MCP_Tools):
        """Регистрация всех инструментов памяти"""

        @mcp.register_tool(name="add_memory",
                           description="Добавить новое воспоминание в память")
        def add_memory(
            content: Annotated[str, "Содержимое воспоминания"],
            importance: Annotated[float,
                                  "Важность воспоминания (0.0-10.0)"] = 1.0,
            tags: Annotated[str, "Теги через запятую (опционально)"] = ""
        ) -> list[types.TextContent | types.ImageContent
                  | types.EmbeddedResource]:
            try:
                if not content.strip():
                    return [
                        types.TextContent(
                            type="text",
                            text="Ошибка: Содержимое не может быть пустым")
                    ]

                # Подготовка метаданных
                metadata = {}
                if tags.strip():
                    metadata['tags'] = [
                        tag.strip() for tag in tags.split(',') if tag.strip()
                    ]
                metadata['created_at'] = datetime.datetime.now(
                    self.tz_plus3).isoformat()

                # Используем синхронную версию
                memory_id = self.memory_system.add_memory_sync(
                    content, importance, metadata)

                if memory_id > 0:
                    self.logger.info(f"Added memory with ID: {memory_id}")
                    return [
                        types.TextContent(
                            type="text",
                            text=
                            f"✅ Воспоминание добавлено в память с ID: {memory_id}"
                        )
                    ]
                else:
                    return [
                        types.TextContent(
                            type="text",
                            text=
                            "⚠️ Воспоминание с таким содержимым уже существует"
                        )
                    ]

            except Exception as e:
                error_msg = f"Ошибка при добавлении воспоминания: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="search_memory",
                           description="Поиск воспоминаний по запросу")
        def search_memory(
            query: Annotated[str, "Поисковый запрос"],
            limit: Annotated[int, "Максимальное количество результатов"] = 10,
            min_similarity: Annotated[
                float, "Минимальная схожесть (0.0-1.0)"] = SIMILARITY_THRESHOLD
        ) -> list[types.TextContent | types.ImageContent
                  | types.EmbeddedResource]:
            try:
                if not query.strip():
                    return [
                        types.TextContent(
                            type="text",
                            text="Ошибка: Поисковый запрос не может быть пустым"
                        )
                    ]

                # Используем синхронную версию
                results = self.memory_system.search_memories_sync(
                    query, limit, min_similarity)

                if not results:
                    return [
                        types.TextContent(
                            type="text",
                            text=
                            f"🔍 По запросу '{query}' воспоминания не найдены")
                    ]

                # Форматирование результатов с проверкой на None
                response = f"🔍 Найдено {len(results)} воспоминаний по запросу '{query}':\n\n"

                for i, memory in enumerate(results, 1):
                    try:
                        timestamp = datetime.datetime.fromisoformat(
                            memory['timestamp']).strftime("%Y-%m-%d %H:%M")
                    except:
                        timestamp = "неизвестно"

                    similarity_percent = (memory.get('similarity', 0)
                                          or 0) * 100
                    importance = memory.get('importance', 0) or 0

                    response += f"**{i}. [ID: {memory.get('id', 'unknown')}]** (схожесть: {similarity_percent:.1f}%)\n"
                    response += f"📅 {timestamp} | 🔥 Важность: {importance:.2f}\n"
                    response += f"📝 {memory.get('summary', 'Без описания')}\n"

                    content = memory.get('content', '')
                    if len(content) > 200:
                        response += f"💭 {content[:200]}...\n"
                    else:
                        response += f"💭 {content}\n"

                    if memory.get('metadata',
                                  {}) and memory['metadata'].get('tags'):
                        tags = ', '.join(memory['metadata']['tags'])
                        response += f"🏷️ Теги: {tags}\n"

                    response += "\n"

                self.logger.info(
                    f"Search completed: {len(results)} results for '{query}'")
                return [types.TextContent(type="text", text=response)]

            except Exception as e:
                error_msg = f"Ошибка при поиске воспоминаний: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="list_memories",
                           description="Получить список всех воспоминаний")
        def list_memories(
            limit: Annotated[int, "Максимальное количество воспоминаний"] = 20
        ) -> list[types.TextContent | types.ImageContent
                  | types.EmbeddedResource]:
            try:
                memories = self.memory_system.get_all_memories_sync(limit)

                if not memories:
                    return [
                        types.TextContent(
                            type="text",
                            text="📝 Память пуста - воспоминания не найдены")
                    ]

                response = f"📚 Последние {len(memories)} воспоминаний:\n\n"

                for i, memory in enumerate(memories, 1):
                    try:
                        timestamp = datetime.datetime.fromisoformat(
                            memory['timestamp']).strftime("%Y-%m-%d %H:%M")
                    except:
                        timestamp = "неизвестно"

                    importance = memory.get('importance', 0) or 0
                    access_count = memory.get('access_count', 0) or 0

                    response += f"**{i}. [ID: {memory.get('id', 'unknown')}]**\n"
                    response += f"📅 {timestamp} | 🔥 Важность: {importance:.2f} | 👁️ Просмотры: {access_count}\n"
                    response += f"📝 {memory.get('summary', 'Без описания')}\n"

                    if memory.get('metadata',
                                  {}) and memory['metadata'].get('tags'):
                        tags = ', '.join(memory['metadata']['tags'])
                        response += f"🏷️ Теги: {tags}\n"

                    response += "\n"

                self.logger.info(f"Listed {len(memories)} memories")
                return [types.TextContent(type="text", text=response)]

            except Exception as e:
                error_msg = f"Ошибка при получении списка воспоминаний: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="delete_memory",
                           description="Удалить воспоминание по ID")
        def delete_memory(
            memory_id: Annotated[int, "ID воспоминания для удаления"]
        ) -> list[types.TextContent | types.ImageContent
                  | types.EmbeddedResource]:
            try:
                success = self.memory_system.delete_memory_sync(memory_id)

                if success:
                    self.logger.info(f"Deleted memory with ID: {memory_id}")
                    return [
                        types.TextContent(
                            type="text",
                            text=
                            f"✅ Воспоминание с ID {memory_id} успешно удалено")
                    ]
                else:
                    return [
                        types.TextContent(
                            type="text",
                            text=f"❌ Воспоминание с ID {memory_id} не найдено")
                    ]

            except Exception as e:
                error_msg = f"Ошибка при удалении воспоминания: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(
            name="cleanup_memory",
            description="Очистка старых и неважных воспоминаний")
        def cleanup_memory(
            max_age_days: Annotated[
                int, "Максимальный возраст воспоминаний в днях"] = 30,
            max_count: Annotated[int,
                                 "Максимальное количество воспоминаний"] = 1000
        ) -> list[types.TextContent | types.ImageContent
                  | types.EmbeddedResource]:
            try:
                deleted_count = self.memory_system.cleanup_old_memories_sync(
                    max_age_days, max_count)

                self.logger.info(
                    f"Memory cleanup completed: {deleted_count} memories deleted"
                )
                return [
                    types.TextContent(
                        type="text",
                        text=
                        f"🧹 Очистка памяти завершена. Удалено {deleted_count} старых воспоминаний"
                    )
                ]

            except Exception as e:
                error_msg = f"Ошибка при очистке памяти: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="memory_stats",
                           description="Получить статистику системы памяти")
        def memory_stats() -> list[types.TextContent | types.ImageContent
                                   | types.EmbeddedResource]:
            try:
                with psycopg2.connect(self.memory_system.db_url) as conn:
                    with conn.cursor() as cursor:
                        # Общее количество воспоминаний
                        cursor.execute("SELECT COUNT(*) FROM memories")
                        total_memories = cursor.fetchone()[0]

                        # Топ-5 по важности
                        cursor.execute("""
                            SELECT content, importance, access_count 
                            FROM memories 
                            ORDER BY importance DESC 
                            LIMIT 5
                        """)
                        top_memories = cursor.fetchall()

                        # Статистика по возрасту с проверкой на None
                        cursor.execute("""
                            SELECT 
                                COUNT(*) as count,
                                AVG(importance) as avg_importance,
                                AVG(access_count) as avg_access
                            FROM memories 
                            WHERE timestamp > NOW() - INTERVAL '7 days'
                        """)
                        recent_stats = cursor.fetchone()

                has_openai = "✅" if getattr(self.memory_system,
                                            'openai_client', None) else "❌"
                has_numpy = "✅" if HAS_NUMPY else "❌"

                response = "📊 **Статистика системы памяти:**\n\n"
                response += f"🧠 Общее количество воспоминаний: **{total_memories or 0}**\n"
                response += f"📈 Воспоминания за последнюю неделю: **{recent_stats[0] or 0}**\n"

                # Безопасное форматирование с проверкой на None
                avg_importance = recent_stats[1] if recent_stats[
                    1] is not None else 0
                avg_access = recent_stats[2] if recent_stats[
                    2] is not None else 0

                response += f"⚡ Средняя важность (неделя): **{avg_importance:.2f}**\n"
                response += f"👁️ Среднее количество просмотров (неделя): **{avg_access:.1f}**\n\n"

                response += "🔧 **Состояние системы:**\n"
                response += f"OpenAI API: {has_openai}\n"
                response += f"NumPy: {has_numpy}\n"
                response += f"База данных: PostgreSQL\n\n"

                if top_memories:
                    response += "🔥 **Топ-5 важных воспоминаний:**\n"
                    for i, (content, importance,
                            access_count) in enumerate(top_memories, 1):
                        content = content or "Пустое содержимое"
                        importance = importance or 0
                        access_count = access_count or 0
                        preview = content[:60] + "..." if len(
                            content) > 60 else content
                        response += f"{i}. {preview} (важность: {importance:.2f}, просмотры: {access_count})\n"

                return [types.TextContent(type="text", text=response)]

            except Exception as e:
                error_msg = f"Ошибка при получении статистики: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]
