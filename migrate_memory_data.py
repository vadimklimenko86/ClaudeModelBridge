
#!/usr/bin/env python3
"""
Скрипт для миграции данных из SQLite memory.db в PostgreSQL
"""

import sqlite3
import psycopg2
import psycopg2.extras
import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def connect_to_sqlite(db_path: str) -> sqlite3.Connection:
    """Подключение к SQLite базе данных"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Для доступа к колонкам по имени
        logger.info(f"Подключение к SQLite: {db_path}")
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения к SQLite: {e}")
        raise


def connect_to_postgresql() -> psycopg2.extensions.connection:
    """Подключение к PostgreSQL базе данных"""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise ValueError("DATABASE_URL не найден в переменных окружения")
    
    try:
        conn = psycopg2.connect(db_url)
        logger.info("Подключение к PostgreSQL успешно")
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения к PostgreSQL: {e}")
        raise


def ensure_postgresql_table(pg_conn: psycopg2.extensions.connection):
    """Убедиться, что таблица memories существует в PostgreSQL"""
    with pg_conn.cursor() as cursor:
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
        
        # Создание индексов
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_importance ON memories(importance DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON memories(timestamp DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_content_hash ON memories(content_hash)
        """)
        
        pg_conn.commit()
        logger.info("Таблица memories и индексы созданы/проверены в PostgreSQL")


def convert_timestamp(sqlite_timestamp: str) -> str:
    """Конвертация timestamp из SQLite формата в PostgreSQL формат"""
    try:
        # SQLite хранит в формате: 2025-06-25T22:30:21.337674+00:00
        # PostgreSQL принимает этот же формат
        return sqlite_timestamp
    except Exception as e:
        logger.warning(f"Ошибка конвертации timestamp {sqlite_timestamp}: {e}")
        # Возвращаем текущее время как fallback
        return datetime.now().isoformat()


def migrate_memory_data(sqlite_path: str):
    """Основная функция миграции данных"""
    # Подключения к базам данных
    sqlite_conn = connect_to_sqlite(sqlite_path)
    pg_conn = connect_to_postgresql()
    
    try:
        # Убеждаемся, что таблица существует
        ensure_postgresql_table(pg_conn)
        
        # Читаем данные из SQLite
        sqlite_cursor = sqlite_conn.cursor()
        try:
            sqlite_cursor.execute("""
                SELECT id, content, summary, importance, access_count, 
                       timestamp, embedding_json, metadata_json, content_hash
                FROM memories
                ORDER BY id
            """)
            
            records = sqlite_cursor.fetchall()
            logger.info(f"Найдено {len(records)} записей в SQLite")
            
            if not records:
                logger.info("Нет данных для миграции")
                return
            
            # Вставляем данные в PostgreSQL
            with pg_conn.cursor() as pg_cursor:
                migrated_count = 0
                skipped_count = 0
                
                for record in records:
                    try:
                        # Конвертируем timestamp
                        converted_timestamp = convert_timestamp(record['timestamp'])
                        
                        # Проверяем, существует ли запись с таким content_hash
                        pg_cursor.execute(
                            "SELECT id FROM memories WHERE content_hash = %s",
                            (record['content_hash'],)
                        )
                        
                        if pg_cursor.fetchone():
                            logger.debug(f"Запись с hash {record['content_hash']} уже существует, пропускаем")
                            skipped_count += 1
                            continue
                        
                        # Вставляем новую запись
                        pg_cursor.execute("""
                            INSERT INTO memories 
                            (content, summary, importance, access_count, timestamp, 
                             embedding_json, metadata_json, content_hash)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            record['content'],
                            record['summary'],
                            record['importance'],
                            record['access_count'],
                            converted_timestamp,
                            record['embedding_json'],
                            record['metadata_json'],
                            record['content_hash']
                        ))
                        
                        migrated_count += 1
                        
                        if migrated_count % 10 == 0:
                            logger.info(f"Мигрировано {migrated_count} записей...")
                    
                    except Exception as e:
                        logger.error(f"Ошибка при миграции записи {record['id']}: {e}")
                        skipped_count += 1
                        continue
                
                # Коммитим изменения
                pg_conn.commit()
                
                logger.info(f"Миграция завершена!")
                logger.info(f"Мигрировано: {migrated_count} записей")
                logger.info(f"Пропущено: {skipped_count} записей")
                
                # Проверяем итоговое количество записей в PostgreSQL
                pg_cursor.execute("SELECT COUNT(*) FROM memories")
                total_count = pg_cursor.fetchone()[0]
                logger.info(f"Общее количество записей в PostgreSQL: {total_count}")
        
        finally:
            sqlite_cursor.close()
    
    except Exception as e:
        logger.error(f"Ошибка во время миграции: {e}")
        pg_conn.rollback()
        raise
    
    finally:
        sqlite_conn.close()
        pg_conn.close()
        logger.info("Подключения к базам данных закрыты")


def verify_migration(sqlite_path: str):
    """Проверка успешности миграции"""
    sqlite_conn = connect_to_sqlite(sqlite_path)
    pg_conn = connect_to_postgresql()
    
    try:
        # Подсчет записей в SQLite
        sqlite_cursor = sqlite_conn.cursor()
        try:
            sqlite_cursor.execute("SELECT COUNT(*) FROM memories")
            sqlite_count = sqlite_cursor.fetchone()[0]
        finally:
            sqlite_cursor.close()
        
        # Подсчет записей в PostgreSQL
        with pg_conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM memories")
            pg_count = cursor.fetchone()[0]
        
        logger.info(f"Записей в SQLite: {sqlite_count}")
        logger.info(f"Записей в PostgreSQL: {pg_count}")
        
        if pg_count >= sqlite_count:
            logger.info("✅ Миграция прошла успешно!")
        else:
            logger.warning("⚠️ Количество записей в PostgreSQL меньше, чем в SQLite")
            
    except Exception as e:
        logger.error(f"Ошибка при проверке миграции: {e}")
    
    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    # Путь к файлу SQLite
    sqlite_file = "attached_assets/memory_1750946124184.db"
    
    if not os.path.exists(sqlite_file):
        logger.error(f"Файл {sqlite_file} не найден!")
        exit(1)
    
    try:
        logger.info("Начинаем миграцию данных из SQLite в PostgreSQL...")
        migrate_memory_data(sqlite_file)
        
        logger.info("Проверяем результаты миграции...")
        verify_migration(sqlite_file)
        
        logger.info("Миграция завершена успешно!")
        
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        exit(1)
