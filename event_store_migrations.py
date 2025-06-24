"""
Миграции и утилиты для управления Event Store.
"""

import asyncio
import json
import logging
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class EventStoreManager:
    """Менеджер для управления Event Store - миграции, бэкапы, мониторинг."""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.backup_dir = self.db_path.parent / "backups"
        
    def create_backup(self, backup_name: Optional[str] = None) -> Path:
        """
        Создает резервную копию базы данных.
        
        Args:
            backup_name: Имя файла бэкапа (по умолчанию с timestamp)
            
        Returns:
            Path: Путь к созданному бэкапу
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"База данных не найдена: {self.db_path}")
        
        # Создаем директорию для бэкапов
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Генерируем имя файла если не указано
        if backup_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"events_backup_{timestamp}.db"
        
        backup_path = self.backup_dir / backup_name
        
        # Создаем бэкап
        shutil.copy2(self.db_path, backup_path)
        
        logger.info(f"Создан бэкап: {backup_path}")
        return backup_path
    
    def restore_from_backup(self, backup_path: str) -> None:
        """
        Восстанавливает базу данных из бэкапа.
        
        Args:
            backup_path: Путь к файлу бэкапа
        """
        backup_file = Path(backup_path)
        if not backup_file.exists():
            raise FileNotFoundError(f"Файл бэкапа не найден: {backup_path}")
        
        # Создаем бэкап текущей БД перед восстановлением
        if self.db_path.exists():
            current_backup = self.create_backup("before_restore")
            logger.info(f"Создан бэкап текущей БД: {current_backup}")
        
        # Восстанавливаем из бэкапа
        shutil.copy2(backup_file, self.db_path)
        
        logger.info(f"База данных восстановлена из: {backup_path}")
    
    def cleanup_old_backups(self, retention_days: int = 7) -> int:
        """
        Удаляет старые бэкапы.
        
        Args:
            retention_days: Количество дней для хранения бэкапов
            
        Returns:
            int: Количество удаленных файлов
        """
        if not self.backup_dir.exists():
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_count = 0
        
        for backup_file in self.backup_dir.glob("*.db"):
            if backup_file.stat().st_mtime < cutoff_date.timestamp():
                backup_file.unlink()
                deleted_count += 1
                logger.debug(f"Удален старый бэкап: {backup_file}")
        
        logger.info(f"Удалено {deleted_count} старых бэкапов")
        return deleted_count
    
    def get_database_stats(self) -> Dict:
        """Получает подробную статистику базы данных."""
        if not self.db_path.exists():
            return {"error": "База данных не существует"}
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Основная статистика
            cursor.execute("SELECT COUNT(*) FROM events")
            stats["total_events"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT stream_id) FROM events")
            stats["total_streams"] = cursor.fetchone()[0]
            
            # Временные рамки
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events")
            time_range = cursor.fetchone()
            stats["oldest_event"] = time_range[0]
            stats["newest_event"] = time_range[1]
            
            # Статистика по потокам
            cursor.execute("""
                SELECT stream_id, COUNT(*) as event_count,
                       MIN(timestamp) as first_event,
                       MAX(timestamp) as last_event
                FROM events
                GROUP BY stream_id
                ORDER BY event_count DESC
                LIMIT 10
            """)
            
            stats["top_streams"] = []
            for row in cursor.fetchall():
                stats["top_streams"].append({
                    "stream_id": row[0],
                    "event_count": row[1],
                    "first_event": row[2],
                    "last_event": row[3]
                })
            
            # События по дням (последние 30 дней)
            cursor.execute("""
                SELECT DATE(timestamp) as event_date, COUNT(*) as daily_count
                FROM events
                WHERE timestamp >= datetime('now', '-30 days')
                GROUP BY DATE(timestamp)
                ORDER BY event_date DESC
            """)
            
            stats["daily_events"] = []
            for row in cursor.fetchall():
                stats["daily_events"].append({
                    "date": row[0],
                    "count": row[1]
                })
            
            # Размер базы данных
            stats["db_size_bytes"] = self.db_path.stat().st_size
            stats["db_size_mb"] = round(stats["db_size_bytes"] / 1024 / 1024, 2)
            
            # Информация о таблицах
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            stats["tables"] = [row[0] for row in cursor.fetchall()]
            
            # Индексы
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
            stats["indexes"] = [row[0] for row in cursor.fetchall()]
            
        return stats
    
    def validate_database(self) -> Dict:
        """Проверяет целостность базы данных."""
        if not self.db_path.exists():
            return {"valid": False, "errors": ["База данных не существует"]}
        
        errors = []
        warnings = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Проверка целостности SQLite
                cursor.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()[0]
                if integrity_result != "ok":
                    errors.append(f"Нарушена целостность SQLite: {integrity_result}")
                
                # Проверка схемы
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
                if not cursor.fetchone():
                    errors.append("Отсутствует таблица events")
                else:
                    # Проверка столбцов
                    cursor.execute("PRAGMA table_info(events)")
                    columns = {row[1]: row[2] for row in cursor.fetchall()}
                    
                    required_columns = {
                        "event_id": "TEXT",
                        "stream_id": "TEXT", 
                        "message_json": "TEXT",
                        "timestamp": "DATETIME"
                    }
                    
                    for col_name, col_type in required_columns.items():
                        if col_name not in columns:
                            errors.append(f"Отсутствует столбец: {col_name}")
                
                # Проверка данных
                cursor.execute("SELECT COUNT(*) FROM events WHERE event_id IS NULL OR event_id = ''")
                null_ids = cursor.fetchone()[0]
                if null_ids > 0:
                    errors.append(f"Найдено {null_ids} событий с пустым event_id")
                
                cursor.execute("SELECT COUNT(*) FROM events WHERE stream_id IS NULL OR stream_id = ''")
                null_streams = cursor.fetchone()[0]
                if null_streams > 0:
                    errors.append(f"Найдено {null_streams} событий с пустым stream_id")
                
                # Проверка JSON
                cursor.execute("SELECT event_id, message_json FROM events LIMIT 100")
                invalid_json_count = 0
                for event_id, message_json in cursor.fetchall():
                    try:
                        json.loads(message_json)
                    except json.JSONDecodeError:
                        invalid_json_count += 1
                        if invalid_json_count <= 5:  # Показываем только первые 5
                            errors.append(f"Невалидный JSON в событии {event_id}")
                
                if invalid_json_count > 5:
                    errors.append(f"И еще {invalid_json_count - 5} событий с невалидным JSON")
                
                # Предупреждения
                cursor.execute("SELECT COUNT(*) FROM events")
                total_events = cursor.fetchone()[0]
                if total_events > 100000:
                    warnings.append(f"Большое количество событий ({total_events}), рекомендуется очистка")
                
        except Exception as e:
            errors.append(f"Ошибка при проверке: {str(e)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    def export_events(self, output_path: str, stream_id: Optional[str] = None, 
                     start_date: Optional[str] = None, end_date: Optional[str] = None) -> int:
        """
        Экспортирует события в JSON файл.
        
        Args:
            output_path: Путь к выходному файлу
            stream_id: Фильтр по ID потока (опционально)
            start_date: Начальная дата в формате ISO (опционально)
            end_date: Конечная дата в формате ISO (опционально)
            
        Returns:
            int: Количество экспортированных событий
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"База данных не найдена: {self.db_path}")
        
        # Формируем SQL запрос
        query = "SELECT event_id, stream_id, message_json, timestamp FROM events WHERE 1=1"
        params = []
        
        if stream_id:
            query += " AND stream_id = ?"
            params.append(stream_id)
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
        
        query += " ORDER BY timestamp"
        
        exported_count = 0
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('[\n')
                first = True
                
                for row in cursor.fetchall():
                    if not first:
                        f.write(',\n')
                    first = False
                    
                    event_data = {
                        "event_id": row[0],
                        "stream_id": row[1], 
                        "message": json.loads(row[2]),
                        "timestamp": row[3]
                    }
                    
                    json.dump(event_data, f, ensure_ascii=False, indent=2)
                    exported_count += 1
                
                f.write('\n]')
        
        logger.info(f"Экспортировано {exported_count} событий в {output_path}")
        return exported_count
    
    def import_events(self, input_path: str) -> int:
        """
        Импортирует события из JSON файла.
        
        Args:
            input_path: Путь к файлу для импорта
            
        Returns:
            int: Количество импортированных событий
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Файл для импорта не найден: {input_path}")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            events_data = json.load(f)
        
        imported_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for event_data in events_data:
                try:
                    cursor.execute("""
                        INSERT OR REPLACE INTO events (event_id, stream_id, message_json, timestamp)
                        VALUES (?, ?, ?, ?)
                    """, (
                        event_data["event_id"],
                        event_data["stream_id"],
                        json.dumps(event_data["message"]),
                        event_data["timestamp"]
                    ))
                    imported_count += 1
                except Exception as e:
                    logger.warning(f"Ошибка импорта события {event_data.get('event_id', 'unknown')}: {e}")
            
            conn.commit()
        
        logger.info(f"Импортировано {imported_count} событий из {input_path}")
        return imported_count


async def run_maintenance_tasks(db_path: str, config_dict: Dict) -> Dict:
    """
    Запускает задачи обслуживания Event Store.
    
    Args:
        db_path: Путь к базе данных
        config_dict: Словарь с конфигурацией
        
    Returns:
        Dict: Результаты выполнения задач
    """
    manager = EventStoreManager(db_path)
    results = {}
    
    try:
        # Создание бэкапа
        if config_dict.get("backup_enabled", False):
            backup_path = manager.create_backup()
            results["backup"] = {"success": True, "path": str(backup_path)}
        
        # Очистка старых бэкапов
        cleanup_count = manager.cleanup_old_backups(
            config_dict.get("backup_retention_days", 7)
        )
        results["backup_cleanup"] = {"success": True, "deleted_count": cleanup_count}
        
        # Валидация БД
        validation = manager.validate_database()
        results["validation"] = validation
        
        # Статистика
        stats = manager.get_database_stats()
        results["stats"] = stats
        
    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Ошибка при выполнении задач обслуживания: {e}")
    
    return results


if __name__ == "__main__":
    # Пример использования
    async def example():
        manager = EventStoreManager("InternalStorage/events.db")
        
        # Создаем бэкап
        backup_path = manager.create_backup()
        print(f"Создан бэкап: {backup_path}")
        
        # Получаем статистику
        stats = manager.get_database_stats()
        print(f"Всего событий: {stats.get('total_events', 0)}")
        
        # Проверяем целостность
        validation = manager.validate_database()
        if validation["valid"]:
            print("База данных валидна")
        else:
            print(f"Ошибки валидации: {validation['errors']}")
    
    asyncio.run(example())