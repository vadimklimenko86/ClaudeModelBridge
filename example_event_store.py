"""
Пример использования Event Store с постоянным хранением.
"""

import asyncio
import json
import logging
from datetime import datetime

from event_store import create_event_store, PersistentEventStore
from event_store_config import get_config

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def demo_basic_usage():
    """Демонстрация базового использования Event Store."""
    print("\n=== Демонстрация базового использования ===")
    
    # Создаем конфигурацию для разработки
    config = get_config("development")
    print(f"Используем конфигурацию: persistent={config.persistent}")
    
    # Создаем хранилище событий
    store = create_event_store(
        persistent=config.persistent,
        db_path=config.db_path,
        max_events_per_stream=config.max_events_per_stream,
        retention_days=config.retention_days,
        memory_cache_size=config.memory_cache_size
    )
    
    print(f"Создано хранилище: {type(store).__name__}")
    
    # Создаем тестовые события
    test_messages = [
        {"method": "initialize", "params": {"client": "test_client_1"}},
        {"method": "tools/list", "params": {}},
        {"method": "tools/call", "params": {"name": "calculator", "arguments": {"a": 5, "b": 3}}},
        {"method": "resources/list", "params": {}},
        {"method": "complete", "params": {"session_id": "12345"}}
    ]
    
    stream_id = "demo_stream_001"
    event_ids = []
    
    # Сохраняем события
    print(f"\nСохраняем {len(test_messages)} событий в поток {stream_id}:")
    for i, message in enumerate(test_messages):
        event_id = await store.store_event(stream_id, message)
        event_ids.append(event_id)
        print(f"  {i+1}. Событие {event_id[:8]}... сохранено")
        
        # Небольшая пауза для различения времени
        await asyncio.sleep(0.1)
    
    # Получаем статистику
    stats = store.get_stream_stats()
    print(f"\nСтатистика потоков: {stats}")
    
    return store, stream_id, event_ids


async def demo_replay_functionality(store, stream_id, event_ids):
    """Демонстрация функциональности переигрывания событий."""
    print("\n=== Демонстрация переигрывания событий ===")
    
    # Список для сбора переиграных событий
    replayed_events = []
    
    async def collect_event(event_message):
        """Callback для сбора переиграных событий."""
        replayed_events.append({
            "event_id": event_message.event_id,
            "message": event_message.message
        })
        print(f"  Переиграно событие {event_message.event_id[:8]}...")
    
    # Переигрываем события после второго события
    last_event_id = event_ids[1]  # После второго события
    print(f"Переигрываем события после {last_event_id[:8]}...")
    
    result_stream_id = await store.replay_events_after(last_event_id, collect_event)
    
    if result_stream_id:
        print(f"Успешно переиграно {len(replayed_events)} событий для потока {result_stream_id}")
        for i, event in enumerate(replayed_events):
            print(f"  {i+1}. {event['message'].get('method', 'unknown')}")
    else:
        print("Не удалось переиграть события")


async def demo_persistent_features():
    """Демонстрация возможностей постоянного хранения."""
    print("\n=== Демонстрация постоянного хранения ===")
    
    # Создаем постоянное хранилище
    config = get_config("production")
    config.db_path = "InternalStorage/demo_events.db"  # Отдельная БД для демо
    
    store = PersistentEventStore(
        db_path=config.db_path,
        max_events_per_stream=config.max_events_per_stream,
        retention_days=config.retention_days
    )
    
    print(f"Создано постоянное хранилище: {config.db_path}")
    
    # Добавляем события в несколько потоков
    streams = ["user_session_1", "user_session_2", "admin_session_1"]
    
    for stream_id in streams:
        print(f"\nДобавляем события в поток {stream_id}:")
        for i in range(5):
            message = {
                "method": f"action_{i}",
                "params": {"stream": stream_id, "timestamp": datetime.now().isoformat()},
                "user": stream_id.split('_')[0]
            }
            event_id = await store.store_event(stream_id, message)
            print(f"  Событие {i+1}: {event_id[:8]}...")
    
    # Получаем расширенную информацию о БД
    if hasattr(store, 'get_database_info'):
        db_info = store.get_database_info()
        print(f"\nИнформация о базе данных:")
        print(f"  Размер: {db_info['database_size_mb']} MB")
        print(f"  Всего событий: {db_info['total_events']}")
        print(f"  Потоков: {db_info['total_streams']}")
        print(f"  Кэш в памяти: {db_info['cache_size']} событий")
    
    # Тестируем очистку потока
    print(f"\nОчищаем поток user_session_1...")
    deleted_count = store.clear_stream("user_session_1")
    print(f"Удалено {deleted_count} событий")
    
    final_stats = store.get_stream_stats()
    print(f"Финальная статистика: {final_stats}")


async def demo_backup_and_management():
    """Демонстрация функций резервного копирования и управления."""
    print("\n=== Демонстрация управления и бэкапов ===")
    
    from event_store_migrations import EventStoreManager
    
    db_path = "InternalStorage/demo_events.db"
    manager = EventStoreManager(db_path)
    
    try:
        # Создаем бэкап
        print("Создаем резервную копию...")
        backup_path = manager.create_backup("demo_backup")
        print(f"Бэкап создан: {backup_path}")
        
        # Получаем детальную статистику
        print("\nПолучаем статистику базы данных...")
        stats = manager.get_database_stats()
        
        print(f"Статистика БД:")
        print(f"  Размер: {stats.get('db_size_mb', 0)} MB")
        print(f"  Всего событий: {stats.get('total_events', 0)}")
        print(f"  Активных потоков: {stats.get('total_streams', 0)}")
        
        if stats.get('top_streams'):
            print(f"  Топ потоков:")
            for stream in stats['top_streams'][:3]:
                print(f"    {stream['stream_id']}: {stream['event_count']} событий")
        
        # Проверяем целостность
        print("\nПроверяем целостность базы данных...")
        validation = manager.validate_database()
        
        if validation['valid']:
            print("✅ База данных валидна")
        else:
            print("❌ Обнаружены проблемы:")
            for error in validation['errors']:
                print(f"    - {error}")
        
        if validation.get('warnings'):
            print("⚠️  Предупреждения:")
            for warning in validation['warnings']:
                print(f"    - {warning}")
        
        # Экспортируем события
        print("\nЭкспортируем события...")
        export_path = "InternalStorage/exported_events.json"
        exported_count = manager.export_events(export_path)
        print(f"Экспортировано {exported_count} событий в {export_path}")
        
    except Exception as e:
        print(f"Ошибка при работе с менеджером: {e}")


async def demo_configuration():
    """Демонстрация различных конфигураций."""
    print("\n=== Демонстрация конфигураций ===")
    
    configs = ["development", "testing", "production"]
    
    for config_name in configs:
        config = get_config(config_name)
        print(f"\nКонфигурация '{config_name}':")
        print(f"  Постоянное хранение: {config.persistent}")
        print(f"  База данных: {config.db_path}")
        print(f"  Макс. событий на поток: {config.max_events_per_stream}")
        print(f"  Срок хранения: {config.retention_days} дней")
        print(f"  Размер кэша: {config.memory_cache_size}")
        print(f"  Бэкапы: {'включены' if config.backup_enabled else 'отключены'}")


async def main():
    """Главная функция для запуска всех демонстраций."""
    print("🚀 Демонстрация Event Store с постоянным хранением")
    print("=" * 60)
    
    try:
        # Демонстрация конфигураций
        await demo_configuration()
        
        # Базовое использование
        store, stream_id, event_ids = await demo_basic_usage()
        
        # Переигрывание событий
        await demo_replay_functionality(store, stream_id, event_ids)
        
        # Постоянное хранение
        await demo_persistent_features()
        
        # Управление и бэкапы
        await demo_backup_and_management()
        
        print("\n✅ Демонстрация успешно завершена!")
        
    except Exception as e:
        print(f"\n❌ Ошибка во время демонстрации: {e}")
        logger.exception("Детали ошибки:")


if __name__ == "__main__":
    asyncio.run(main())