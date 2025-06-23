"""
Пример использования модульной системы OAuth 2.0

Этот файл показывает, как использовать новую модульную структуру
вместо монолитного oauth2.py файла.
"""

import logging
from oauth2_modules import OAuth2Manager

# Настройка логгера
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_oauth_manager():
    """Создание и настройка OAuth2 менеджера"""
    # Создаем менеджер
    oauth_manager = OAuth2Manager(logger)
    
    # Можно добавить дополнительных клиентов
    # from oauth2_modules import OAuth2Client
    # 
    # custom_client = OAuth2Client(
    #     client_id="custom_client",
    #     client_secret="custom_secret",
    #     redirect_uris=["https://example.com/callback"],
    #     name="Custom Client"
    # )
    # oauth_manager.add_client(custom_client)
    
    return oauth_manager

def get_oauth_routes():
    """Получить маршруты для интеграции с Starlette/FastAPI"""
    oauth_manager = create_oauth_manager()
    return oauth_manager.routes

# Для совместимости с существующим кодом
def get_oauth2_manager(logger):
    """Функция для создания OAuth2Manager (для совместимости)"""
    return OAuth2Manager(logger)

if __name__ == "__main__":
    # Пример использования
    manager = create_oauth_manager()
    
    # Показываем статистику
    stats = manager.get_stats()
    print("OAuth2 Manager Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Показываем количество маршрутов
    print(f"\nRegistered routes: {len(manager.routes)}")
    for route in manager.routes:
        print(f"  {route.path} - {route.methods}")
