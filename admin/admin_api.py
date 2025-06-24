"""
API модуль для админ-панели RemoteMCP
"""

import os
import psutil
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import logging
from pathlib import Path
import sqlite3
import aiofiles
import glob

logger = logging.getLogger(__name__)

@dataclass
class SystemStats:
    """Статистика системы"""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    uptime: str
    active_tools: int
    total_requests: int
    error_rate: float
    last_updated: datetime

@dataclass
class ToolInfo:
    """Информация об инструменте"""
    name: str
    description: str
    module: str
    enabled: bool
    usage_count: int
    last_used: Optional[datetime]
    error_count: int
    avg_response_time: float

@dataclass
class LogEntry:
    """Запись лога"""
    timestamp: datetime
    level: str
    message: str
    source: str
    details: Optional[Dict[str, Any]] = None

@dataclass
class UserSession:
    """Информация о сессии пользователя"""
    session_id: str
    username: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    requests_count: int

class AdminAPI:
    """API класс для админ-панели"""
    
    def __init__(self, mcp_tools=None, event_store=None):
        self.mcp_tools = mcp_tools
        self.event_store = event_store
        self.stats_cache = {}
        self.cache_ttl = 30  # секунд
        
        # Инициализируем базу статистики
        self._init_stats_db()
    
    def _init_stats_db(self):
        """Инициализирует базу данных для статистики"""
        try:
            # Создаем директорию для данных
            os.makedirs("Data", exist_ok=True)
            
            # Подключаемся к базе статистики
            self.stats_db_path = "Data/admin_stats.db"
            
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                # Таблица для статистики инструментов
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS tool_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tool_name TEXT NOT NULL,
                        usage_count INTEGER DEFAULT 0,
                        error_count INTEGER DEFAULT 0,
                        total_response_time REAL DEFAULT 0,
                        last_used TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Таблица для системных метрик
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        cpu_usage REAL,
                        memory_usage REAL,
                        disk_usage REAL,
                        active_connections INTEGER,
                        request_rate REAL
                    )
                """)
                
                # Таблица для логов ошибок
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS error_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        level TEXT,
                        source TEXT,
                        message TEXT,
                        details TEXT
                    )
                """)
                
                conn.commit()
                
            logger.info("База данных статистики инициализирована")
            
        except Exception as e:
            logger.error(f"Ошибка инициализации базы статистики: {e}")
    
    async def get_system_stats(self) -> Dict[str, Any]:
        """Получает статистику системы"""
        try:
            # Проверяем кеш
            cache_key = "system_stats"
            if (cache_key in self.stats_cache and 
                datetime.now() - self.stats_cache[cache_key]["timestamp"] < timedelta(seconds=self.cache_ttl)):
                return self.stats_cache[cache_key]["data"]
            
            # Получаем системные метрики
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Время работы процесса
            process = psutil.Process()
            uptime_seconds = datetime.now().timestamp() - process.create_time()
            uptime = str(timedelta(seconds=int(uptime_seconds)))
            
            # Статистика инструментов
            tools_stats = await self._get_tools_stats_from_db()
            
            # Статистика запросов
            request_stats = await self._get_request_stats()
            
            stats = {
                "cpu_usage": round(cpu_percent, 1),
                "memory_usage": round(memory.percent, 1),
                "memory_total": round(memory.total / (1024**3), 1),  # GB
                "memory_used": round(memory.used / (1024**3), 1),   # GB
                "disk_usage": round((disk.used / disk.total) * 100, 1),
                "disk_total": round(disk.total / (1024**3), 1),     # GB
                "disk_free": round(disk.free / (1024**3), 1),       # GB
                "uptime": uptime,
                "active_tools": tools_stats.get("active_count", 0),
                "total_tools": tools_stats.get("total_count", 0),
                "total_requests": request_stats.get("total", 0),
                "successful_requests": request_stats.get("successful", 0),
                "error_rate": round(request_stats.get("error_rate", 0), 2),
                "avg_response_time": round(request_stats.get("avg_response_time", 0), 3),
                "last_updated": datetime.now()
            }
            
            # Сохраняем в кеш
            self.stats_cache[cache_key] = {
                "data": stats,
                "timestamp": datetime.now()
            }
            
            # Сохраняем метрики в базу
            await self._save_system_metrics(stats)
            
            return stats
            
        except Exception as e:
            logger.error(f"Ошибка получения статистики системы: {e}")
            return {
                "cpu_usage": 0,
                "memory_usage": 0,
                "disk_usage": 0,
                "uptime": "Unknown",
                "active_tools": 0,
                "total_requests": 0,
                "error_rate": 0,
                "last_updated": datetime.now()
            }
    
    async def _get_tools_stats_from_db(self) -> Dict[str, int]:
        """Получает статистику инструментов из базы"""
        try:
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                # Общее количество инструментов
                if self.mcp_tools:
                    total_count = len(self.mcp_tools.get_registered_tools())
                else:
                    total_count = 0
                
                # Активные инструменты (использованные за последние 24 часа)
                cursor.execute("""
                    SELECT COUNT(DISTINCT tool_name) 
                    FROM tool_stats 
                    WHERE last_used > datetime('now', '-24 hours')
                """)
                active_count = cursor.fetchone()[0] or 0
                
                return {
                    "total_count": total_count,
                    "active_count": active_count
                }
                
        except Exception as e:
            logger.error(f"Ошибка получения статистики инструментов: {e}")
            return {"total_count": 0, "active_count": 0}
    
    async def _get_request_stats(self) -> Dict[str, Any]:
        """Получает статистику запросов"""
        try:
            # Здесь можно интегрироваться с event_store или логами
            # Пока возвращаем заглушку
            return {
                "total": 1000,
                "successful": 950,
                "errors": 50,
                "error_rate": 5.0,
                "avg_response_time": 0.234
            }
            
        except Exception as e:
            logger.error(f"Ошибка получения статистики запросов: {e}")
            return {
                "total": 0,
                "successful": 0,
                "errors": 0,
                "error_rate": 0.0,
                "avg_response_time": 0.0
            }
    
    async def _save_system_metrics(self, stats: Dict[str, Any]):
        """Сохраняет системные метрики в базу"""
        try:
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO system_metrics 
                    (cpu_usage, memory_usage, disk_usage, active_connections, request_rate)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    stats["cpu_usage"],
                    stats["memory_usage"], 
                    stats["disk_usage"],
                    0,  # active_connections - можно добавить позже
                    0   # request_rate - можно добавить позже
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Ошибка сохранения метрик: {e}")
    
    async def get_tools_list(self) -> List[Dict[str, Any]]:
        """Получает список всех инструментов"""
        try:
            tools = []
            
            if self.mcp_tools:
                registered_tools = self.mcp_tools.get_registered_tools()
                
                for tool_name, tool_info in registered_tools.items():
                    # Получаем статистику из базы
                    stats = await self._get_tool_stats(tool_name)
                    
                    tools.append({
                        "name": tool_name,
                        "description": tool_info.get("description", ""),
                        "module": tool_info.get("module", "Unknown"),
                        "enabled": True,  # Все зарегистрированные инструменты активны
                        "usage_count": stats.get("usage_count", 0),
                        "error_count": stats.get("error_count", 0),
                        "last_used": stats.get("last_used"),
                        "avg_response_time": stats.get("avg_response_time", 0)
                    })
            
            return tools
            
        except Exception as e:
            logger.error(f"Ошибка получения списка инструментов: {e}")
            return []
    
    async def _get_tool_stats(self, tool_name: str) -> Dict[str, Any]:
        """Получает статистику конкретного инструмента"""
        try:
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT usage_count, error_count, total_response_time, last_used
                    FROM tool_stats 
                    WHERE tool_name = ?
                """, (tool_name,))
                
                result = cursor.fetchone()
                
                if result:
                    usage_count, error_count, total_response_time, last_used = result
                    avg_response_time = total_response_time / usage_count if usage_count > 0 else 0
                    
                    return {
                        "usage_count": usage_count,
                        "error_count": error_count,
                        "avg_response_time": round(avg_response_time, 3),
                        "last_used": datetime.fromisoformat(last_used) if last_used else None
                    }
                else:
                    return {
                        "usage_count": 0,
                        "error_count": 0,
                        "avg_response_time": 0,
                        "last_used": None
                    }
                    
        except Exception as e:
            logger.error(f"Ошибка получения статистики инструмента {tool_name}: {e}")
            return {
                "usage_count": 0,
                "error_count": 0,
                "avg_response_time": 0,
                "last_used": None
            }
    
    async def get_tools_usage_stats(self) -> Dict[str, Any]:
        """Получает общую статистику использования инструментов"""
        try:
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                # Топ используемых инструментов
                cursor.execute("""
                    SELECT tool_name, usage_count 
                    FROM tool_stats 
                    ORDER BY usage_count DESC 
                    LIMIT 10
                """)
                top_tools = [{"name": row[0], "count": row[1]} for row in cursor.fetchall()]
                
                # Инструменты с ошибками
                cursor.execute("""
                    SELECT tool_name, error_count, usage_count
                    FROM tool_stats 
                    WHERE error_count > 0
                    ORDER BY error_count DESC 
                    LIMIT 10
                """)
                error_tools = [
                    {
                        "name": row[0], 
                        "errors": row[1], 
                        "total": row[2],
                        "error_rate": round((row[1] / row[2]) * 100, 1) if row[2] > 0 else 0
                    } 
                    for row in cursor.fetchall()
                ]
                
                return {
                    "top_used": top_tools,
                    "with_errors": error_tools
                }
                
        except Exception as e:
            logger.error(f"Ошибка получения статистики использования: {e}")
            return {"top_used": [], "with_errors": []}
    
    async def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Получает последние события системы"""
        try:
            events = []
            
            # Получаем из event_store если доступен
            if self.event_store:
                # Здесь нужно интегрироваться с вашим event_store
                pass
            
            # Получаем из логов базы данных
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT timestamp, level, source, message, details
                    FROM error_logs 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                for row in cursor.fetchall():
                    events.append({
                        "timestamp": datetime.fromisoformat(row[0]),
                        "level": row[1],
                        "source": row[2],
                        "message": row[3],
                        "details": json.loads(row[4]) if row[4] else None
                    })
            
            return events
            
        except Exception as e:
            logger.error(f"Ошибка получения событий: {e}")
            return []
    
    async def get_user_stats(self) -> Dict[str, Any]:
        """Получает статистику пользователей"""
        try:
            # Заглушка для статистики пользователей
            # Здесь можно интегрироваться с OAuth2 модулем
            return {
                "total_users": 150,
                "active_today": 45,
                "active_this_week": 89,
                "new_this_month": 12,
                "top_users": [
                    {"username": "user1", "requests": 234},
                    {"username": "user2", "requests": 189},
                    {"username": "user3", "requests": 156}
                ]
            }
            
        except Exception as e:
            logger.error(f"Ошибка получения статистики пользователей: {e}")
            return {
                "total_users": 0,
                "active_today": 0,
                "active_this_week": 0,
                "new_this_month": 0,
                "top_users": []
            }
    
    async def get_logs(self, level: str = "all", limit: int = 100, search: str = "") -> List[Dict[str, Any]]:
        """Получает логи системы"""
        try:
            logs = []
            
            # Читаем логи из файлов
            log_files = glob.glob("*.log") + glob.glob("logs/*.log")
            
            for log_file in log_files[-5:]:  # Последние 5 файлов
                try:
                    async with aiofiles.open(log_file, 'r', encoding='utf-8') as f:
                        lines = await f.readlines()
                        
                        for line in reversed(lines[-limit:]):
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Простой парсинг лога
                            parts = line.split(' ', 3)
                            if len(parts) >= 4:
                                timestamp_str = f"{parts[0]} {parts[1]}"
                                log_level = parts[2]
                                message = parts[3]
                                
                                # Фильтрация по уровню
                                if level != "all" and log_level.lower() != level.lower():
                                    continue
                                
                                # Поиск
                                if search and search.lower() not in message.lower():
                                    continue
                                
                                try:
                                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
                                except:
                                    timestamp = datetime.now()
                                
                                logs.append({
                                    "timestamp": timestamp,
                                    "level": log_level,
                                    "message": message,
                                    "source": os.path.basename(log_file)
                                })
                                
                except Exception as e:
                    logger.error(f"Ошибка чтения файла лога {log_file}: {e}")
            
            # Сортируем по времени (новые сначала)
            logs.sort(key=lambda x: x["timestamp"], reverse=True)
            
            return logs[:limit]
            
        except Exception as e:
            logger.error(f"Ошибка получения логов: {e}")
            return []
    
    async def get_settings(self) -> Dict[str, Any]:
        """Получает настройки системы"""
        try:
            # Читаем настройки из config.py
            settings = {
                "system": {
                    "debug_mode": False,
                    "log_level": "INFO",
                    "max_requests_per_minute": 60,
                    "session_timeout": 8  # часов
                },
                "security": {
                    "csrf_protection": True,
                    "rate_limiting": True,
                    "secure_headers": True,
                    "login_attempts_limit": 5
                },
                "monitoring": {
                    "stats_retention_days": 30,
                    "metrics_collection": True,
                    "performance_logging": True
                }
            }
            
            return settings
            
        except Exception as e:
            logger.error(f"Ошибка получения настроек: {e}")
            return {}
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Получает текущие метрики системы для мониторинга"""
        try:
            # Получаем процессы
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if proc.info['cpu_percent'] > 1.0:  # Только активные процессы
                        processes.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cpu": round(proc.info['cpu_percent'], 1),
                            "memory": round(proc.info['memory_percent'], 1)
                        })
                except:
                    continue
            
            # Сортируем по использованию CPU
            processes.sort(key=lambda x: x['cpu'], reverse=True)
            
            # Сетевые соединения
            try:
                connections = len(psutil.net_connections())
            except:
                connections = 0
            
            return {
                "processes": processes[:20],  # Топ 20 процессов
                "network_connections": connections,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0],
                "boot_time": datetime.fromtimestamp(psutil.boot_time())
            }
            
        except Exception as e:
            logger.error(f"Ошибка получения метрик: {e}")
            return {
                "processes": [],
                "network_connections": 0,
                "load_average": [0, 0, 0],
                "boot_time": datetime.now()
            }
    
    async def get_performance_history(self, hours: int = 24) -> Dict[str, List]:
        """Получает историю производительности"""
        try:
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT timestamp, cpu_usage, memory_usage, disk_usage
                    FROM system_metrics 
                    WHERE timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp
                """.format(hours))
                
                timestamps = []
                cpu_data = []
                memory_data = []
                disk_data = []
                
                for row in cursor.fetchall():
                    timestamps.append(row[0])
                    cpu_data.append(row[1])
                    memory_data.append(row[2])
                    disk_data.append(row[3])
                
                return {
                    "timestamps": timestamps,
                    "cpu": cpu_data,
                    "memory": memory_data,
                    "disk": disk_data
                }
                
        except Exception as e:
            logger.error(f"Ошибка получения истории производительности: {e}")
            return {
                "timestamps": [],
                "cpu": [],
                "memory": [],
                "disk": []
            }
    
    def record_tool_usage(self, tool_name: str, response_time: float, success: bool = True):
        """Записывает использование инструмента"""
        try:
            with sqlite3.connect(self.stats_db_path) as conn:
                cursor = conn.cursor()
                
                # Проверяем, есть ли запись
                cursor.execute("SELECT id, usage_count, error_count, total_response_time FROM tool_stats WHERE tool_name = ?", (tool_name,))
                result = cursor.fetchone()
                
                if result:
                    # Обновляем существующую запись
                    record_id, usage_count, error_count, total_response_time = result
                    
                    new_usage_count = usage_count + 1
                    new_error_count = error_count + (0 if success else 1)
                    new_total_response_time = total_response_time + response_time
                    
                    cursor.execute("""
                        UPDATE tool_stats 
                        SET usage_count = ?, error_count = ?, total_response_time = ?, 
                            last_used = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (new_usage_count, new_error_count, new_total_response_time, record_id))
                else:
                    # Создаем новую запись
                    cursor.execute("""
                        INSERT INTO tool_stats (tool_name, usage_count, error_count, total_response_time, last_used)
                        VALUES (?, 1, ?, ?, CURRENT_TIMESTAMP)
                    """, (tool_name, 0 if success else 1, response_time))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Ошибка записи статистики инструмента {tool_name}: {e}")
