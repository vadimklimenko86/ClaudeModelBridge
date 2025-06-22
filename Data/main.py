"""
Пример запуска RemoteMCP сервера
"""

import logging
import mcp.types as types
from typing import Annotated
from datetime import datetime
import pytz

from mcp.server.lowlevel import Server
from custom_server import CustomServerWithOauth2
from MCP_Tools import MCP_Tools


# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_mcp_server():
    """Настройка и конфигурация MCP сервера"""
    
    # Создание MCP сервера
    mcp_server = Server("remote-mcp-demo")
    
    # Создание менеджера инструментов
    tools = MCP_Tools(mcp_server)
    
    # Регистрация инструментов
    @tools.register_tool("get_current_time", "Получить текущее время в указанной временной зоне")
    def get_current_time(
        timezone: Annotated[str, "Временная зона (например: UTC, Europe/Moscow, America/New_York)"] = "UTC",
        format: Annotated[str, "Формат времени (например: %Y-%m-%d %H:%M:%S)"] = "%Y-%m-%d %H:%M:%S"
    ) -> str:
        """Возвращает текущее время в указанной временной зоне"""
        try:
            tz = pytz.timezone(timezone)
            current_time = datetime.now(tz)
            return f"Текущее время в {timezone}: {current_time.strftime(format)}"
        except Exception as e:
            return f"Ошибка: {str(e)}"
    
    @tools.register_tool("calculate", "Выполнить математическое вычисление")
    def calculate(
        expression: Annotated[str, "Математическое выражение (например: 2+2, 10*5, sqrt(16))"],
        precision: Annotated[int, "Количество знаков после запятой"] = 2
    ) -> str:
        """Безопасно вычисляет математическое выражение"""
        try:
            # В продакшене использовать безопасный парсер выражений
            import math
            # Добавляем безопасные математические функции
            safe_dict = {
                'abs': abs, 'round': round, 'min': min, 'max': max,
                'sqrt': math.sqrt, 'pow': pow, 'pi': math.pi, 'e': math.e,
                'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
                'log': math.log, 'log10': math.log10
            }
            # Ограничиваем доступные операции
            result = eval(expression, {"__builtins__": {}}, safe_dict)
            return f"{expression} = {round(result, precision)}"
        except Exception as e:
            return f"Ошибка вычисления: {str(e)}"
    
    @tools.register_simple_tool("get_server_info", "Получить информацию о сервере")
    def get_server_info() -> str:
        """Возвращает информацию о MCP сервере"""
        return """
RemoteMCP Server v1.0
- OAuth2/OpenID Connect поддержка
- Streamable HTTP транспорт  
- Поддержка возобновляемых потоков
- Зарегистрировано инструментов: 3
        """.strip()
    
    # Регистрация обработчиков в MCP сервере
    @mcp_server.list_tools()
    async def list_tools() -> list[types.Tool]:
        """Возвращает список доступных инструментов"""
        return tools.get_tools_list()
    
    @mcp_server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Вызывает указанный инструмент"""
        try:
            return tools.execute_tool(name, arguments)
        except KeyError:
            return [types.TextContent(
                type="text",
                text=f"Ошибка: Инструмент '{name}' не найден"
            )]
        except Exception as e:
            return [types.TextContent(
                type="text", 
                text=f"Ошибка выполнения инструмента: {str(e)}"
            )]
    
    logger.info(f"MCP сервер настроен с {len(tools)} инструментами")
    
    return mcp_server


# Создание сервера
mcp_server = setup_mcp_server()
server = CustomServerWithOauth2(logger, mcp_server)

# Точка входа для ASGI
app = server


if __name__ == "__main__":
    import uvicorn
    
    logger.info("Запуск RemoteMCP сервера...")
    logger.info("OAuth2 метаданные: http://localhost:8000/.well-known/oauth-authorization-server")
    logger.info("MCP endpoint: http://localhost:8000/mcp/")
    
    # Запуск сервера
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=True  # Автоперезагрузка при изменениях (только для разработки)
    )
