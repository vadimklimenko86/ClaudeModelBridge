"""
Тесты для MCP_Tools
"""

import pytest
from typing import Annotated, Optional, List
import mcp.types as types
from mcp.server.lowlevel import Server
from MCP_Tools import MCP_Tools


@pytest.fixture
def mcp_server():
    """Создание MCP сервера для тестов"""
    return Server("test-server")


@pytest.fixture
def tools_manager(mcp_server):
    """Создание менеджера инструментов"""
    return MCP_Tools(mcp_server)


class TestToolRegistration:
    """Тесты регистрации инструментов"""
    
    def test_simple_tool_registration(self, tools_manager):
        """Тест регистрации простого инструмента"""
        @tools_manager.register_simple_tool("test_tool", "Test description")
        def test_tool():
            return "Test result"
        
        assert "test_tool" in tools_manager
        assert len(tools_manager) == 1
        
        tool = tools_manager.tools_registry["test_tool"]
        assert tool.name == "test_tool"
        assert tool.description == "Test description"
        assert tool.inputSchema["type"] == "object"
        assert tool.inputSchema["properties"] == {}
        
    def test_tool_with_parameters(self, tools_manager):
        """Тест регистрации инструмента с параметрами"""
        @tools_manager.register_tool("calc", "Calculator tool")
        def calculate(
            x: int,
            y: int,
            operation: str = "add"
        ):
            if operation == "add":
                return f"{x} + {y} = {x + y}"
            elif operation == "multiply":
                return f"{x} * {y} = {x * y}"
            return "Unknown operation"
        
        tool = tools_manager.tools_registry["calc"]
        schema = tool.inputSchema
        
        assert "x" in schema["properties"]
        assert "y" in schema["properties"]
        assert "operation" in schema["properties"]
        
        assert schema["properties"]["x"]["type"] == "integer"
        assert schema["properties"]["y"]["type"] == "integer"
        assert schema["properties"]["operation"]["type"] == "string"
        
        # x и y обязательные, operation - нет
        assert set(schema["required"]) == {"x", "y"}
        
    def test_tool_with_annotated_params(self, tools_manager):
        """Тест регистрации инструмента с Annotated параметрами"""
        @tools_manager.register_tool("weather", "Get weather info")
        def get_weather(
            city: Annotated[str, "City name"],
            units: Annotated[str, "Temperature units (C/F)"] = "C",
            detailed: Annotated[bool, "Include detailed forecast"] = False
        ):
            return f"Weather in {city}: 20°{units}"
        
        tool = tools_manager.tools_registry["weather"]
        schema = tool.inputSchema
        
        assert schema["properties"]["city"]["description"] == "City name"
        assert schema["properties"]["units"]["description"] == "Temperature units (C/F)"
        assert schema["properties"]["detailed"]["type"] == "boolean"
        
        assert schema["required"] == ["city"]
        
    def test_tool_with_optional_params(self, tools_manager):
        """Тест регистрации инструмента с Optional параметрами"""
        @tools_manager.register_tool("search", "Search tool")
        def search(
            query: str,
            limit: Optional[int] = None,
            tags: Optional[List[str]] = None
        ):
            return f"Searching for: {query}"
        
        tool = tools_manager.tools_registry["search"]
        schema = tool.inputSchema
        
        assert schema["properties"]["query"]["type"] == "string"
        assert "limit" in schema["properties"]
        assert "tags" in schema["properties"]
        
        # Только query обязательный
        assert schema["required"] == ["query"]


class TestToolExecution:
    """Тесты выполнения инструментов"""
    
    def test_simple_tool_execution(self, tools_manager):
        """Тест выполнения простого инструмента"""
        @tools_manager.register_simple_tool("hello", "Say hello")
        def hello():
            return "Hello, World!"
        
        result = tools_manager.execute_tool("hello", {})
        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert result[0].text == "Hello, World!"
        
    def test_tool_with_params_execution(self, tools_manager):
        """Тест выполнения инструмента с параметрами"""
        @tools_manager.register_tool("greet", "Greet someone")
        def greet(name: str, formal: bool = False):
            if formal:
                return f"Good day, {name}!"
            return f"Hi, {name}!"
        
        # Обычное приветствие
        result = tools_manager.execute_tool("greet", {"name": "Alice"})
        assert result[0].text == "Hi, Alice!"
        
        # Формальное приветствие
        result = tools_manager.execute_tool("greet", {"name": "Alice", "formal": True})
        assert result[0].text == "Good day, Alice!"
        
    def test_tool_missing_required_param(self, tools_manager):
        """Тест выполнения инструмента без обязательного параметра"""
        @tools_manager.register_tool("test", "Test tool")
        def test(required_param: str):
            return required_param
        
        with pytest.raises(ValueError) as exc_info:
            tools_manager.execute_tool("test", {})
        
        assert "required_param" in str(exc_info.value)
        
    def test_tool_not_found(self, tools_manager):
        """Тест выполнения несуществующего инструмента"""
        with pytest.raises(KeyError) as exc_info:
            tools_manager.execute_tool("nonexistent", {})
        
        assert "nonexistent" in str(exc_info.value)
        
    def test_tool_extra_params_ignored(self, tools_manager):
        """Тест игнорирования лишних параметров"""
        @tools_manager.register_tool("echo", "Echo tool")
        def echo(message: str):
            return message
        
        # Лишние параметры должны игнорироваться
        result = tools_manager.execute_tool("echo", {
            "message": "Hello",
            "extra_param": "ignored"
        })
        assert result[0].text == "Hello"


class TestTypeConversion:
    """Тесты конвертации типов"""
    
    def test_basic_type_conversion(self, tools_manager):
        """Тест конвертации базовых типов"""
        conversions = {
            str: {"type": "string"},
            int: {"type": "integer"},
            float: {"type": "number"},
            bool: {"type": "boolean"},
            dict: {"type": "object"},
            list: {"type": "array"}
        }
        
        for python_type, expected_schema in conversions.items():
            schema = tools_manager._python_type_to_json_schema(python_type)
            assert schema == expected_schema
            
    def test_list_type_conversion(self, tools_manager):
        """Тест конвертации List типов"""
        schema = tools_manager._python_type_to_json_schema(List[str])
        assert schema["type"] == "array"
        assert schema["items"]["type"] == "string"
        
        schema = tools_manager._python_type_to_json_schema(List[int])
        assert schema["type"] == "array"
        assert schema["items"]["type"] == "integer"
        
    def test_optional_type_conversion(self, tools_manager):
        """Тест конвертации Optional типов"""
        schema = tools_manager._python_type_to_json_schema(Optional[str])
        assert schema["type"] == "string"
        
        schema = tools_manager._python_type_to_json_schema(Optional[int])
        assert schema["type"] == "integer"


class TestToolsList:
    """Тесты получения списка инструментов"""
    
    def test_get_tools_list(self, tools_manager):
        """Тест получения списка инструментов"""
        # Регистрируем несколько инструментов
        @tools_manager.register_simple_tool("tool1", "First tool")
        def tool1():
            return "Result 1"
        
        @tools_manager.register_tool("tool2", "Second tool")
        def tool2(param: str):
            return f"Result: {param}"
        
        tools_list = tools_manager.get_tools_list()
        assert len(tools_list) == 2
        
        tool_names = [tool.name for tool in tools_list]
        assert "tool1" in tool_names
        assert "tool2" in tool_names
