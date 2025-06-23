"""
Модуль для регистрации и управления MCP инструментами (tools).
"""

import inspect
import logging
from typing import (
    Dict, Callable, Annotated, Any, Union, Optional, List,
    get_type_hints, get_origin, get_args
)
from functools import wraps

import mcp.types as types
from mcp.server.lowlevel import Server

logger = logging.getLogger(__name__)


class MCP_Tools:
	"""Класс для управления MCP инструментами"""

	def __init__(self, serverapp: Server):
		"""
		Инициализация менеджера инструментов.
		
		Args:
			serverapp: Экземпляр MCP сервера
		"""
		self.serverapp = serverapp
		self.tools_registry: Dict[str, types.Tool] = {}
		self.tools_handlers: Dict[str, Callable] = {}
		
		logger.info("MCP_Tools manager initialized")

	def _python_type_to_json_schema(self, python_type: Any) -> Dict[str, Any]:
		"""
		Конвертация Python типа в JSON Schema тип.
		
		Args:
			python_type: Python тип для конвертации
			
		Returns:
			JSON Schema описание типа
		"""
		# Обработка Union типов (включая Optional)
		origin = get_origin(python_type)
		if origin is Union:
			args = get_args(python_type)
			# Проверка на Optional (Union[X, None])
			if len(args) == 2 and type(None) in args:
				non_none_type = args[0] if args[1] is type(None) else args[1]
				schema = self._python_type_to_json_schema(non_none_type)
				# Для необязательных параметров не добавляем их в required
				return schema
			else:
				# Обычный Union
				return {
					"oneOf": [self._python_type_to_json_schema(arg) for arg in args]
				}
		
		# Обработка List типов
		if origin is list or origin is List:
			args = get_args(python_type)
			item_type = args[0] if args else Any
			return {
				"type": "array",
				"items": self._python_type_to_json_schema(item_type)
			}
		
		# Базовые типы
		type_mapping = {
			str: {"type": "string"},
			int: {"type": "integer"},
			float: {"type": "number"},
			bool: {"type": "boolean"},
			dict: {"type": "object"},
			list: {"type": "array"},
			type(None): {"type": "null"},
			Any: {}  # Любой тип
		}
		
		# Проверяем прямое соответствие
		if python_type in type_mapping:
			return type_mapping[python_type]
		
		# Для классов используем имя класса как строку
		if inspect.isclass(python_type):
			if python_type.__name__ in ['str', 'string']:
				return {"type": "string"}
			elif python_type.__name__ in ['int', 'integer']:
				return {"type": "integer"}
			elif python_type.__name__ in ['float', 'number']:
				return {"type": "number"}
			elif python_type.__name__ in ['bool', 'boolean']:
				return {"type": "boolean"}
			elif python_type.__name__ in ['dict', 'object']:
				return {"type": "object"}
			elif python_type.__name__ in ['list', 'array']:
				return {"type": "array"}
		
		# По умолчанию возвращаем строку
		return {"type": "string"}

	def register_tool(self, name: str, description: str = "") -> Callable:
		"""
		Декоратор для регистрации MCP инструмента.
		Автоматически извлекает параметры функции и их типы для создания JSON Schema.
		
		Args:
			name: Имя инструмента
			description: Описание инструмента
			
		Returns:
			Декоратор функции
		"""
		def decorator(func: Callable) -> Callable:
			# Получаем сигнатуру функции
			signature = inspect.signature(func)
			
			# Получаем аннотации типов
			try:
				type_hints = get_type_hints(func, include_extras=True)
			except (NameError, AttributeError):
				type_hints = {}
			
			# Создаем JSON Schema для параметров
			properties = {}
			required = []
			
			for param_name, param in signature.parameters.items():
				# Пропускаем self, cls и подобные
				if param_name in ['self', 'cls']:
					continue
				
				# Получаем тип параметра
				param_type = type_hints.get(param_name, param.annotation)
				param_description = ""
				
				# Обработка Annotated типов для извлечения описания
				if get_origin(param_type) is Annotated:
					args = get_args(param_type)
					if args:
						param_type = args[0]  # Основной тип
						# Объединяем все строковые метаданные как описание
						metadata_strings = [str(arg) for arg in args[1:] if isinstance(arg, str)]
						param_description = ". ".join(metadata_strings)
				
				# Если тип не указан, используем Any
				if param_type == inspect.Parameter.empty:
					param_type = Any
				
				# Конвертируем тип в JSON Schema
				schema = self._python_type_to_json_schema(param_type)
				if param_description:
					schema["description"] = param_description
				
				properties[param_name] = schema
				
				# Добавляем в required, если параметр обязательный
				if param.default == inspect.Parameter.empty:
					# Проверяем, что это не Optional тип
					if get_origin(param_type) is not Union or type(None) not in get_args(param_type):
						required.append(param_name)
			
			# Создаем Tool объект
			input_schema = {
				"type": "object",
				"properties": properties
			}
			
			if required:
				input_schema["required"] = required
			
			tool = types.Tool(
				name=name,
				description=description or func.__doc__ or f"Tool {name}",
				inputSchema=input_schema
			)
			
			# Регистрируем инструмент
			self.tools_registry[name] = tool
			
			# Создаем обертку для обработки параметров
			@wraps(func)
			def wrapper(params: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
				if not isinstance(params, dict):
					raise TypeError(f"Parameters for {name} must be dict, got {type(params)}")
				
				# Валидация обязательных параметров
				for req_param in required:
					if req_param not in params:
						raise ValueError(f"Required parameter '{req_param}' missing for tool '{name}'")
				
				# Фильтруем только те параметры, которые ожидает функция
				sig_params = set(signature.parameters.keys()) - {'self', 'cls'}
				filtered_params = {k: v for k, v in params.items() if k in sig_params}
				
				# Вызываем оригинальную функцию
				result = func(**filtered_params)
				
				# Преобразуем результат в список, если необходимо
				if not isinstance(result, list):
					if isinstance(result, (types.TextContent, types.ImageContent, types.EmbeddedResource)):
						result = [result]
					elif isinstance(result, str):
						result = [types.TextContent(type="text", text=str(result))]
					else:
						result = [types.TextContent(type="text", text=str(result))]
				
				return result
			
			self.tools_handlers[name] = wrapper
			
			#logger.info(f"Registered tool '{name}' with schema: {input_schema}")
			
			return wrapper
		
		return decorator

	def register_simple_tool(self, name: str, description: str = "") -> Callable:
		"""
		Упрощенный декоратор для регистрации инструмента без параметров.
		
		Args:
			name: Имя инструмента
			description: Описание инструмента
			
		Returns:
			Декоратор функции
		"""
		def decorator(func: Callable) -> Callable:
			# Создаем Tool объект без параметров
			tool = types.Tool(
				name=name,
				description=description or func.__doc__ or f"Tool {name}",
				inputSchema={
					"type": "object",
					"properties": {}
				}
			)
			
			# Регистрируем инструмент
			self.tools_registry[name] = tool
			
			# Создаем обертку
			@wraps(func)
			def wrapper(params: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
				# Игнорируем параметры для простых инструментов
				result = func()
				
				# Преобразуем результат
				if not isinstance(result, list):
					if isinstance(result, (types.TextContent, types.ImageContent, types.EmbeddedResource)):
						result = [result]
					elif isinstance(result, str):
						result = [types.TextContent(type="text", text=str(result))]
					else:
						result = [types.TextContent(type="text", text=str(result))]
				
				return result
			
			self.tools_handlers[name] = wrapper
			
			#logger.info(f"Registered simple tool '{name}'")
			
			return wrapper
		
		return decorator

	def get_tools_list(self) -> List[types.Tool]:
		"""
		Получить список всех зарегистрированных инструментов.
		
		Returns:
			Список Tool объектов
		"""
		return list(self.tools_registry.values())

	def execute_tool(self, name: str, params: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
		"""
		Выполнить инструмент по имени.
		
		Args:
			name: Имя инструмента
			params: Параметры для инструмента
			
		Returns:
			Результат выполнения инструмента
			
		Raises:
			KeyError: Если инструмент не найден
			TypeError: Если параметры неверного типа
			ValueError: Если отсутствуют обязательные параметры
		"""
		if name not in self.tools_handlers:
			raise KeyError(f"Tool '{name}' not found")
		
		return self.tools_handlers[name](params)

	def __contains__(self, name: str) -> bool:
		"""Проверить, зарегистрирован ли инструмент"""
		return name in self.tools_registry

	def __len__(self) -> int:
		"""Получить количество зарегистрированных инструментов"""
		return len(self.tools_registry)
