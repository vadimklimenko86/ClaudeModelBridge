from typing import Dict, Callable, Annotated
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
import mcp.types as types
import asyncio
import contextlib
import logging
import json
from mcp.shared.context import RequestContext
from collections.abc import AsyncIterator, Awaitable, Iterable
import inspect
from typing import Any, get_type_hints
from functools import wraps

from typing import get_origin, get_args, Union, Optional, List
from dataclasses import dataclass, field

from enum import Enum
import re


class MCP_Tools:

	def __init__(self, serverapp: Server):
		self.serverapp = serverapp
		self.ToolsDict: Dict[str, types.Tool] = {}
		self.ToolsFuncs: Dict[str,
		                      Callable[[dict],
		                               list[types.TextContent | types.ImageContent
		                                    | types.EmbeddedResource]]] = {}

	def RegisterTool2(self, name: str, description: str = "") -> Callable:
		"""
		Декоратор, который извлекает параметры функции и их типы,
		сохраняя их в атрибуте функции.
		"""

		def decorator(func: Callable):

			# Получаем сигнатуру функции
			signature = inspect.signature(func)

			# Получаем аннотации типов
			try:
				type_hints = get_type_hints(func)
			except (NameError, AttributeError):
				type_hints = {}

			# Извлекаем информацию о параметрах
			params_info = {}
			for param_name, param in signature.parameters.items():

				param_type = type_hints.get(param_name, param.annotation)
				type = param_type
				descr: str = ""

				if get_origin(param.annotation) is Annotated:
					args = get_args(param.annotation)
					if args:
						type = args[0]  # Основной тип
						descr = ". ".join(args[1:])  # Все метаданные

				if inspect.isclass(type):
					type = param_type.__name__

				if type == 'str':
					type = 'string'

				# Если тип не указан, используем inspect.Parameter.empty
				if param_type == inspect.Parameter.empty:
					param_type = Any

				params_info[param_name] = {
				    'type': type,
				    'description': descr,
				}

			self.ToolsDict[name] = types.Tool(name=name,
			                                  description=description,
			                                  inputSchema={
			                                      "type": "object",
			                                      "properties": params_info
			                                  })

			def wrapper(params: dict):
				if not isinstance(params, dict):
					raise TypeError(
					    f"Параметр для {name} должен быть dict, получен {type(params)}")
				return func(**params)

			self.ToolsFuncs[name] = wrapper
			return wrapper

		return decorator

	def RegisterTool(
	    self,
	    name: str,
	    description: str = ""
	) -> Callable[[
	    Callable[[], list[types.TextContent | types.ImageContent
	                      | types.EmbeddedResource]]
	], Callable[[], list[types.TextContent | types.ImageContent
	                     | types.EmbeddedResource]]]:  # type: ignore[type-arg]

		def decorator(
		    func: Callable[[], list[types.TextContent | types.ImageContent
		                            | types.EmbeddedResource]]
		) -> Callable[[], list[types.TextContent | types.ImageContent | types.
		                       EmbeddedResource]]:  # type: ignore[type-arg]
			#self.app.router.mount(path, app=func)

			self.ToolsDict[name] = types.Tool(name=name,
			                                  description=description,
			                                  inputSchema={
			                                      "type": "object",
			                                      "properties": {}
			                                  })
			self.ToolsFuncs[name] = lambda param: func()
			return func

		return decorator
