from typing import Dict
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
import mcp.types as types

from collections.abc import AsyncIterator, Awaitable, Callable, Iterable


class MCP_Tools:

	def __init__(self, serverapp: Server):
		self.serverapp = serverapp
		self.ToolsDict: Dict[str, types.Tool] = {}
		self.ToolsFuncs: Dict[str, Callable] = {}

	def RegisterTool(
	    self,
	    name: str,
	    description: str = "") -> Callable:  # type: ignore[type-arg]

		def decorator(func: Callable) -> Callable:  # type: ignore[type-arg]
			#self.app.router.mount(path, app=func)
			self.ToolsDict[name] = types.Tool(name=name,
			                                  description=description,
			                                  inputSchema={
			                                      "type": "object",
			                                      "properties": {}
			                                  })
			self.ToolsFuncs[name] = func
			return func

		return decorator
