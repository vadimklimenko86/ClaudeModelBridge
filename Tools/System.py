from Data.MCP_Tools import MCP_Tools
import mcp.types as types
import datetime

class SystemTools:
	def __init__(self, mcp: MCP_Tools) -> None:
		tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))



		@mcp.register_tool(name="gettime", description="Получить текущее время")
		def gettime()->list[types.TextContent
		| types.ImageContent
		| types.EmbeddedResource]:
			return [
				types.TextContent(
								type="text",
								text=f"Current time: {datetime.datetime.now(tz_plus3).isoformat()}"
						)
			]
		