# Remote MCP Server

A complete Remote Model Context Protocol (MCP) server implementation using the official Python SDK v1.9.2, designed for seamless integration with Claude.ai.

## Features

- **Official MCP SDK v1.9.2** - Uses the authentic Python SDK without wrappers
- **Full Claude.ai Compatibility** - Implements complete MCP specification
- **Multiple Transports** - Supports stdio and HTTP transports
- **System Monitoring** - Real-time system metrics and information
- **Mathematical Calculator** - Safe expression evaluation with functions
- **Echo Tool** - Message echoing with metadata and timestamps
- **Resource Access** - System metrics and platform information resources

## Quick Start

### For Claude.ai Integration (Recommended)

1. **Add to Claude.ai Configuration**
   
   Add this configuration to your Claude.ai MCP settings:
   ```json
   {
     "mcpServers": {
       "remote-mcp-server": {
         "command": "python",
         "args": ["mcp_claude_server.py"],
         "env": {},
         "description": "Remote MCP Server using Official Python SDK v1.9.2"
       }
     }
   }
   ```

2. **Test the Connection**
   
   In Claude.ai, you can now use these tools:
   - `echo` - Echo messages with timestamps
   - `system_info` - Get comprehensive system information
   - `calculator` - Perform mathematical calculations

### For Web Interface

Run the HTTP server for web-based interaction:

```bash
python main.py
```

Visit `http://localhost:5000` to access the dashboard.

## Available Tools

### Echo Tool
```json
{
  "name": "echo",
  "description": "Echo back any message with timestamp",
  "parameters": {
    "message": "string (required) - Message to echo back"
  }
}
```

### System Information
```json
{
  "name": "system_info", 
  "description": "Get real-time system information and metrics",
  "parameters": {
    "detail_level": "string (optional) - basic, detailed, or full"
  }
}
```

### Calculator
```json
{
  "name": "calculator",
  "description": "Perform mathematical calculations safely", 
  "parameters": {
    "expression": "string (required) - Mathematical expression to evaluate"
  }
}
```

## Available Resources

- `system://metrics/realtime` - Real-time system performance metrics
- `system://info/platform` - Operating system and platform details

## Technical Specifications

- **Protocol Version**: 2024-11-05
- **SDK Version**: 1.9.2
- **Python Version**: 3.11+
- **Transport Methods**: stdio, HTTP
- **Claude.ai Compatible**: Yes

## Dependencies

- `mcp` - Official MCP Python SDK
- `psutil` - System information
- `flask` - Web interface (optional)
- `flask-cors` - CORS support (optional)

## File Structure

```
├── mcp_claude_server.py     # Main MCP server for Claude.ai
├── main.py                  # HTTP server with web interface
├── claude_mcp_config.json   # Claude.ai configuration
└── README.md               # This documentation
```

## API Endpoints (HTTP Mode)

- `GET /` - Web dashboard
- `GET /health` - Health check
- `GET /api/metrics` - System metrics
- `GET /mcp/info` - MCP server information
- `GET /mcp/tools` - Available tools list
- `GET /mcp/resources` - Available resources list
- `POST /mcp/call/{tool_name}` - Call specific tool

## Usage Examples

### Using with Claude.ai

Once configured, you can ask Claude.ai:

- "Can you echo 'Hello World' for me?"
- "What's the current system information?"
- "Calculate the square root of 144"
- "Show me real-time system metrics"

### Direct HTTP API Usage

```bash
# Get system information
curl -X POST http://localhost:5000/mcp/call/system_info \
  -H "Content-Type: application/json" \
  -d '{"detail_level": "detailed"}'

# Use calculator
curl -X POST http://localhost:5000/mcp/call/calculator \
  -H "Content-Type: application/json" \
  -d '{"expression": "2 + 3 * 4"}'

# Echo message
curl -X POST http://localhost:5000/mcp/call/echo \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from MCP!"}'
```

## Security Features

- Safe mathematical expression evaluation
- No arbitrary code execution
- Limited system access
- Input validation and sanitization

## Troubleshooting

### Claude.ai Connection Issues

1. Ensure Python is in your system PATH
2. Verify the configuration file path is correct
3. Check that all dependencies are installed
4. Confirm the server script is executable

### HTTP Server Issues

1. Check if port 5000 is available
2. Verify Flask and dependencies are installed
3. Check system permissions for psutil access

## Protocol Compliance

This implementation follows the official MCP specification:
- Proper JSON-RPC 2.0 message formatting
- Complete capability negotiation
- Standard initialization handshake
- Error handling and status codes
- Resource subscription support

## Contributing

This server is built using the official MCP Python SDK without modifications. For protocol updates, refer to the official MCP specification and SDK documentation.

## License

This implementation follows the same license terms as the official MCP Python SDK.