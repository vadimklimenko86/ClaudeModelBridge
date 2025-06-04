# MCP Server for Claude.ai with Official Python SDK

This server implements the Model Context Protocol (MCP) using the official Python SDK v1.9.2 for seamless Claude.ai integration.

## Features

- **Echo Tool**: Echoes back input messages with official SDK validation
- **System Info**: Comprehensive system information using psutil
- **Calculator**: Safe mathematical expression evaluation with AST parsing

## Technical Implementation

### Official SDK Integration
- Uses **mcp** package v1.9.2 from https://github.com/modelcontextprotocol/python-sdk
- Implements proper tool definitions with official MCP types
- Full compliance with MCP protocol version 2024-11-05

### Claude.ai Connection

#### Server URL
```
https://21d397d0-82f3-4fc2-893c-55bb08214050-00-1490hbmwtwihm.riker.replit.dev/mcp/
```

#### Protocol Details
- **Version**: 2024-11-05 (Latest)
- **Transport**: HTTP JSON-RPC 2.0
- **SDK Version**: 1.9.2
- **Methods**: initialize, tools/list, tools/call

### Configuration File
```json
{
  "mcpServers": {
    "flask-mcp-server": {
      "command": "python",
      "args": ["-c", "import requests; import json; import sys; r = requests.post('https://21d397d0-82f3-4fc2-893c-55bb08214050-00-1490hbmwtwihm.riker.replit.dev/mcp/', json=json.loads(sys.stdin.read())); print(r.text)"],
      "env": {
        "MCP_SERVER_URL": "https://21d397d0-82f3-4fc2-893c-55bb08214050-00-1490hbmwtwihm.riker.replit.dev/mcp/"
      }
    }
  }
}
```

### Sample Requests

#### Initialize Connection
```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}}
  },
  "id": 1
}
```

#### List Available Tools
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}
```

#### Execute Tool
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "calculator",
    "arguments": {"expression": "2 + 3 * 4"}
  },
  "id": 3
}
```

## Status

✅ Official MCP Python SDK v1.9.2 integrated  
✅ Protocol version 2024-11-05 implemented  
✅ All tools tested and functional  
✅ JSON-RPC 2.0 fully compliant  
✅ CORS enabled for external access  
✅ Comprehensive request logging  
✅ Ready for Claude.ai integration