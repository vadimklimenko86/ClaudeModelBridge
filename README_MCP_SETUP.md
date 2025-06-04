# MCP Server Setup for Claude AI

## Overview
This Flask MCP server provides Model Context Protocol integration for Claude AI. To resolve authentication errors, follow these setup steps.

## Server Configuration

### 1. Server Endpoints
- **Main MCP Endpoint**: `http://localhost:5000/mcp/mcp`
- **Management API**: `http://localhost:5000/mcp/`
- **Health Check**: `http://localhost:5000/mcp/health`

### 2. Authentication
The server accepts API key authentication via Authorization header:
```
Authorization: Bearer your-api-key
```

For development, the server also accepts requests without authentication.

### 3. Claude AI Configuration

#### Option A: Direct HTTP Configuration
Add this to your Claude AI MCP configuration:

```json
{
  "mcpServers": {
    "flask-mcp-server": {
      "command": "python",
      "args": [
        "-c", 
        "import requests; import json; import sys; data = json.load(sys.stdin); response = requests.post('http://localhost:5000/mcp/mcp', json=data, headers={'Content-Type': 'application/json'}); print(json.dumps(response.json()))"
      ]
    }
  }
}
```

#### Option B: With Authentication
```json
{
  "mcpServers": {
    "flask-mcp-server": {
      "command": "python",
      "args": [
        "-c", 
        "import requests; import json; import sys; data = json.load(sys.stdin); response = requests.post('http://localhost:5000/mcp/mcp', json=data, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer mcp-server-token'}); print(json.dumps(response.json()))"
      ]
    }
  }
}
```

### 4. Available Tools
The server provides these tools:
- **echo**: Echo back messages
- **system_info**: Get system information
- **calculator**: Perform mathematical calculations

### 5. Testing Connection
Test the MCP server connection:
```bash
curl -X POST http://localhost:5000/mcp/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list", "params": {}}'
```

Expected response:
```json
{
  "tools": [
    {
      "name": "echo",
      "description": "Echo back the input message",
      "inputSchema": {...}
    },
    ...
  ]
}
```

## Troubleshooting

### Authorization Errors
1. Ensure the server is running on `http://localhost:5000`
2. Verify CORS headers are properly configured
3. Check that the MCP endpoint path is `/mcp/mcp`
4. Confirm Python requests library is available for Claude AI

### Connection Issues
1. Verify server is accessible: `curl http://localhost:5000/mcp/health`
2. Check firewall settings for port 5000
3. Ensure no other services are using port 5000

## Development Notes
- The server runs with CORS enabled for all origins
- Authentication is optional in development mode
- All MCP protocol methods are supported
- Real-time logging available at `/logs`