#!/usr/bin/env python3
"""
MCP Client for Claude AI Integration
This script acts as a bridge between Claude AI and the Flask MCP Server
"""

import json
import sys
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MCP_SERVER_URL = "http://localhost:5000/mcp/mcp"
API_KEY = "mcp-server-token"

def main():
    """Main MCP client function"""
    try:
        # Read JSON request from stdin
        request_data = json.load(sys.stdin)
        logger.info(f"Sending MCP request: {request_data.get('method', 'unknown')}")
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {API_KEY}'
        }
        
        # Send request to MCP server
        response = requests.post(
            MCP_SERVER_URL,
            json=request_data,
            headers=headers,
            timeout=30
        )
        
        # Check response status
        if response.status_code == 200:
            result = response.json()
            logger.info(f"MCP response successful: {result.get('method', 'response')}")
            print(json.dumps(result))
        else:
            logger.error(f"MCP server error: {response.status_code} - {response.text}")
            error_response = {
                "error": {
                    "code": -32603,
                    "message": f"Server error: {response.status_code}",
                    "data": response.text
                }
            }
            print(json.dumps(error_response))
            
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        error_response = {
            "error": {
                "code": -32700,
                "message": "Parse error",
                "data": str(e)
            }
        }
        print(json.dumps(error_response))
        
    except requests.RequestException as e:
        logger.error(f"Request error: {e}")
        error_response = {
            "error": {
                "code": -32000,
                "message": "Connection error",
                "data": str(e)
            }
        }
        print(json.dumps(error_response))
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        error_response = {
            "error": {
                "code": -32603,
                "message": "Internal error",
                "data": str(e)
            }
        }
        print(json.dumps(error_response))

if __name__ == "__main__":
    main()