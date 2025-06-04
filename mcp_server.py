import json
import time
import uuid
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from app import db
from models import Tool, Resource, MCPLog

logger = logging.getLogger(__name__)

class MCPManager:
    """Manages MCP protocol communication and tool execution"""
    
    def __init__(self):
        self.tools = {}
        self.resources = {}
        self.capabilities = {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
            "logging": {}
        }
    
    def initialize(self):
        """Initialize the MCP manager with database tools and resources"""
        logger.info("Initializing MCP Manager...")
        self.load_tools()
        self.load_resources()
        logger.info(f"Loaded {len(self.tools)} tools and {len(self.resources)} resources")
    
    def load_tools(self):
        """Load tools from database"""
        tools = Tool.query.filter_by(is_active=True).all()
        self.tools = {tool.name: tool.to_dict() for tool in tools}
    
    def load_resources(self):
        """Load resources from database"""
        resources = Resource.query.filter_by(is_active=True).all()
        self.resources = {resource.name: resource.to_dict() for resource in resources}
    
    def handle_mcp_request(self, request_data: Dict) -> Dict:
        """Handle incoming MCP requests"""
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        try:
            method = request_data.get('method', '')
            params = request_data.get('params', {})
            
            logger.debug(f"Handling MCP request: {method}")
            
            # Route the request based on method
            if method == 'initialize':
                response = self._handle_initialize(params)
            elif method == 'tools/list':
                response = self._handle_tools_list()
            elif method == 'tools/call':
                response = self._handle_tool_call(params)
            elif method == 'resources/list':
                response = self._handle_resources_list()
            elif method == 'resources/read':
                response = self._handle_resource_read(params)
            else:
                response = {
                    'error': {
                        'code': -32601,
                        'message': f'Method not found: {method}'
                    }
                }
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Log the request/response
            self._log_request(request_id, method, request_data, response, 200, duration_ms)
            
            # Log activity (WebSocket disabled for stability)
            logger.debug(f"MCP Activity: {method} completed in {duration_ms:.2f}ms")
            
            return response
            
        except Exception as e:
            logger.error(f"Error handling MCP request: {str(e)}")
            duration_ms = (time.time() - start_time) * 1000
            error_response = {
                'error': {
                    'code': -32603,
                    'message': f'Internal error: {str(e)}'
                }
            }
            method_str = request_data.get('method', 'unknown') if 'method' in locals() else 'unknown'
            self._log_request(request_id, method_str, request_data, error_response, 500, duration_ms)
            return error_response
    
    def _handle_initialize(self, params: Dict) -> Dict:
        """Handle MCP initialize request"""
        return {
            'protocolVersion': '2024-11-05',
            'capabilities': self.capabilities,
            'serverInfo': {
                'name': 'Flask MCP Server',
                'version': '1.0.0'
            }
        }
    
    def _handle_tools_list(self) -> Dict:
        """Handle tools list request"""
        tools_list = []
        for tool_name, tool_data in self.tools.items():
            tools_list.append({
                'name': tool_name,
                'description': tool_data.get('description', ''),
                'inputSchema': tool_data.get('schema', {})
            })
        
        return {'tools': tools_list}
    
    def _handle_tool_call(self, params: Dict) -> Dict:
        """Handle tool call request"""
        tool_name = params.get('name')
        arguments = params.get('arguments', {})
        
        if tool_name not in self.tools:
            return {
                'error': {
                    'code': -32602,
                    'message': f'Tool not found: {tool_name}'
                }
            }
        
        tool = self.tools[tool_name]
        
        try:
            # Execute the tool
            result = self._execute_tool(tool, arguments)
            return {'content': [{'type': 'text', 'text': str(result)}]}
        except Exception as e:
            return {
                'error': {
                    'code': -32603,
                    'message': f'Tool execution failed: {str(e)}'
                }
            }
    
    def _handle_resources_list(self) -> Dict:
        """Handle resources list request"""
        resources_list = []
        for resource_name, resource_data in self.resources.items():
            resources_list.append({
                'uri': resource_data['uri'],
                'name': resource_name,
                'description': resource_data.get('description', ''),
                'mimeType': resource_data.get('mime_type')
            })
        
        return {'resources': resources_list}
    
    def _handle_resource_read(self, params: Dict) -> Dict:
        """Handle resource read request"""
        uri = params.get('uri')
        
        # Find resource by URI
        resource = None
        for res_data in self.resources.values():
            if res_data['uri'] == uri:
                resource = res_data
                break
        
        if not resource:
            return {
                'error': {
                    'code': -32602,
                    'message': f'Resource not found: {uri}'
                }
            }
        
        try:
            # For demo purposes, return basic resource info
            # In production, this would fetch actual resource content
            content = f"Resource: {resource['name']}\nURI: {resource['uri']}\nDescription: {resource.get('description', 'No description')}"
            
            return {
                'contents': [{
                    'uri': uri,
                    'mimeType': resource.get('mime_type', 'text/plain'),
                    'text': content
                }]
            }
        except Exception as e:
            return {
                'error': {
                    'code': -32603,
                    'message': f'Resource read failed: {str(e)}'
                }
            }
    
    def _execute_tool(self, tool: Dict, arguments: Dict) -> Any:
        """Execute a tool with given arguments"""
        endpoint = tool.get('endpoint')
        method = tool.get('method', 'POST')
        
        if endpoint:
            # Make HTTP request to tool endpoint
            if method.upper() == 'GET':
                response = requests.get(endpoint, params=arguments)
            else:
                response = requests.post(endpoint, json=arguments)
            
            response.raise_for_status()
            return response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
        else:
            # Built-in tool execution
            return self._execute_builtin_tool(tool['name'], arguments)
    
    def _execute_builtin_tool(self, tool_name: str, arguments: Dict) -> Any:
        """Execute built-in tools"""
        if tool_name == 'echo':
            return arguments.get('message', 'Hello from MCP Server!')
        elif tool_name == 'system_info':
            import platform
            return {
                'system': platform.system(),
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'timestamp': datetime.utcnow().isoformat()
            }
        elif tool_name == 'calculator':
            expression = arguments.get('expression', '')
            try:
                # Simple safe math evaluation for basic operations only
                # Replace dangerous functions and limit to basic math
                safe_expression = expression.replace('^', '**')
                allowed_chars = set('0123456789+-*/.() ')
                if all(c in allowed_chars for c in safe_expression):
                    result = eval(safe_expression)
                    return {
                        'expression': expression,
                        'result': result,
                        'type': type(result).__name__
                    }
                else:
                    return {
                        'expression': expression,
                        'error': 'Only basic math operations (+, -, *, /, parentheses) are allowed',
                        'result': None
                    }
            except Exception as e:
                return {
                    'expression': expression,
                    'error': f"Calculation error: {str(e)}",
                    'result': None
                }
        else:
            raise Exception(f"Unknown built-in tool: {tool_name}")
    
    def _log_request(self, request_id: str, method: str, request_data: Dict, 
                    response_data: Dict, status_code: int, duration_ms: float):
        """Log MCP request/response"""
        try:
            # Skip database logging for now to avoid timeouts
            logger.info(f"MCP Request: {method} - {status_code} - {duration_ms:.2f}ms")
        except Exception as e:
            logger.error(f"Error logging request: {str(e)}")
    
    def register_tool(self, name: str, description: str, schema: Dict, 
                     endpoint: Optional[str] = None, method: str = 'POST') -> bool:
        """Register a new tool"""
        try:
            tool = Tool()
            tool.name = name
            tool.description = description
            tool.schema = json.dumps(schema)
            tool.endpoint = endpoint
            tool.method = method
            
            db.session.add(tool)
            db.session.commit()
            
            # Reload tools
            self.load_tools()
            
            # Log tool update (WebSocket disabled for stability)
            logger.debug(f"Tool registered: {tool.to_dict()}")
            
            return True
        except Exception as e:
            logger.error(f"Error registering tool: {str(e)}")
            db.session.rollback()
            return False
    


    def get_stats(self) -> Dict:
        """Get MCP server statistics"""
        recent_logs = MCPLog.query.order_by(MCPLog.timestamp.desc()).limit(100).all()
        
        total_requests = len(recent_logs)
        avg_duration = sum(log.duration_ms for log in recent_logs) / total_requests if total_requests > 0 else 0
        error_count = sum(1 for log in recent_logs if log.status_code >= 400)
        
        return {
            'total_tools': len(self.tools),
            'total_resources': len(self.resources),
            'total_requests': total_requests,
            'error_rate': (error_count / total_requests * 100) if total_requests > 0 else 0,
            'avg_duration_ms': avg_duration,
            'uptime': 'N/A'  # Would need to track server start time
        }

# Global instance
mcp_manager = MCPManager()
