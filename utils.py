import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def validate_json_schema(data: Any, schema: Dict) -> bool:
    """Basic JSON schema validation"""
    try:
        # This is a simplified validation - in production, use jsonschema library
        if schema.get('type') == 'object':
            if not isinstance(data, dict):
                return False
            
            required = schema.get('required', [])
            for field in required:
                if field not in data:
                    return False
            
            properties = schema.get('properties', {})
            for field, field_schema in properties.items():
                if field in data:
                    if not validate_json_schema(data[field], field_schema):
                        return False
        
        elif schema.get('type') == 'string':
            return isinstance(data, str)
        elif schema.get('type') == 'number':
            return isinstance(data, (int, float))
        elif schema.get('type') == 'boolean':
            return isinstance(data, bool)
        elif schema.get('type') == 'array':
            if not isinstance(data, list):
                return False
            items_schema = schema.get('items', {})
            for item in data:
                if not validate_json_schema(item, items_schema):
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Schema validation error: {str(e)}")
        return False

def format_duration(milliseconds: float) -> str:
    """Format duration in human-readable format"""
    if milliseconds < 1000:
        return f"{milliseconds:.0f}ms"
    elif milliseconds < 60000:
        return f"{milliseconds/1000:.1f}s"
    else:
        return f"{milliseconds/60000:.1f}m"

def sanitize_json(data: Any) -> Any:
    """Sanitize data for JSON serialization"""
    if isinstance(data, datetime):
        return data.isoformat()
    elif isinstance(data, dict):
        return {k: sanitize_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_json(item) for item in data]
    else:
        return data

def generate_tool_schema_template() -> Dict:
    """Generate a template for tool schema"""
    return {
        "type": "object",
        "properties": {
            "message": {
                "type": "string",
                "description": "Input message for the tool"
            }
        },
        "required": ["message"]
    }

def validate_mcp_request(request_data: Dict) -> Optional[str]:
    """Validate MCP request format"""
    if not isinstance(request_data, dict):
        return "Request must be a JSON object"
    
    if 'method' not in request_data:
        return "Request must include 'method' field"
    
    method = request_data.get('method')
    if not isinstance(method, str):
        return "Method must be a string"
    
    # Validate known methods
    valid_methods = [
        'initialize',
        'tools/list',
        'tools/call',
        'resources/list',
        'resources/read'
    ]
    
    if method not in valid_methods:
        logger.warning(f"Unknown method: {method}")
    
    return None

def create_error_response(code: int, message: str, data: Any = None) -> Dict:
    """Create standardized error response"""
    error = {
        'code': code,
        'message': message
    }
    
    if data is not None:
        error['data'] = data
    
    return {'error': error}

def create_success_response(result: Any) -> Dict:
    """Create standardized success response"""
    return {'result': result}
