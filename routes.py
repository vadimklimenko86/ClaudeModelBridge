import json
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from app import db
from models import Tool, Resource, MCPLog
from mcp_server import mcp_manager
import logging

logger = logging.getLogger(__name__)

# Create blueprints
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

@main_bp.route('/')
def index():
    """Main dashboard"""
    stats = mcp_manager.get_stats()
    recent_logs = MCPLog.query.order_by(MCPLog.timestamp.desc()).limit(10).all()
    return render_template('index.html', stats=stats, recent_logs=recent_logs)

@main_bp.route('/tools')
def tools():
    """Tools management page"""
    tools = Tool.query.order_by(Tool.created_at.desc()).all()
    return render_template('tools.html', tools=tools)

@main_bp.route('/api-docs')
def api_docs():
    """API documentation page"""
    return render_template('api_docs.html')

@main_bp.route('/logs')
def logs():
    """Logs page"""
    page = request.args.get('page', 1, type=int)
    logs = MCPLog.query.order_by(MCPLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('logs.html', logs=logs)

# API Routes

def authenticate_request():
    """Authenticate MCP requests"""
    # Check for API key in headers
    api_key = request.headers.get('Authorization')
    if api_key:
        # Remove 'Bearer ' prefix if present
        if api_key.startswith('Bearer '):
            api_key = api_key[7:]
        # For now, accept any non-empty API key - can be configured later
        return True
    
    # Also accept requests without auth for development
    return True

@api_bp.route('/mcp', methods=['POST', 'OPTIONS'])
def mcp_endpoint():
    """Main MCP protocol endpoint"""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response
    
    # Authenticate request
    if not authenticate_request():
        return jsonify({'error': {'code': -32000, 'message': 'Authentication required'}}), 401
    
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({'error': {'code': -32700, 'message': 'Parse error'}}), 400
        
        logger.info(f"MCP Request received: {request_data.get('method', 'unknown')}")
        response_data = mcp_manager.handle_mcp_request(request_data)
        logger.info(f"MCP Response ready: {response_data.get('error', {}).get('code', 'success')}")
        
        response = jsonify(response_data)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response
    
    except Exception as e:
        logger.error(f"MCP endpoint error: {str(e)}")
        return jsonify({
            'error': {
                'code': -32603,
                'message': f'Internal error: {str(e)}'
            }
        }), 500

@api_bp.route('/tools', methods=['GET'])
def list_tools():
    """List all registered tools"""
    tools = Tool.query.filter_by(is_active=True).all()
    return jsonify([tool.to_dict() for tool in tools])

@api_bp.route('/tools', methods=['POST'])
def create_tool():
    """Create a new tool"""
    data = request.get_json()
    
    try:
        name = data.get('name')
        description = data.get('description', '')
        schema = data.get('schema', {})
        endpoint = data.get('endpoint')
        method = data.get('method', 'POST')
        
        if not name:
            return jsonify({'error': 'Tool name is required'}), 400
        
        # Check if tool already exists
        existing_tool = Tool.query.filter_by(name=name).first()
        if existing_tool:
            return jsonify({'error': 'Tool with this name already exists'}), 409
        
        success = mcp_manager.register_tool(name, description, schema, endpoint, method)
        
        if success:
            tool = Tool.query.filter_by(name=name).first()
            return jsonify(tool.to_dict()), 201
        else:
            return jsonify({'error': 'Failed to register tool'}), 500
            
    except Exception as e:
        logger.error(f"Error creating tool: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tools/<int:tool_id>', methods=['PUT'])
def update_tool(tool_id):
    """Update a tool"""
    tool = Tool.query.get_or_404(tool_id)
    data = request.get_json()
    
    try:
        tool.name = data.get('name', tool.name)
        tool.description = data.get('description', tool.description)
        tool.schema = json.dumps(data.get('schema', json.loads(tool.schema or '{}')))
        tool.endpoint = data.get('endpoint', tool.endpoint)
        tool.method = data.get('method', tool.method)
        tool.is_active = data.get('is_active', tool.is_active)
        
        db.session.commit()
        mcp_manager.load_tools()  # Reload tools
        
        return jsonify(tool.to_dict())
        
    except Exception as e:
        logger.error(f"Error updating tool: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tools/<int:tool_id>', methods=['DELETE'])
def delete_tool(tool_id):
    """Delete a tool"""
    tool = Tool.query.get_or_404(tool_id)
    
    try:
        tool.is_active = False
        db.session.commit()
        mcp_manager.load_tools()  # Reload tools
        
        return jsonify({'message': 'Tool deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting tool: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/resources', methods=['GET'])
def list_resources():
    """List all resources"""
    resources = Resource.query.filter_by(is_active=True).all()
    return jsonify([resource.to_dict() for resource in resources])

@api_bp.route('/resources', methods=['POST'])
def create_resource():
    """Create a new resource"""
    data = request.get_json()
    
    try:
        resource = Resource(
            name=data.get('name'),
            description=data.get('description', ''),
            uri=data.get('uri'),
            mime_type=data.get('mime_type', 'text/plain')
        )
        
        db.session.add(resource)
        db.session.commit()
        mcp_manager.load_resources()  # Reload resources
        
        return jsonify(resource.to_dict()), 201
        
    except Exception as e:
        logger.error(f"Error creating resource: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/authorize', methods=['POST', 'OPTIONS'])
def authorize():
    """Authorization endpoint for API key validation"""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response
    
    try:
        # Handle both JSON and header-based authentication
        request_data = {}
        if request.content_type == 'application/json':
            request_data = request.get_json() or {}
        
        # Check if API key is provided in JSON body or Authorization header
        api_key = request_data.get('api_key') or request.headers.get('Authorization')
        
        if api_key:
            # Remove 'Bearer ' prefix if present
            if api_key.startswith('Bearer '):
                api_key = api_key[7:]
            
            # Validate API key (accept any non-empty key for now)
            if len(api_key.strip()) > 0:
                response_data = {
                    'authorized': True,
                    'message': 'Authentication successful',
                    'permissions': ['mcp:read', 'mcp:write', 'tools:execute'],
                    'expires_in': 3600,
                    'server_info': {
                        'name': 'Flask MCP Server',
                        'version': '1.0.0',
                        'endpoint': '/mcp/mcp'
                    }
                }
            else:
                response_data = {
                    'authorized': False,
                    'message': 'Invalid API key format',
                    'error': 'INVALID_KEY_FORMAT'
                }
        else:
            response_data = {
                'authorized': False,
                'message': 'API key required',
                'error': 'MISSING_API_KEY'
            }
        
        response = jsonify(response_data)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response
        
    except Exception as e:
        logger.error(f"Authorization endpoint error: {str(e)}")
        error_response = jsonify({
            'authorized': False,
            'message': 'Authorization service error',
            'error': 'SERVICE_ERROR'
        })
        error_response.headers.add('Access-Control-Allow-Origin', '*')
        return error_response, 500

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get server statistics"""
    return jsonify(mcp_manager.get_stats())

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': MCPLog.query.first().timestamp.isoformat() if MCPLog.query.first() else None,
        'version': '1.0.0'
    })

# OAuth Authorization Server Discovery Endpoint (MCP Specification)
@main_bp.route('/.well-known/oauth-authorization-server', methods=['GET'])
def oauth_authorization_server():
    """OAuth Authorization Server Metadata (RFC 8414)
    
    This endpoint provides OAuth 2.0 authorization server metadata
    as required by the MCP specification for authorization.
    """
    base_url = request.url_root.rstrip('/')
    
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "scopes_supported": [
            "mcp:read",
            "mcp:write", 
            "tools:execute",
            "resources:read",
            "admin"
        ],
        "response_types_supported": [
            "code",
            "token"
        ],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "code_challenge_methods_supported": [
            "S256",
            "plain"
        ],
        "revocation_endpoint": f"{base_url}/oauth/revoke",
        "introspection_endpoint": f"{base_url}/oauth/introspect",
        "registration_endpoint": f"{base_url}/oauth/register",
        "service_documentation": f"{base_url}/api-docs",
        "ui_locales_supported": ["en", "ru"],
        "op_policy_uri": f"{base_url}/privacy-policy",
        "op_tos_uri": f"{base_url}/terms-of-service"
    }
    
    response = jsonify(metadata)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@main_bp.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """JSON Web Key Set (JWKS) endpoint
    
    Provides public keys for JWT token verification
    as required by OAuth 2.0 and MCP specification.
    """
    # Generate a sample JWKS for development
    # In production, this should contain actual public keys
    jwks_data = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "mcp-server-key-1",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI",
                "e": "AQAB",
                "x5c": ["MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTgwElo7P1A6J6Goi2i3C7TZ0D4VO8w3ej6TuvnJJi4D1Cf6J7yrZ7+D4DZkMM6a+OJd3dV4j4m3HL9OV4bBXKiYZ+deLl1JVQW8W9Dz1h4h3g2p9IyCKW5YCKzB7+6iQF5hwDAwIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCZ"],
                "x5t": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
                "x5t#S256": "E9cux_4WIOtOl_kKh0TUyeWz3pOjaXK-7ixI-rPQ5xk"
            }
        ]
    }
    
    response = jsonify(jwks_data)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response
