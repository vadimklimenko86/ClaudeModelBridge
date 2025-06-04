import json
import time
import uuid
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, Response, stream_template
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
    recent_logs = MCPLog.query.order_by(
        MCPLog.timestamp.desc()).limit(10).all()
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
        page=page, per_page=50, error_out=False)
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


@api_bp.route('/mcp', methods=['GET', 'POST', 'OPTIONS'])
@api_bp.route('/', methods=['GET', 'POST', 'OPTIONS'])
def mcp_endpoint():
    """Main MCP protocol endpoint"""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers',
                             'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response

    # Handle GET requests - SSE for Claude.ai compatibility
    if request.method == 'GET':
        accept_header = request.headers.get('Accept', '')
        if 'text/event-stream' in accept_header:
            # Claude.ai is requesting SSE connection - implement proper MCP HTTP+SSE transport
            logger.info("Serving MCP HTTP+SSE stream for Claude.ai integration")
            
            def mcp_sse_generator():
                # MCP HTTP+SSE transport: each message is a complete JSON-RPC message
                # Start with handshake notification
                handshake = {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {}
                }
                yield f"data: {json.dumps(handshake)}\n\n"
                
                # Send server info when requested
                server_info = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {
                            "tools": {"listChanged": True},
                            "resources": {"subscribe": True, "listChanged": True},
                            "logging": {},
                            "prompts": {"listChanged": True}
                        },
                        "serverInfo": {
                            "name": "Flask MCP Server",
                            "version": "1.0.0"
                        }
                    }
                }
                yield f"data: {json.dumps(server_info)}\n\n"
                
                # Send tools list
                tools_list = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "Echo back the input message",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "message": {
                                            "type": "string",
                                            "description": "Message to echo back"
                                        }
                                    },
                                    "required": ["message"]
                                }
                            },
                            {
                                "name": "system_info",
                                "description": "Get system information",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "required": []
                                }
                            },
                            {
                                "name": "calculator",
                                "description": "Perform basic mathematical calculations",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "expression": {
                                            "type": "string",
                                            "description": "Mathematical expression to evaluate"
                                        }
                                    },
                                    "required": ["expression"]
                                }
                            }
                        ]
                    }
                }
                yield f"data: {json.dumps(tools_list)}\n\n"
            
            response = Response(mcp_sse_generator(), mimetype='text/event-stream')
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Authorization,Cache-Control,Content-Type')
            response.headers.add('Cache-Control', 'no-cache')
            response.headers.add('Connection', 'keep-alive')
            response.headers.add('X-Accel-Buffering', 'no')
            return response
        else:
            # Regular GET request for info
            return jsonify({
                'service': 'MCP Server',
                'version': '1.0.0',
                'status': 'active',
                'description': 'Model Context Protocol Server for Claude AI integration',
                'endpoint': request.url,
                'methods': ['POST'],
                'documentation': '/api-docs',
                'tools_count': len(mcp_manager.tools),
                'resources_count': len(mcp_manager.resources),
                'transport': 'http+sse'
            })

    # Handle POST requests for MCP tool execution and protocol methods
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32700,
                    'message': 'Parse error'
                },
                'id': None
            }), 400

        logger.info(f"MCP POST request: {request_data.get('method', 'unknown')}")
        
        # Handle different MCP methods
        method = request_data.get('method')
        params = request_data.get('params', {})
        request_id = request_data.get('id')
        
        if method == 'initialize':
            result = {
                'protocolVersion': '2025-03-26',
                'capabilities': {
                    'tools': {'listChanged': True},
                    'resources': {'subscribe': True, 'listChanged': True},
                    'logging': {},
                    'prompts': {'listChanged': True}
                },
                'serverInfo': {
                    'name': 'Flask MCP Server',
                    'version': '1.0.0'
                }
            }
        elif method == 'tools/list':
            result = {
                'tools': [
                    {
                        'name': 'echo',
                        'description': 'Echo back the input message',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'message': {
                                    'type': 'string',
                                    'description': 'Message to echo back'
                                }
                            },
                            'required': ['message']
                        }
                    },
                    {
                        'name': 'system_info',
                        'description': 'Get system information',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {},
                            'required': []
                        }
                    },
                    {
                        'name': 'calculator',
                        'description': 'Perform basic mathematical calculations',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'expression': {
                                    'type': 'string',
                                    'description': 'Mathematical expression to evaluate'
                                }
                            },
                            'required': ['expression']
                        }
                    }
                ]
            }
        elif method == 'tools/call':
            tool_name = params.get('name')
            arguments = params.get('arguments', {})
            
            if tool_name == 'echo':
                result = {
                    'content': [
                        {
                            'type': 'text',
                            'text': f"Echo: {arguments.get('message', '')}"
                        }
                    ]
                }
            elif tool_name == 'system_info':
                import platform
                result = {
                    'content': [
                        {
                            'type': 'text',
                            'text': f"System: {platform.system()} {platform.release()}\nPython: {platform.python_version()}\nArchitecture: {platform.machine()}"
                        }
                    ]
                }
            elif tool_name == 'calculator':
                try:
                    expression = arguments.get('expression', '')
                    # Safe evaluation of basic math expressions
                    import ast
                    import operator
                    
                    ops = {
                        ast.Add: operator.add,
                        ast.Sub: operator.sub,
                        ast.Mult: operator.mul,
                        ast.Div: operator.truediv,
                        ast.Pow: operator.pow,
                        ast.USub: operator.neg,
                    }
                    
                    def eval_expr(node):
                        if isinstance(node, ast.Num):
                            return node.n
                        elif isinstance(node, ast.BinOp):
                            return ops[type(node.op)](eval_expr(node.left), eval_expr(node.right))
                        elif isinstance(node, ast.UnaryOp):
                            return ops[type(node.op)](eval_expr(node.operand))
                        else:
                            raise TypeError(node)
                    
                    tree = ast.parse(expression, mode='eval')
                    calc_result = eval_expr(tree.body)
                    
                    result = {
                        'content': [
                            {
                                'type': 'text',
                                'text': f"Result: {expression} = {calc_result}"
                            }
                        ]
                    }
                except Exception as e:
                    result = {
                        'content': [
                            {
                                'type': 'text',
                                'text': f"Error calculating '{expression}': {str(e)}"
                            }
                        ]
                    }
            else:
                return jsonify({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32601,
                        'message': f'Unknown tool: {tool_name}'
                    },
                    'id': request_id
                }), 400
        else:
            return jsonify({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32601,
                    'message': f'Method not found: {method}'
                },
                'id': request_id
            }), 400

        response_data = {
            'jsonrpc': '2.0',
            'result': result,
            'id': request_id
        }
        
        response = jsonify(response_data)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response

    except Exception as e:
        logger.error(f"MCP endpoint error: {str(e)}")
        return jsonify({
            'jsonrpc': '2.0',
            'error': {
                'code': -32603,
                'message': f'Internal error: {str(e)}'
            },
            'id': request_data.get('id') if 'request_data' in locals() else None
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
            return jsonify({'error':
                            'Tool with this name already exists'}), 409

        success = mcp_manager.register_tool(name, description, schema,
                                            endpoint, method)

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
        tool.schema = json.dumps(
            data.get('schema', json.loads(tool.schema or '{}')))
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
        resource = Resource(name=data.get('name'),
                            description=data.get('description', ''),
                            uri=data.get('uri'),
                            mime_type=data.get('mime_type', 'text/plain'))

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
        response.headers.add('Access-Control-Allow-Headers',
                             'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response

    try:
        # Handle both JSON and header-based authentication
        request_data = {}
        if request.content_type == 'application/json':
            request_data = request.get_json() or {}

        # Check if API key is provided in JSON body or Authorization header
        api_key = request_data.get('api_key') or request.headers.get(
            'Authorization')

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
        response.headers.add('Access-Control-Allow-Headers',
                             'Content-Type,Authorization')
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


@api_bp.route('/logs/<int:log_id>', methods=['GET'])
def get_log_details(log_id):
    """Get detailed information for a specific log entry"""
    try:
        log = MCPLog.query.get_or_404(log_id)
        
        # Safe JSON parsing with fallback
        def safe_json_parse(data):
            if not data:
                return None
            try:
                return json.loads(data)
            except (json.JSONDecodeError, TypeError):
                # Return raw string if JSON parsing fails
                return {'raw_data': str(data)}
        
        return jsonify({
            'id': log.id,
            'request_id': log.request_id,
            'method': log.method,
            'status_code': log.status_code,
            'duration_ms': log.duration_ms,
            'timestamp': log.timestamp.isoformat(),
            'request_data': safe_json_parse(log.request_data),
            'response_data': safe_json_parse(log.response_data)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status':
        'healthy',
        'timestamp':
        MCPLog.query.first().timestamp.isoformat()
        if MCPLog.query.first() else None,
        'version':
        '1.0.0'
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
        "issuer":
        base_url,
        "authorization_endpoint":
        f"{base_url}/oauth/authorize",
        "token_endpoint":
        f"{base_url}/oauth/token",
        "jwks_uri":
        f"{base_url}/.well-known/jwks.json",
        "scopes_supported":
        ["mcp:read", "mcp:write", "tools:execute", "resources:read", "admin"],
        "response_types_supported": ["code", "token"],
        "grant_types_supported":
        ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported":
        ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "revocation_endpoint":
        f"{base_url}/oauth/revoke",
        "introspection_endpoint":
        f"{base_url}/oauth/introspect",
        "registration_endpoint":
        f"{base_url}/oauth/register",
        "service_documentation":
        f"{base_url}/api-docs",
        "ui_locales_supported": ["en", "ru"],
        "op_policy_uri":
        f"{base_url}/privacy-policy",
        "op_tos_uri":
        f"{base_url}/terms-of-service"
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
        "keys": [{
            "kty":
            "RSA",
            "use":
            "sig",
            "kid":
            "mcp-server-key-1",
            "alg":
            "RS256",
            "n":
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI",
            "e":
            "AQAB",
            "x5c": [
                "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTgwElo7P1A6J6Goi2i3C7TZ0D4VO8w3ej6TuvnJJi4D1Cf6J7yrZ7+D4DZkMM6a+OJd3dV4j4m3HL9OV4bBXKiYZ+deLl1JVQW8W9Dz1h4h3g2p9IyCKW5YCKzB7+6iQF5hwDAwIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCZ"
            ],
            "x5t":
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            "x5t#S256":
            "E9cux_4WIOtOl_kKh0TUyeWz3pOjaXK-7ixI-rPQ5xk"
        }]
    }

    response = jsonify(jwks_data)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


# OAuth Authorization Endpoints
@main_bp.route('/oauth/authorize', methods=['GET', 'POST'])
def oauth_authorize():
    """OAuth 2.0 Authorization Endpoint
    
    Handles authorization requests according to RFC 6749.
    Supports authorization code and implicit grant flows.
    """
    if request.method == 'GET':
        # Authorization request - show consent page
        client_id = request.args.get('client_id')
        response_type = request.args.get('response_type')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope', 'mcp:read')
        state = request.args.get('state')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method')

        # Validate required parameters
        if not client_id or not response_type or not redirect_uri:
            return jsonify({
                'error':
                'invalid_request',
                'error_description':
                'Missing required parameters: client_id, response_type, redirect_uri'
            }), 400

        if response_type not in ['code', 'token']:
            return jsonify({
                'error':
                'unsupported_response_type',
                'error_description':
                'Only code and token response types are supported'
            }), 400

        # For demo purposes, auto-approve the authorization
        # In production, this would show a consent page
        if response_type == 'code':
            # Authorization code flow
            auth_code = f"auth_code_{int(time.time())}"

            # Build redirect URL with authorization code
            redirect_params = {'code': auth_code, 'state': state}
            if state:
                redirect_params['state'] = state

            # In production, store code with expiration and client validation
            redirect_url = f"{redirect_uri}?{'&'.join([f'{k}={v}' for k, v in redirect_params.items() if v])}"

        else:
            # Implicit flow - return access token directly
            access_token = f"access_token_{int(time.time())}"

            redirect_params = {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': '3600',
                'scope': scope
            }
            if state:
                redirect_params['state'] = state

            redirect_url = f"{redirect_uri}#{'&'.join([f'{k}={v}' for k, v in redirect_params.items() if v])}"

        return redirect(redirect_url)

    else:
        # POST - Handle authorization approval/denial
        action = request.form.get('action')
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        state = request.form.get('state')

        if action == 'approve':
            # Generate authorization code
            auth_code = f"auth_code_{int(time.time())}"
            redirect_params = {'code': auth_code}
            if state:
                redirect_params['state'] = state
            redirect_url = f"{redirect_uri}?{'&'.join([f'{k}={v}' for k, v in redirect_params.items()])}"
        else:
            # User denied authorization
            redirect_params = {'error': 'access_denied'}
            if state:
                redirect_params['state'] = state
            redirect_url = f"{redirect_uri}?{'&'.join([f'{k}={v}' for k, v in redirect_params.items()])}"

        return redirect(redirect_url)


@main_bp.route('/oauth/token', methods=['POST'])
def oauth_token():
    """OAuth 2.0 Token Endpoint
    
    Exchanges authorization codes for access tokens.
    Supports authorization_code and client_credentials grant types.
    """
    grant_type = request.form.get('grant_type') or (request.json.get(
        'grant_type') if request.is_json and request.json else None)

    if not grant_type:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing grant_type parameter'
        }), 400

    if grant_type == 'authorization_code':
        code = request.form.get('code') or (request.json.get(
            'code') if request.is_json and request.json else None)
        client_id = request.form.get('client_id') or (request.json.get(
            'client_id') if request.is_json and request.json else None)
        redirect_uri = request.form.get('redirect_uri') or (request.json.get(
            'redirect_uri') if request.is_json and request.json else None)

        if not code or not client_id:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Missing required parameters'
            }), 400

        # In production, validate the authorization code
        # For demo, accept any code that starts with 'auth_code_'
        if not code.startswith('auth_code_'):
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Invalid authorization code'
            }), 400

        # Generate access token
        access_token = f"mcp_access_token_{int(time.time())}"
        refresh_token = f"mcp_refresh_token_{int(time.time())}"

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token,
            'scope': 'mcp:read mcp:write tools:execute'
        })

    elif grant_type == 'client_credentials':
        # Client credentials flow
        client_id = request.form.get('client_id') or (request.json.get(
            'client_id') if request.is_json and request.json else None)
        client_secret = request.form.get('client_secret') or (request.json.get(
            'client_secret') if request.is_json and request.json else None)
        scope = request.form.get('scope') or (request.json.get(
            'scope') if request.is_json and request.json else 'mcp:read')

        if not client_id:
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Missing client_id'
            }), 400

        # Generate machine-to-machine access token
        access_token = f"mcp_m2m_token_{int(time.time())}"

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': scope
        })

    else:
        return jsonify({
            'error':
            'unsupported_grant_type',
            'error_description':
            f'Grant type {grant_type} is not supported'
        }), 400


@main_bp.route('/oauth/register', methods=['POST', 'GET'])
def oauth_register():
    """OAuth 2.0 Dynamic Client Registration Endpoint
    
    Allows clients to register with the authorization server.
    Supports both GET (registration form) and POST (registration API).
    """
    if request.method == 'GET':
        # Show client registration form
        return render_template('oauth_register.html')

    # Handle client registration
    client_metadata = request.get_json() if request.is_json else {
        'client_name':
        request.form.get('client_name'),
        'client_uri':
        request.form.get('client_uri'),
        'redirect_uris':
        request.form.getlist('redirect_uris')
        or [request.form.get('redirect_uri')],
        'grant_types':
        request.form.getlist('grant_types') or ['authorization_code'],
        'response_types':
        request.form.getlist('response_types') or ['code'],
        'scope':
        request.form.get('scope', 'mcp:read')
    }

    # Validate required fields
    if not client_metadata.get('client_name'):
        return jsonify({
            'error': 'invalid_client_metadata',
            'error_description': 'client_name is required'
        }), 400

    if not client_metadata.get('redirect_uris'):
        return jsonify({
            'error':
            'invalid_redirect_uri',
            'error_description':
            'At least one redirect_uri is required'
        }), 400

    # Generate client credentials
    client_id = f"client_{int(time.time())}"
    client_secret = f"secret_{int(time.time())}"

    # Create client registration response
    client_info = {
        'client_id': client_id,
        'client_secret': client_secret,
        'client_name': client_metadata.get('client_name'),
        'client_uri': client_metadata.get('client_uri'),
        'redirect_uris': client_metadata.get('redirect_uris'),
        'grant_types': client_metadata.get('grant_types',
                                           ['authorization_code']),
        'response_types': client_metadata.get('response_types', ['code']),
        'scope': client_metadata.get('scope', 'mcp:read'),
        'token_endpoint_auth_method': 'client_secret_post',
        'client_id_issued_at': int(time.time()),
        'client_secret_expires_at': 0  # Never expires in this demo
    }

    # In production, save client info to database
    logger.info(f"Registered new OAuth client: {client_id}")

    if request.is_json:
        return jsonify(client_info), 201
    else:
        # Show success page with client credentials
        return render_template('oauth_register_success.html',
                               client_info=client_info)
