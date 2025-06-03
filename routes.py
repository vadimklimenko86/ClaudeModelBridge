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

@api_bp.route('/mcp', methods=['POST'])
def mcp_endpoint():
    """Main MCP protocol endpoint"""
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({'error': {'code': -32700, 'message': 'Parse error'}}), 400
        
        logger.info(f"MCP Request received: {request_data.get('method', 'unknown')}")
        response = mcp_manager.handle_mcp_request(request_data)
        logger.info(f"MCP Response ready: {response.get('error', {}).get('code', 'success')}")
        return jsonify(response)
    
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
