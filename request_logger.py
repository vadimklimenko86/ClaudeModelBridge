import logging
import time
from datetime import datetime
from flask import request, g
from app import db
from models import MCPLog

logger = logging.getLogger(__name__)

class RequestLogger:
    """Comprehensive request logging middleware"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize request logging for Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.errorhandler(404)(self.handle_404)
        app.errorhandler(500)(self.handle_500)
        app.errorhandler(Exception)(self.handle_exception)
    
    def before_request(self):
        """Log request start time and details"""
        g.start_time = time.time()
        g.request_id = f"req_{int(time.time() * 1000)}"
        
        # Log all incoming requests
        logger.info(f"[{g.request_id}] {request.method} {request.path} - {request.remote_addr}")
        logger.debug(f"[{g.request_id}] Headers: {dict(request.headers)}")
        
        if request.is_json and request.get_json():
            logger.debug(f"[{g.request_id}] JSON Body: {request.get_json()}")
        elif request.form:
            logger.debug(f"[{g.request_id}] Form Data: {dict(request.form)}")
        elif request.args:
            logger.debug(f"[{g.request_id}] Query Params: {dict(request.args)}")
    
    def after_request(self, response):
        """Log request completion"""
        duration = (time.time() - g.start_time) * 1000 if hasattr(g, 'start_time') else 0
        request_id = getattr(g, 'request_id', 'unknown')
        
        logger.info(f"[{request_id}] Response: {response.status_code} - {duration:.2f}ms")
        
        # Log to database for non-MCP requests
        if not request.path.startswith('/mcp/mcp'):
            # Safely get response size without breaking direct passthrough mode
            response_size = 0
            try:
                if hasattr(response, 'content_length') and response.content_length:
                    response_size = response.content_length
                elif hasattr(response, 'response') and response.response:
                    # For static files, estimate size from headers
                    content_length = response.headers.get('Content-Length')
                    if content_length:
                        response_size = int(content_length)
            except:
                response_size = 0
            
            self.log_to_database(
                request_id=request_id,
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                duration_ms=duration,
                user_agent=request.headers.get('User-Agent', ''),
                ip_address=request.remote_addr,
                request_data=self.get_request_data(),
                response_size=response_size
            )
        
        return response
    
    def handle_404(self, error):
        """Handle 404 errors and log them"""
        request_id = getattr(g, 'request_id', 'unknown')
        duration = (time.time() - g.start_time) * 1000 if hasattr(g, 'start_time') else 0
        
        logger.warning(f"[{request_id}] 404 Not Found: {request.method} {request.path}")
        
        # Log 404s to database
        self.log_to_database(
            request_id=request_id,
            method=request.method,
            path=request.path,
            status_code=404,
            duration_ms=duration,
            user_agent=request.headers.get('User-Agent', ''),
            ip_address=request.remote_addr,
            request_data=self.get_request_data(),
            error_message=f"Page not found: {request.path}"
        )
        
        return {
            'error': 'Not Found',
            'message': f'The requested URL {request.path} was not found on this server.',
            'status_code': 404,
            'request_id': request_id
        }, 404
    
    def handle_500(self, error):
        """Handle 500 errors and log them"""
        request_id = getattr(g, 'request_id', 'unknown')
        duration = (time.time() - g.start_time) * 1000 if hasattr(g, 'start_time') else 0
        
        logger.error(f"[{request_id}] 500 Internal Server Error: {str(error)}")
        
        # Log 500s to database
        self.log_to_database(
            request_id=request_id,
            method=request.method,
            path=request.path,
            status_code=500,
            duration_ms=duration,
            user_agent=request.headers.get('User-Agent', ''),
            ip_address=request.remote_addr,
            request_data=self.get_request_data(),
            error_message=str(error)
        )
        
        return {
            'error': 'Internal Server Error',
            'message': 'An internal server error occurred.',
            'status_code': 500,
            'request_id': request_id
        }, 500
    
    def handle_exception(self, error):
        """Handle all unhandled exceptions"""
        request_id = getattr(g, 'request_id', 'unknown')
        duration = (time.time() - g.start_time) * 1000 if hasattr(g, 'start_time') else 0
        
        logger.error(f"[{request_id}] Unhandled Exception: {str(error)}")
        
        # Log exceptions to database
        self.log_to_database(
            request_id=request_id,
            method=request.method,
            path=request.path,
            status_code=500,
            duration_ms=duration,
            user_agent=request.headers.get('User-Agent', ''),
            ip_address=request.remote_addr,
            request_data=self.get_request_data(),
            error_message=f"Exception: {str(error)}"
        )
        
        return {
            'error': 'Server Error',
            'message': 'An unexpected error occurred.',
            'status_code': 500,
            'request_id': request_id
        }, 500
    
    def get_request_data(self):
        """Extract request data for logging"""
        data = {
            'headers': dict(request.headers),
            'args': dict(request.args),
            'method': request.method,
            'path': request.path,
            'url': request.url
        }
        
        if request.is_json:
            try:
                data['json'] = request.get_json()
            except:
                data['json'] = None
        
        if request.form:
            data['form'] = dict(request.form)
        
        return str(data)
    
    def log_to_database(self, request_id, method, path, status_code, duration_ms, 
                       user_agent, ip_address, request_data, response_size=0, error_message=None):
        """Log request details to database"""
        try:
            log_entry = MCPLog(
                request_id=request_id,
                method=f"{method} {path}",
                request_data=request_data,
                response_data=error_message or f"Status: {status_code}, Size: {response_size}b",
                status_code=status_code,
                duration_ms=duration_ms,
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log to database: {str(e)}")
            db.session.rollback()