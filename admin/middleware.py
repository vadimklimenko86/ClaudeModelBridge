"""
Middleware для админ-панели RemoteMCP
"""

import time
import secrets
import hashlib
from typing import Callable, Dict, Any, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse, RedirectResponse
from starlette.status import HTTP_429_TOO_MANY_REQUESTS, HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED
import logging
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Middleware для проверки аутентификации в админ-панели"""
    
    def __init__(self, app, admin_auth, excluded_paths: list = None):
        super().__init__(app)
        self.admin_auth = admin_auth
        self.excluded_paths = excluded_paths or ['/admin/login', '/admin/static', '/admin/api/health']
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Проверяет аутентификацию для защищенных путей"""
        path = request.url.path
        
        # Пропускаем исключенные пути
        if any(path.startswith(excluded) for excluded in self.excluded_paths):
            return await call_next(request)
        
        # Проверяем только админ пути
        if not path.startswith('/admin'):
            return await call_next(request)
        
        # Получаем токен из cookies или заголовка
        token = request.cookies.get('admin_token')
        if not token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            if path.startswith('/admin/api'):
                return JSONResponse(
                    {'error': 'Токен аутентификации отсутствует'},
                    status_code=HTTP_401_UNAUTHORIZED
                )
            return RedirectResponse('/admin/login')
        
        # Проверяем токен
        payload = self.admin_auth.verify_token(token)
        if not payload:
            if path.startswith('/admin/api'):
                return JSONResponse(
                    {'error': 'Недействительный токен'},
                    status_code=HTTP_401_UNAUTHORIZED
                )
            return RedirectResponse('/admin/login')
        
        # Добавляем информацию о пользователе в request
        request.state.admin_user = payload
        request.state.admin_token = token
        
        return await call_next(request)

class CSRFMiddleware(BaseHTTPMiddleware):
    """Middleware для защиты от CSRF атак"""
    
    def __init__(self, app, secret_key: str):
        super().__init__(app)
        self.secret_key = secret_key
        self.safe_methods = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
    
    def _generate_csrf_token(self, session_id: str) -> str:
        """Генерирует CSRF токен"""
        timestamp = str(int(time.time()))
        data = f"{session_id}:{timestamp}:{self.secret_key}"
        token = hashlib.sha256(data.encode()).hexdigest()
        return f"{timestamp}.{token}"
    
    def _verify_csrf_token(self, token: str, session_id: str) -> bool:
        """Проверяет CSRF токен"""
        try:
            timestamp_str, provided_token = token.split('.', 1)
            timestamp = int(timestamp_str)
            
            # Проверяем, что токен не старше 2 часов
            if time.time() - timestamp > 7200:
                return False
            
            # Генерируем ожидаемый токен
            data = f"{session_id}:{timestamp_str}:{self.secret_key}"
            expected_token = hashlib.sha256(data.encode()).hexdigest()
            
            return provided_token == expected_token
            
        except (ValueError, IndexError):
            return False
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Проверяет CSRF токены для небезопасных методов"""
        
        # Пропускаем безопасные методы
        if request.method in self.safe_methods:
            response = await call_next(request)
            
            # Добавляем CSRF токен в cookies для GET запросов к админке
            if (request.method == 'GET' and 
                request.url.path.startswith('/admin') and 
                hasattr(request.state, 'admin_user')):
                
                session_id = request.cookies.get('session_id', secrets.token_urlsafe(32))
                csrf_token = self._generate_csrf_token(session_id)
                
                response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True)
                response.set_cookie('session_id', session_id, httponly=True, secure=True)
            
            return response
        
        # Проверяем CSRF для небезопасных методов в админке
        if request.url.path.startswith('/admin'):
            session_id = request.cookies.get('session_id')
            csrf_token = None
            
            # Получаем CSRF токен из формы или заголовка
            if request.headers.get('content-type', '').startswith('application/x-www-form-urlencoded'):
                form_data = await request.form()
                csrf_token = form_data.get('csrf_token')
            elif request.headers.get('content-type', '').startswith('application/json'):
                try:
                    json_data = await request.json()
                    csrf_token = json_data.get('csrf_token')
                except:
                    pass
            
            if not csrf_token:
                csrf_token = request.headers.get('X-CSRF-Token')
            
            if not session_id or not csrf_token or not self._verify_csrf_token(csrf_token, session_id):
                logger.warning(f"CSRF токен не прошел проверку для {request.url.path}")
                if request.url.path.startswith('/admin/api'):
                    return JSONResponse(
                        {'error': 'CSRF токен недействителен'},
                        status_code=HTTP_403_FORBIDDEN
                    )
                return JSONResponse(
                    {'error': 'CSRF токен недействителен'},
                    status_code=HTTP_403_FORBIDDEN
                )
        
        return await call_next(request)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware для ограничения частоты запросов"""
    
    def __init__(self, app, requests_per_minute: int = 60, burst_requests: int = 10):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_requests = burst_requests
        self.request_counts: Dict[str, list] = defaultdict(list)
        self.burst_counts: Dict[str, int] = defaultdict(int)
        self.burst_reset_time: Dict[str, datetime] = {}
    
    def _get_client_id(self, request: Request) -> str:
        """Получает идентификатор клиента"""
        # Используем IP адрес клиента
        client_ip = request.client.host
        
        # Для аутентифицированных пользователей добавляем username
        if hasattr(request.state, 'admin_user'):
            username = request.state.admin_user.get('username', '')
            return f"{client_ip}:{username}"
        
        return client_ip
    
    def _cleanup_old_requests(self, client_id: str, current_time: datetime):
        """Очищает старые записи запросов"""
        minute_ago = current_time - timedelta(minutes=1)
        self.request_counts[client_id] = [
            req_time for req_time in self.request_counts[client_id]
            if req_time > minute_ago
        ]
    
    def _is_rate_limited(self, client_id: str) -> tuple[bool, str]:
        """Проверяет, превышен ли лимит запросов"""
        current_time = datetime.now()
        
        # Очищаем старые записи
        self._cleanup_old_requests(client_id, current_time)
        
        # Проверяем burst лимит (кратковременные всплески)
        if client_id in self.burst_reset_time:
            if current_time - self.burst_reset_time[client_id] > timedelta(seconds=10):
                self.burst_counts[client_id] = 0
                del self.burst_reset_time[client_id]
        
        if self.burst_counts[client_id] >= self.burst_requests:
            return True, f"Превышен лимит всплесков ({self.burst_requests} запросов за 10 секунд)"
        
        # Проверяем лимит за минуту
        if len(self.request_counts[client_id]) >= self.requests_per_minute:
            return True, f"Превышен лимит ({self.requests_per_minute} запросов в минуту)"
        
        return False, ""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Проверяет лимиты запросов"""
        
        # Применяем только к админ путям
        if not request.url.path.startswith('/admin'):
            return await call_next(request)
        
        client_id = self._get_client_id(request)
        current_time = datetime.now()
        
        # Проверяем лимиты
        is_limited, reason = self._is_rate_limited(client_id)
        
        if is_limited:
            logger.warning(f"Rate limit exceeded for {client_id}: {reason}")
            return JSONResponse(
                {
                    'error': 'Превышен лимит запросов',
                    'detail': reason,
                    'retry_after': 60
                },
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                headers={'Retry-After': '60'}
            )
        
        # Записываем текущий запрос
        self.request_counts[client_id].append(current_time)
        self.burst_counts[client_id] += 1
        
        if client_id not in self.burst_reset_time:
            self.burst_reset_time[client_id] = current_time
        
        return await call_next(request)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware для добавления заголовков безопасности"""
    
    def __init__(self, app):
        super().__init__(app)
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "font-src 'self'; "
                "frame-ancestors 'none';"
            ),
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "payment=(), "
                "usb=(), "
                "magnetometer=(), "
                "gyroscope=(), "
                "speaker=()"
            )
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Добавляет заголовки безопасности"""
        response = await call_next(request)
        
        # Добавляем заголовки безопасности для админ путей
        if request.url.path.startswith('/admin'):
            for header, value in self.security_headers.items():
                response.headers[header] = value
        
        return response

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware для логирования запросов"""
    
    def __init__(self, app):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Логирует админ запросы"""
        
        if not request.url.path.startswith('/admin'):
            return await call_next(request)
        
        start_time = time.time()
        client_ip = request.client.host
        method = request.method
        path = request.url.path
        user_agent = request.headers.get('user-agent', 'Unknown')
        
        username = 'anonymous'
        if hasattr(request.state, 'admin_user'):
            username = request.state.admin_user.get('username', 'unknown')
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            logger.info(
                f"Admin Request: {method} {path} | "
                f"User: {username} | "
                f"IP: {client_ip} | "
                f"Status: {response.status_code} | "
                f"Time: {process_time:.3f}s | "
                f"UA: {user_agent[:100]}"
            )
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            
            logger.error(
                f"Admin Request Error: {method} {path} | "
                f"User: {username} | "
                f"IP: {client_ip} | "
                f"Error: {str(e)} | "
                f"Time: {process_time:.3f}s"
            )
            
            raise
