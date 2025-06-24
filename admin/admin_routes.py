"""
Маршруты для админ-панели RemoteMCP
"""

from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_302_FOUND, HTTP_400_BAD_REQUEST
from typing import Optional, Dict, Any
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class AdminRoutes:
    """Класс для управления маршрутами админ-панели"""
    
    def __init__(self, admin_auth, admin_api):
        self.admin_auth = admin_auth
        self.admin_api = admin_api
        self.router = APIRouter(prefix="/admin", tags=["admin"])
        self.templates = Jinja2Templates(directory="templates")
        
        # Регистрируем маршруты
        self._register_routes()
    
    def _register_routes(self):
        """Регистрирует все маршруты админ-панели"""
        
        # Страницы
        self.router.add_api_route("/", self.dashboard, methods=["GET"], response_class=HTMLResponse)
        self.router.add_api_route("/login", self.login_page, methods=["GET"], response_class=HTMLResponse)
        self.router.add_api_route("/login", self.login_post, methods=["POST"])
        self.router.add_api_route("/logout", self.logout, methods=["POST"])
        self.router.add_api_route("/tools", self.tools_page, methods=["GET"], response_class=HTMLResponse)
        self.router.add_api_route("/users", self.users_page, methods=["GET"], response_class=HTMLResponse)
        self.router.add_api_route("/logs", self.logs_page, methods=["GET"], response_class=HTMLResponse)
        self.router.add_api_route("/settings", self.settings_page, methods=["GET"], response_class=HTMLResponse)
        self.router.add_api_route("/monitoring", self.monitoring_page, methods=["GET"], response_class=HTMLResponse)
        
        # Настройки и действия
        self.router.add_api_route("/change-password", self.change_password, methods=["POST"])
    
    async def dashboard(self, request: Request):
        """Главная страница админ-панели"""
        try:
            # Получаем статистику системы
            stats = await self.admin_api.get_system_stats()
            
            # Получаем последние события
            recent_events = await self.admin_api.get_recent_events(limit=10)
            
            # Получаем активные сессии
            active_sessions = self.admin_auth.get_active_sessions()
            
            context = {
                "request": request,
                "user": request.state.admin_user,
                "stats": stats,
                "recent_events": recent_events,
                "active_sessions_count": len(active_sessions),
                "page_title": "Главная панель"
            }
            
            return self.templates.TemplateResponse("admin/dashboard.html", context)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки главной страницы: {e}")
            raise HTTPException(status_code=500, detail="Ошибка загрузки страницы")
    
    async def login_page(self, request: Request):
        """Страница входа"""
        # Если пользователь уже аутентифицирован, перенаправляем на главную
        token = request.cookies.get('admin_token')
        if token and self.admin_auth.verify_token(token):
            return RedirectResponse("/admin/", status_code=HTTP_302_FOUND)
        
        context = {
            "request": request,
            "page_title": "Вход в админ-панель"
        }
        
        return self.templates.TemplateResponse("admin/login.html", context)
    
    async def login_post(self, request: Request):
        """Обработка формы входа"""
        try:
            form_data = await request.form()
            username = form_data.get("username", "").strip()
            password = form_data.get("password", "")
            
            if not username or not password:
                context = {
                    "request": request,
                    "error": "Введите имя пользователя и пароль",
                    "page_title": "Вход в админ-панель"
                }
                return self.templates.TemplateResponse("admin/login.html", context)
            
            # Получаем IP адрес
            client_ip = request.client.host
            if "x-forwarded-for" in request.headers:
                client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
            
            # Аутентификация
            token = self.admin_auth.authenticate(username, password, client_ip)
            
            if not token:
                context = {
                    "request": request,
                    "error": "Неверное имя пользователя или пароль",
                    "username": username,
                    "page_title": "Вход в админ-панель"
                }
                return self.templates.TemplateResponse("admin/login.html", context)
            
            # Создаем ответ с перенаправлением
            response = RedirectResponse("/admin/", status_code=HTTP_302_FOUND)
            
            # Устанавливаем токен в cookie
            response.set_cookie(
                "admin_token",
                token,
                max_age=8 * 3600,  # 8 часов
                httponly=True,
                secure=True,
                samesite="strict"
            )
            
            logger.info(f"Успешный вход: {username} from {client_ip}")
            return response
            
        except Exception as e:
            logger.error(f"Ошибка при входе: {e}")
            context = {
                "request": request,
                "error": "Внутренняя ошибка сервера",
                "page_title": "Вход в админ-панель"
            }
            return self.templates.TemplateResponse("admin/login.html", context)
    
    async def logout(self, request: Request):
        """Выход из системы"""
        try:
            token = request.state.admin_token
            self.admin_auth.logout(token)
            
            response = RedirectResponse("/admin/login", status_code=HTTP_302_FOUND)
            response.delete_cookie("admin_token")
            
            logger.info("Пользователь вышел из системы")
            return response
            
        except Exception as e:
            logger.error(f"Ошибка при выходе: {e}")
            return RedirectResponse("/admin/login", status_code=HTTP_302_FOUND)
    
    async def tools_page(self, request: Request):
        """Страница управления инструментами"""
        try:
            # Получаем список всех инструментов
            tools = await self.admin_api.get_tools_list()
            
            # Получаем статистику использования
            tools_stats = await self.admin_api.get_tools_usage_stats()
            
            context = {
                "request": request,
                "user": request.state.admin_user,
                "tools": tools,
                "tools_stats": tools_stats,
                "page_title": "Управление инструментами"
            }
            
            return self.templates.TemplateResponse("admin/tools.html", context)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки страницы инструментов: {e}")
            raise HTTPException(status_code=500, detail="Ошибка загрузки страницы")
    
    async def users_page(self, request: Request):
        """Страница управления пользователями"""
        try:
            # Получаем активные сессии
            active_sessions = self.admin_auth.get_active_sessions()
            
            # Получаем статистику пользователей
            user_stats = await self.admin_api.get_user_stats()
            
            context = {
                "request": request,
                "user": request.state.admin_user,
                "active_sessions": active_sessions,
                "user_stats": user_stats,
                "page_title": "Управление пользователями"
            }
            
            return self.templates.TemplateResponse("admin/users.html", context)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки страницы пользователей: {e}")
            raise HTTPException(status_code=500, detail="Ошибка загрузки страницы")
    
    async def logs_page(self, request: Request):
        """Страница просмотра логов"""
        try:
            # Получаем параметры фильтрации
            level = request.query_params.get("level", "all")
            limit = int(request.query_params.get("limit", "100"))
            search = request.query_params.get("search", "")
            
            # Получаем логи
            logs = await self.admin_api.get_logs(level=level, limit=limit, search=search)
            
            context = {
                "request": request,
                "user": request.state.admin_user,
                "logs": logs,
                "current_level": level,
                "current_limit": limit,
                "current_search": search,
                "page_title": "Просмотр логов"
            }
            
            return self.templates.TemplateResponse("admin/logs.html", context)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки страницы логов: {e}")
            raise HTTPException(status_code=500, detail="Ошибка загрузки страницы")
    
    async def settings_page(self, request: Request):
        """Страница настроек"""
        try:
            # Получаем текущие настройки
            settings = await self.admin_api.get_settings()
            
            context = {
                "request": request,
                "user": request.state.admin_user,
                "settings": settings,
                "page_title": "Настройки системы"
            }
            
            return self.templates.TemplateResponse("admin/settings.html", context)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки страницы настроек: {e}")
            raise HTTPException(status_code=500, detail="Ошибка загрузки страницы")
    
    async def monitoring_page(self, request: Request):
        """Страница мониторинга"""
        try:
            # Получаем метрики системы
            metrics = await self.admin_api.get_system_metrics()
            
            # Получаем историю производительности
            performance_history = await self.admin_api.get_performance_history()
            
            context = {
                "request": request,
                "user": request.state.admin_user,
                "metrics": metrics,
                "performance_history": performance_history,
                "page_title": "Мониторинг системы"
            }
            
            return self.templates.TemplateResponse("admin/monitoring.html", context)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки страницы мониторинга: {e}")
            raise HTTPException(status_code=500, detail="Ошибка загрузки страницы")
    
    async def change_password(self, request: Request):
        """Смена пароля"""
        try:
            form_data = await request.form()
            current_password = form_data.get("current_password", "")
            new_password = form_data.get("new_password", "")
            confirm_password = form_data.get("confirm_password", "")
            
            # Валидация
            if not all([current_password, new_password, confirm_password]):
                return JSONResponse(
                    {"success": False, "error": "Все поля обязательны"},
                    status_code=HTTP_400_BAD_REQUEST
                )
            
            if new_password != confirm_password:
                return JSONResponse(
                    {"success": False, "error": "Пароли не совпадают"},
                    status_code=HTTP_400_BAD_REQUEST
                )
            
            if len(new_password) < 8:
                return JSONResponse(
                    {"success": False, "error": "Пароль должен содержать минимум 8 символов"},
                    status_code=HTTP_400_BAD_REQUEST
                )
            
            # Смена пароля
            username = request.state.admin_user.get("username")
            success = self.admin_auth.change_password(username, current_password, new_password)
            
            if not success:
                return JSONResponse(
                    {"success": False, "error": "Неверный текущий пароль"},
                    status_code=HTTP_400_BAD_REQUEST
                )
            
            logger.info(f"Пароль изменен для пользователя: {username}")
            return JSONResponse({"success": True, "message": "Пароль успешно изменен"})
            
        except Exception as e:
            logger.error(f"Ошибка смены пароля: {e}")
            return JSONResponse(
                {"success": False, "error": "Внутренняя ошибка сервера"},
                status_code=500
            )
    
    def get_router(self) -> APIRouter:
        """Возвращает настроенный роутер"""
        return self.router
