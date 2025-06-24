"""
Система аутентификации для админ-панели RemoteMCP
"""

import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class AdminUser:
    """Модель пользователя-администратора"""
    username: str
    password_hash: str
    role: str = "admin"
    is_active: bool = True
    last_login: Optional[datetime] = None
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None

class AdminAuth:
    """Класс для управления аутентификацией администраторов"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.admin_users: Dict[str, AdminUser] = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        
        # Создаем администратора по умолчанию
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Создает администратора по умолчанию"""
        default_username = "admin"
        default_password = "RemoteMCP2025!"
        
        password_hash = self._hash_password(default_password)
        self.admin_users[default_username] = AdminUser(
            username=default_username,
            password_hash=password_hash
        )
        
        logger.info(f"Создан администратор по умолчанию: {default_username}")
    
    def _hash_password(self, password: str) -> str:
        """Хеширует пароль с солью"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return f"{salt}:{password_hash.hex()}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Проверяет пароль против хеша"""
        try:
            salt, hash_value = password_hash.split(':')
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return computed_hash.hex() == hash_value
        except Exception as e:
            logger.error(f"Ошибка проверки пароля: {e}")
            return False
    
    def _is_account_locked(self, user: AdminUser) -> bool:
        """Проверяет, заблокирован ли аккаунт"""
        if user.locked_until and datetime.now() < user.locked_until:
            return True
        
        # Если блокировка истекла, сбрасываем счетчик попыток
        if user.locked_until and datetime.now() >= user.locked_until:
            user.failed_attempts = 0
            user.locked_until = None
            
        return False
    
    def _lock_account(self, user: AdminUser):
        """Блокирует аккаунт после превышения лимита попыток"""
        user.locked_until = datetime.now() + self.lockout_duration
        logger.warning(f"Аккаунт {user.username} заблокирован до {user.locked_until}")
    
    def authenticate(self, username: str, password: str, ip_address: str = None) -> Optional[str]:
        """
        Аутентификация администратора
        
        Args:
            username: Имя пользователя
            password: Пароль
            ip_address: IP адрес для логирования
            
        Returns:
            JWT токен если аутентификация успешна, иначе None
        """
        try:
            # Проверяем существование пользователя
            if username not in self.admin_users:
                logger.warning(f"Попытка входа с несуществующим пользователем: {username} from {ip_address}")
                return None
            
            user = self.admin_users[username]
            
            # Проверяем, активен ли пользователь
            if not user.is_active:
                logger.warning(f"Попытка входа с неактивным аккаунтом: {username}")
                return None
            
            # Проверяем блокировку аккаунта
            if self._is_account_locked(user):
                logger.warning(f"Попытка входа с заблокированным аккаунтом: {username}")
                return None
            
            # Проверяем пароль
            if not self._verify_password(password, user.password_hash):
                user.failed_attempts += 1
                
                if user.failed_attempts >= self.max_failed_attempts:
                    self._lock_account(user)
                
                logger.warning(f"Неверный пароль для {username} (попытка {user.failed_attempts})")
                return None
            
            # Успешная аутентификация
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login = datetime.now()
            
            # Создаем JWT токен
            token = self._create_jwt_token(username)
            
            # Сохраняем сессию
            session_id = secrets.token_urlsafe(32)
            self.active_sessions[session_id] = {
                'username': username,
                'token': token,
                'created_at': datetime.now(),
                'ip_address': ip_address,
                'last_activity': datetime.now()
            }
            
            logger.info(f"Успешная аутентификация: {username} from {ip_address}")
            return token
            
        except Exception as e:
            logger.error(f"Ошибка аутентификации: {e}")
            return None
    
    def _create_jwt_token(self, username: str) -> str:
        """Создает JWT токен для пользователя"""
        payload = {
            'username': username,
            'role': 'admin',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=8)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Проверяет JWT токен
        
        Args:
            token: JWT токен
            
        Returns:
            Payload токена если валиден, иначе None
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Проверяем, существует ли пользователь и активен ли он
            username = payload.get('username')
            if username not in self.admin_users or not self.admin_users[username].is_active:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Попытка использования истекшего токена")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Неверный токен: {e}")
            return None
        except Exception as e:
            logger.error(f"Ошибка проверки токена: {e}")
            return None
    
    def logout(self, token: str) -> bool:
        """
        Выход из системы
        
        Args:
            token: JWT токен
            
        Returns:
            True если выход успешен
        """
        try:
            # Удаляем все сессии с этим токеном
            sessions_to_remove = [
                session_id for session_id, session_data in self.active_sessions.items()
                if session_data.get('token') == token
            ]
            
            for session_id in sessions_to_remove:
                del self.active_sessions[session_id]
            
            logger.info("Пользователь вышел из системы")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка при выходе: {e}")
            return False
    
    def cleanup_expired_sessions(self):
        """Очищает истекшие сессии"""
        try:
            now = datetime.now()
            expired_sessions = []
            
            for session_id, session_data in self.active_sessions.items():
                # Удаляем сессии старше 8 часов
                if now - session_data['created_at'] > timedelta(hours=8):
                    expired_sessions.append(session_id)
                # Удаляем неактивные сессии (более 2 часов без активности)
                elif now - session_data['last_activity'] > timedelta(hours=2):
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.active_sessions[session_id]
            
            if expired_sessions:
                logger.info(f"Удалено {len(expired_sessions)} истекших сессий")
                
        except Exception as e:
            logger.error(f"Ошибка очистки сессий: {e}")
    
    def get_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Возвращает список активных сессий"""
        self.cleanup_expired_sessions()
        return self.active_sessions.copy()
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """
        Изменяет пароль пользователя
        
        Args:
            username: Имя пользователя
            old_password: Старый пароль
            new_password: Новый пароль
            
        Returns:
            True если пароль изменен успешно
        """
        try:
            if username not in self.admin_users:
                return False
            
            user = self.admin_users[username]
            
            # Проверяем старый пароль
            if not self._verify_password(old_password, user.password_hash):
                return False
            
            # Устанавливаем новый пароль
            user.password_hash = self._hash_password(new_password)
            
            logger.info(f"Пароль изменен для пользователя: {username}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка смены пароля: {e}")
            return False
