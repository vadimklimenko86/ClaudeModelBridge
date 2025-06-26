"""OAuth 2.0 Database management with PostgreSQL"""

import psycopg2
import psycopg2.extras
import time
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager


class OAuth2Database:
    """Класс для управления PostgreSQL базой данных OAuth 2.0"""

    def __init__(self,
                 db_url: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        self.db_url = db_url or os.environ.get("DATABASE_URL")
        if not self.db_url:
            raise ValueError("DATABASE_URL environment variable is required")
        self.logger = logger or logging.getLogger(__name__)
        self._init_database()

    def _init_database(self):
        """Инициализация базы данных с созданием таблиц"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Таблица клиентов OAuth2
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS oauth2_clients (
                    client_id VARCHAR(255) PRIMARY KEY,
                    client_secret TEXT NOT NULL,
                    name TEXT NOT NULL,
                    redirect_uris TEXT NOT NULL,  -- JSON array
                    grant_types TEXT NOT NULL,    -- JSON array
                    scopes TEXT DEFAULT '[]',     -- JSON array
                    created_at DOUBLE PRECISION NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL
                )
            """)

            # Таблица пользователей
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS oauth2_users (
                    user_id VARCHAR(255) PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at DOUBLE PRECISION NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL
                )
            """)

            # Таблица access токенов
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
                    token TEXT PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    client_id VARCHAR(255) NOT NULL,
                    scope TEXT NOT NULL,
                    token_type VARCHAR(50) DEFAULT 'Bearer',
                    expires_at DOUBLE PRECISION NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    is_revoked BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES oauth2_users (user_id),
                    FOREIGN KEY (client_id) REFERENCES oauth2_clients (client_id)
                )
            """)

            # Таблица refresh токенов
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
                    token TEXT PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    client_id VARCHAR(255) NOT NULL,
                    scope TEXT NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    is_revoked BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES oauth2_users (user_id),
                    FOREIGN KEY (client_id) REFERENCES oauth2_clients (client_id)
                )
            """)

            # Таблица кодов авторизации
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
                    code TEXT PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    client_id VARCHAR(255) NOT NULL,
                    scope TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    code_challenge TEXT,
                    code_challenge_method VARCHAR(50),
                    expires_at DOUBLE PRECISION NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    is_used BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES oauth2_users (user_id),
                    FOREIGN KEY (client_id) REFERENCES oauth2_clients (client_id)
                )
            """)

            # Создаем индексы для производительности
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON oauth2_access_tokens(user_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON oauth2_access_tokens(expires_at)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON oauth2_refresh_tokens(user_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON oauth2_refresh_tokens(expires_at)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON oauth2_authorization_codes(expires_at)"
            )

            conn.commit()
            self.logger.info("OAuth2 database initialized successfully")

    @contextmanager
    def _get_connection(self):
        """Контекстный менеджер для работы с подключением к БД"""
        conn = psycopg2.connect(self.db_url)
        conn.cursor_factory = psycopg2.extras.RealDictCursor  # Для доступа к колонкам по имени
        try:
            yield conn
        finally:
            conn.close()

    # === Управление клиентами ===
    def create_client(self,
                      client_id: str,
                      client_secret: str,
                      name: str,
                      redirect_uris: List[str],
                      grant_types: List[str],
                      scopes: Optional[List[str]] = None) -> bool:
        """Создание нового OAuth2 клиента"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = time.time()

                cursor.execute(
                    """
                    INSERT INTO oauth2_clients 
                    (client_id, client_secret, name, redirect_uris, grant_types, scopes, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                    (client_id, client_secret, name, json.dumps(redirect_uris),
                     json.dumps(grant_types), json.dumps(scopes
                                                         or []), now, now))
                conn.commit()
                self.logger.info(
                    f"Created OAuth2 client: {name} ({client_id})")
                return True
        except psycopg2.IntegrityError:
            self.logger.error(f"Client {client_id} already exists")
            return False

    def get_client(self, client_id: str) -> Optional[Dict]:
        """Получение клиента по ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM oauth2_clients WHERE client_id = %s",
                           (client_id, ))
            row = cursor.fetchone()

            if row:
                return {
                    'client_id': row['client_id'],
                    'client_secret': row['client_secret'],
                    'name': row['name'],
                    'redirect_uris': json.loads(row['redirect_uris']),
                    'grant_types': json.loads(row['grant_types']),
                    'scopes': json.loads(row['scopes']),
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at']
                }
            return None

    def list_clients(self) -> List[Dict]:
        """Получение списка всех клиентов"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM oauth2_clients ORDER BY created_at DESC")
            rows = cursor.fetchall()

            clients = []
            for row in rows:
                clients.append({
                    'client_id':
                    row['client_id'],
                    'client_secret':
                    row['client_secret'],
                    'name':
                    row['name'],
                    'redirect_uris':
                    json.loads(row['redirect_uris']),
                    'grant_types':
                    json.loads(row['grant_types']),
                    'scopes':
                    json.loads(row['scopes']),
                    'created_at':
                    row['created_at'],
                    'updated_at':
                    row['updated_at']
                })
            return clients

    def delete_client(self, client_id: str) -> bool:
        """Удаление клиента"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM oauth2_clients WHERE client_id = %s",
                           (client_id, ))
            conn.commit()

            if cursor.rowcount > 0:
                self.logger.info(f"Deleted OAuth2 client: {client_id}")
                return True
            return False

    # === Управление пользователями ===
    def create_user(self, user_id: str, email: str, name: str,
                    password_hash: str) -> bool:
        """Создание нового пользователя"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = time.time()

                cursor.execute(
                    """
                    INSERT INTO oauth2_users 
                    (user_id, email, name, password_hash, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (user_id, email, name, password_hash, now, now))
                conn.commit()
                self.logger.info(f"Created user: {user_id}")
                return True
        except psycopg2.IntegrityError:
            self.logger.error(
                f"User {user_id} or email {email} already exists")
            return False

    def get_user(self, user_id: str) -> Optional[Dict]:
        """Получение пользователя по ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM oauth2_users WHERE user_id = %s AND is_active = %s",
                (user_id, True))
            row = cursor.fetchone()

            if row:
                return {
                    'id': row['user_id'],
                    'user_id': row['user_id'],  # Совместимость
                    'email': row['email'],
                    'name': row['name'],
                    'password_hash': row['password_hash'],
                    'is_active': bool(row['is_active']),
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at']
                }
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Получение пользователя по email"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM oauth2_users WHERE email = %s AND is_active = %s",
                (email, True))
            row = cursor.fetchone()

            if row:
                return {
                    'id': row['user_id'],
                    'user_id': row['user_id'],
                    'email': row['email'],
                    'name': row['name'],
                    'password_hash': row['password_hash'],
                    'is_active': bool(row['is_active']),
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at']
                }
            return None

    def list_users(self) -> List[Dict]:
        """Получение списка всех активных пользователей"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM oauth2_users WHERE is_active = %s ORDER BY created_at DESC",
                (True,)
            )
            rows = cursor.fetchall()

            users = []
            for row in rows:
                users.append({
                    'id': row['user_id'],
                    'user_id': row['user_id'],
                    'email': row['email'],
                    'name': row['name'],
                    'password_hash': row['password_hash'],
                    'is_active': bool(row['is_active']),
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at']
                })
            return users

    def deactivate_user(self, user_id: str) -> bool:
        """Деактивация пользователя"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE oauth2_users SET is_active = %s, updated_at = %s WHERE user_id = %s",
                (False, time.time(), user_id))
            conn.commit()

            if cursor.rowcount > 0:
                self.logger.info(f"Deactivated user: {user_id}")
                return True
            return False

    # === Управление access токенами ===
    def save_access_token(self,
                          token: str,
                          user_id: str,
                          client_id: str,
                          scope: str,
                          expires_at: float,
                          token_type: str = 'Bearer') -> bool:
        """Сохранение access токена"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO oauth2_access_tokens 
                    (token, user_id, client_id, scope, token_type, expires_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (token, user_id, client_id, scope, token_type, expires_at,
                      time.time()))
                conn.commit()
                return True
        except psycopg2.IntegrityError:
            self.logger.error(f"Access token already exists: {token[:10]}...")
            return False

    def get_access_token(self, token: str) -> Optional[Dict]:
        """Получение access токена"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM oauth2_access_tokens 
                WHERE token = %s AND is_revoked = %s AND expires_at > %s
            """, (token, False, time.time()))
            row = cursor.fetchone()

            if row:
                return {
                    'token': row['token'],
                    'user_id': row['user_id'],
                    'client_id': row['client_id'],
                    'scope': row['scope'],
                    'token_type': row['token_type'],
                    'expires_at': row['expires_at'],
                    'created_at': row['created_at'],
                    'is_revoked': bool(row['is_revoked'])
                }
            return None

    def revoke_access_token(self, token: str) -> bool:
        """Отзыв access токена"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE oauth2_access_tokens SET is_revoked = %s WHERE token = %s",
                (True, token))
            conn.commit()
            return cursor.rowcount > 0

    # === Управление refresh токенами ===
    def save_refresh_token(self, token: str, user_id: str, client_id: str,
                           scope: str, expires_at: float) -> bool:
        """Сохранение refresh токена"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO oauth2_refresh_tokens 
                    (token, user_id, client_id, scope, expires_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (token, user_id, client_id, scope, expires_at,
                      time.time()))
                conn.commit()
                return True
        except psycopg2.IntegrityError:
            self.logger.error(f"Refresh token already exists: {token[:10]}...")
            return False

    def get_refresh_token(self, token: str) -> Optional[Dict]:
        """Получение refresh токена"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM oauth2_refresh_tokens 
                WHERE token = %s AND is_revoked = %s AND expires_at > %s
            """, (token, False, time.time()))
            row = cursor.fetchone()

            if row:
                return {
                    'token': row['token'],
                    'user_id': row['user_id'],
                    'client_id': row['client_id'],
                    'scope': row['scope'],
                    'expires_at': row['expires_at'],
                    'created_at': row['created_at'],
                    'is_revoked': bool(row['is_revoked'])
                }
            return None

    def revoke_refresh_token(self, token: str) -> bool:
        """Отзыв refresh токена"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE oauth2_refresh_tokens SET is_revoked = %s WHERE token = %s",
                (True, token))
            conn.commit()
            return cursor.rowcount > 0

    # === Управление кодами авторизации ===
    def save_authorization_code(self,
                                code: str,
                                user_id: str,
                                client_id: str,
                                scope: str,
                                redirect_uri: str,
                                expires_at: float,
                                code_challenge: Optional[str] = None,
                                code_challenge_method: Optional[str] = None) -> bool:
        """Сохранение кода авторизации"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO oauth2_authorization_codes 
                    (code, user_id, client_id, scope, redirect_uri, code_challenge, 
                     code_challenge_method, expires_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (code, user_id, client_id, scope, redirect_uri,
                      code_challenge, code_challenge_method, expires_at,
                      time.time()))
                conn.commit()
                return True
        except psycopg2.IntegrityError:
            self.logger.error(
                f"Authorization code already exists: {code[:10]}...")
            return False

    def get_authorization_code(self, code: str) -> Optional[Dict]:
        """Получение кода авторизации"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM oauth2_authorization_codes 
                WHERE code = %s AND is_used = %s AND expires_at > %s
            """, (code, False, time.time()))
            row = cursor.fetchone()

            if row:
                return {
                    'code': row['code'],
                    'user_id': row['user_id'],
                    'client_id': row['client_id'],
                    'scope': row['scope'],
                    'redirect_uri': row['redirect_uri'],
                    'code_challenge': row['code_challenge'],
                    'code_challenge_method': row['code_challenge_method'],
                    'expires_at': row['expires_at'],
                    'created_at': row['created_at'],
                    'is_used': bool(row['is_used'])
                }
            return None

    def use_authorization_code(self, code: str) -> bool:
        """Пометить код авторизации как использованный"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE oauth2_authorization_codes SET is_used = %s WHERE code = %s",
                (True, code))
            conn.commit()
            return cursor.rowcount > 0

    # === Служебные методы ===
    def revoke_all_user_tokens(self, user_id: str) -> int:
        """Отзыв всех токенов пользователя"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Отзываем access токены
            cursor.execute(
                "UPDATE oauth2_access_tokens SET is_revoked = %s WHERE user_id = %s AND is_revoked = %s",
                (True, user_id, False))
            access_count = cursor.rowcount

            # Отзываем refresh токены
            cursor.execute(
                "UPDATE oauth2_refresh_tokens SET is_revoked = %s WHERE user_id = %s AND is_revoked = %s",
                (True, user_id, False))
            refresh_count = cursor.rowcount

            conn.commit()
            total_revoked = access_count + refresh_count

            if total_revoked > 0:
                self.logger.info(
                    f"Revoked {total_revoked} tokens for user: {user_id}")

            return total_revoked

    def cleanup_expired_tokens(self) -> int:
        """Очистка истекших токенов"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            current_time = time.time()

            # Удаляем истекшие access токены
            cursor.execute(
                "DELETE FROM oauth2_access_tokens WHERE expires_at <= %s",
                (current_time, ))
            access_deleted = cursor.rowcount

            # Удаляем истекшие refresh токены
            cursor.execute(
                "DELETE FROM oauth2_refresh_tokens WHERE expires_at <= %s",
                (current_time, ))
            refresh_deleted = cursor.rowcount

            # Удаляем истекшие коды авторизации
            cursor.execute(
                "DELETE FROM oauth2_authorization_codes WHERE expires_at <= %s",
                (current_time, ))
            codes_deleted = cursor.rowcount

            conn.commit()
            total_deleted = access_deleted + refresh_deleted + codes_deleted

            if total_deleted > 0:
                self.logger.info(f"Cleaned up {total_deleted} expired entries")

            return total_deleted

    def get_stats(self) -> Dict:
        """Получение статистики базы данных"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            current_time = time.time()

            # Подсчет клиентов
            cursor.execute("SELECT COUNT(*) FROM oauth2_clients")
            clients_count = cursor.fetchone()[0]

            # Подсчет пользователей
            cursor.execute(
                "SELECT COUNT(*) FROM oauth2_users WHERE is_active = %s",
                (True,))
            active_users = cursor.fetchone()[0]

            # Подсчет активных access токенов
            cursor.execute(
                "SELECT COUNT(*) FROM oauth2_access_tokens WHERE is_revoked = %s AND expires_at > %s",
                (False, current_time))
            active_access_tokens = cursor.fetchone()[0]

            # Подсчет активных refresh токенов
            cursor.execute(
                "SELECT COUNT(*) FROM oauth2_refresh_tokens WHERE is_revoked = %s AND expires_at > %s",
                (False, current_time))
            active_refresh_tokens = cursor.fetchone()[0]

            # Подсчет активных кодов авторизации
            cursor.execute(
                "SELECT COUNT(*) FROM oauth2_authorization_codes WHERE is_used = %s AND expires_at > %s",
                (False, current_time))
            active_auth_codes = cursor.fetchone()[0]

            return {
                'clients_count': clients_count,
                'active_users': active_users,
                'active_access_tokens': active_access_tokens,
                'active_refresh_tokens': active_refresh_tokens,
                'active_authorization_codes': active_auth_codes,
                'timestamp': current_time
            }