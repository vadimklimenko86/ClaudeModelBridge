from MCP_Tools import MCP_Tools
import mcp.types as types
import datetime
import os
import logging
import json
import subprocess
import re
import socket
import threading
import time
from typing import Dict, Callable, Annotated, List, Optional, Tuple
from pathlib import Path


class SSHTools:

    def __init__(self, mcp: MCP_Tools) -> None:
        # Настройка часового пояса и рабочей директории
        self.tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))
        self.working_dir = "Data"  # "."
        self.log_file = os.path.join("Tools", "ssh.log")
        self.ssh_config_dir = os.path.join(self.working_dir, ".ssh")
        self.active_connections = {}  # Хранение активных подключений
        self.active_tunnels = {}  # Хранение активных туннелей

        # Создание рабочей директории и SSH конфигурации
        if not self.working_dir == None:
            os.makedirs(self.working_dir, exist_ok=True)
            os.makedirs(self.ssh_config_dir, exist_ok=True)

        # Настройка логирования
        self._setup_logging()

        # Регистрация инструментов
        self._register_tools(mcp)

        self.logger.info("SSHTools initialized")

    def _setup_logging(self):
        """Настройка системы логирования"""
        self.logger = logging.getLogger('SSHTools')
        self.logger.setLevel(logging.INFO)

        # Очистка существующих handlers
        if self.logger.handlers:
            self.logger.handlers.clear()

        # Форматтер для логов
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S')

        # Handler для записи в файл
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        # Установка часового пояса для логов
        logging.Formatter.converter = lambda *args: datetime.datetime.now(
            self.tz_plus3).timetuple()

    def _validate_host(self, host: str) -> str:
        """
        Валидация хоста
        
        Args:
            host: Хост для валидации
            
        Returns:
            str: Валидный хост
            
        Raises:
            ValueError: При невалидном хосте
        """
        if not host:
            raise ValueError("Хост не может быть пустым")

        host = host.strip()
        
        # Проверка на недопустимые символы
        if any(char in host for char in ['<', '>', '|', '&', ';', '`', '$']):
            raise ValueError("Хост содержит недопустимые символы")
            
        # Простая проверка формата (IP или домен)
        if not re.match(r'^[a-zA-Z0-9.-]+$', host):
            raise ValueError("Неверный формат хоста")
            
        return host

    def _validate_port(self, port: int) -> int:
        """Валидация порта"""
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError("Порт должен быть числом от 1 до 65535")
        return port

    def _validate_username(self, username: str) -> str:
        """Валидация имени пользователя"""
        if not username:
            raise ValueError("Имя пользователя не может быть пустым")
            
        username = username.strip()
        
        # Проверка на недопустимые символы
        if any(char in username for char in ['<', '>', '|', '&', ';', '`', '$', ' ']):
            raise ValueError("Имя пользователя содержит недопустимые символы")
            
        return username

    def _run_ssh_command(self, command: List[str], timeout: int = 30, input_data: str = None) -> Tuple[bool, str, str]:
        """
        Выполнить SSH команду
        
        Args:
            command: Список аргументов команды
            timeout: Тайм-аут выполнения
            input_data: Данные для ввода
            
        Returns:
            tuple: (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=timeout,
                input=input_data
            )
            
            success = result.returncode == 0
            return success, result.stdout.strip(), result.stderr.strip()
            
        except subprocess.TimeoutExpired:
            return False, "", f"Команда превысила лимит времени выполнения ({timeout} сек)"
        except FileNotFoundError:
            return False, "", "SSH не установлен или не найден в PATH"
        except Exception as e:
            return False, "", f"Ошибка выполнения команды: {str(e)}"

    def _get_connection_key(self, host: str, port: int, username: str) -> str:
        """Получить ключ для идентификации подключения"""
        return f"{username}@{host}:{port}"

    def _register_tools(self, mcp: MCP_Tools):
        """Регистрация всех инструментов"""

        @mcp.register_tool(name="ssh_connect", description="Подключиться к SSH серверу")
        def ssh_connect(
            host: Annotated[str, "Хост для подключения"],
            username: Annotated[str, "Имя пользователя"],
            port: Annotated[int, "Порт SSH"] = 22,
            key_file: Annotated[str, "Путь к файлу ключа (опционально)"] = "",
            password_auth: Annotated[bool, "Использовать аутентификацию по паролю"] = False
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                validated_host = self._validate_host(host)
                validated_port = self._validate_port(port)
                validated_username = self._validate_username(username)
                
                connection_key = self._get_connection_key(validated_host, validated_port, validated_username)
                
                # Подготовка команды подключения
                command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
                
                if key_file:
                    key_path = os.path.join(self.ssh_config_dir, key_file)
                    if os.path.exists(key_path):
                        command.extend(['-i', key_path])
                    else:
                        return [types.TextContent(type="text", text=f"❌ Файл ключа не найден: {key_file}")]
                
                command.extend(['-p', str(validated_port)])
                command.append(f"{validated_username}@{validated_host}")
                command.append('echo "SSH connection test successful"')
                
                success, stdout, stderr = self._run_ssh_command(command, timeout=15)
                
                if success:
                    self.active_connections[connection_key] = {
                        'host': validated_host,
                        'port': validated_port,
                        'username': validated_username,
                        'key_file': key_file,
                        'connected_at': datetime.datetime.now(self.tz_plus3)
                    }
                    
                    result = f"✅ Успешное подключение к {connection_key}\n{stdout}"
                    self.logger.info(f"SSH connection successful: {connection_key}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка подключения к {connection_key}: {stderr}"
                    self.logger.error(f"SSH connection failed: {connection_key} - {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при подключении: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_execute", description="Выполнить команду на удаленном сервере")
        def ssh_execute(
            host: Annotated[str, "Хост для подключения"],
            username: Annotated[str, "Имя пользователя"],
            command: Annotated[str, "Команда для выполнения"],
            port: Annotated[int, "Порт SSH"] = 22,
            key_file: Annotated[str, "Путь к файлу ключа (опционально)"] = "",
            timeout: Annotated[int, "Тайм-аут выполнения в секундах"] = 30
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                validated_host = self._validate_host(host)
                validated_port = self._validate_port(port)
                validated_username = self._validate_username(username)
                
                # Проверка безопасности команды
                dangerous_patterns = ['rm -rf /', 'mkfs', 'dd if=', ':(){ :|:& };:', 'shutdown', 'reboot', 'halt']
                if any(pattern in command for pattern in dangerous_patterns):
                    return [types.TextContent(type="text", text="❌ Команда заблокирована по соображениям безопасности")]
                
                connection_key = self._get_connection_key(validated_host, validated_port, validated_username)
                
                # Подготовка SSH команды
                ssh_command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
                
                if key_file:
                    key_path = os.path.join(self.ssh_config_dir, key_file)
                    if os.path.exists(key_path):
                        ssh_command.extend(['-i', key_path])
                    else:
                        return [types.TextContent(type="text", text=f"❌ Файл ключа не найден: {key_file}")]
                
                ssh_command.extend(['-p', str(validated_port)])
                ssh_command.append(f"{validated_username}@{validated_host}")
                ssh_command.append(command)
                
                success, stdout, stderr = self._run_ssh_command(ssh_command, timeout=timeout)
                
                if success:
                    result = f"✅ Команда выполнена на {connection_key}:\n📝 Команда: {command}\n📤 Результат:\n{stdout}"
                    if stderr:
                        result += f"\n⚠️ Предупреждения:\n{stderr}"
                    self.logger.info(f"SSH command executed on {connection_key}: {command}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка выполнения команды на {connection_key}: {stderr}"
                    self.logger.error(f"SSH command failed on {connection_key}: {command} - {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при выполнении команды: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_copy", description="Копировать файлы через SCP")
        def ssh_copy(
            host: Annotated[str, "Хост для подключения"],
            username: Annotated[str, "Имя пользователя"],
            source: Annotated[str, "Исходный путь"],
            destination: Annotated[str, "Путь назначения"],
            direction: Annotated[str, "Направление: upload (на сервер) или download (с сервера)"] = "upload",
            port: Annotated[int, "Порт SSH"] = 22,
            key_file: Annotated[str, "Путь к файлу ключа (опционально)"] = "",
            recursive: Annotated[bool, "Рекурсивное копирование директорий"] = False
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                validated_host = self._validate_host(host)
                validated_port = self._validate_port(port)
                validated_username = self._validate_username(username)
                
                connection_key = self._get_connection_key(validated_host, validated_port, validated_username)
                
                # Подготовка SCP команды
                scp_command = ['scp', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
                
                if key_file:
                    key_path = os.path.join(self.ssh_config_dir, key_file)
                    if os.path.exists(key_path):
                        scp_command.extend(['-i', key_path])
                    else:
                        return [types.TextContent(type="text", text=f"❌ Файл ключа не найден: {key_file}")]
                
                scp_command.extend(['-P', str(validated_port)])
                
                if recursive:
                    scp_command.append('-r')
                
                # Определение источника и назначения
                if direction == "upload":
                    # Загрузка на сервер
                    local_path = os.path.join(self.working_dir, source)
                    if not os.path.exists(local_path):
                        return [types.TextContent(type="text", text=f"❌ Локальный файл не найден: {source}")]
                    
                    scp_command.append(local_path)
                    scp_command.append(f"{validated_username}@{validated_host}:{destination}")
                    
                elif direction == "download":
                    # Скачивание с сервера
                    local_path = os.path.join(self.working_dir, destination)
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    
                    scp_command.append(f"{validated_username}@{validated_host}:{source}")
                    scp_command.append(local_path)
                else:
                    return [types.TextContent(type="text", text="❌ Направление должно быть 'upload' или 'download'")]
                
                success, stdout, stderr = self._run_ssh_command(scp_command, timeout=120)
                
                if success:
                    result = f"✅ Файлы скопированы ({direction}) для {connection_key}:\n📁 {source} → {destination}"
                    if stdout:
                        result += f"\n📤 Результат:\n{stdout}"
                    self.logger.info(f"SCP {direction} successful: {connection_key} - {source} → {destination}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка копирования файлов для {connection_key}: {stderr}"
                    self.logger.error(f"SCP {direction} failed: {connection_key} - {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при копировании файлов: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_keygen", description="Генерировать SSH ключи")
        def ssh_keygen(
            key_name: Annotated[str, "Имя ключа"],
            key_type: Annotated[str, "Тип ключа: rsa, ed25519, ecdsa"] = "ed25519",
            key_size: Annotated[int, "Размер ключа (для RSA)"] = 4096,
            comment: Annotated[str, "Комментарий к ключу"] = ""
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                if not key_name:
                    return [types.TextContent(type="text", text="❌ Необходимо указать имя ключа")]
                
                # Валидация имени ключа
                if not re.match(r'^[a-zA-Z0-9_-]+$', key_name):
                    return [types.TextContent(type="text", text="❌ Имя ключа может содержать только буквы, цифры, _ и -")]
                
                key_path = os.path.join(self.ssh_config_dir, key_name)
                
                # Проверка существования ключа
                if os.path.exists(key_path) or os.path.exists(f"{key_path}.pub"):
                    return [types.TextContent(type="text", text=f"❌ Ключ с именем '{key_name}' уже существует")]
                
                # Подготовка команды генерации ключа
                keygen_command = ['ssh-keygen', '-t', key_type, '-f', key_path, '-N', '']
                
                if key_type == 'rsa':
                    keygen_command.extend(['-b', str(key_size)])
                
                if comment:
                    keygen_command.extend(['-C', comment])
                
                success, stdout, stderr = self._run_ssh_command(keygen_command, timeout=30)
                
                if success:
                    # Чтение публичного ключа
                    try:
                        with open(f"{key_path}.pub", 'r') as f:
                            public_key = f.read().strip()
                        
                        result = f"✅ SSH ключ '{key_name}' успешно создан\n"
                        result += f"🔐 Тип: {key_type}"
                        if key_type == 'rsa':
                            result += f" ({key_size} бит)"
                        result += f"\n📁 Приватный ключ: {key_name}\n📁 Публичный ключ: {key_name}.pub\n"
                        result += f"🔑 Публичный ключ:\n{public_key}"
                        
                        self.logger.info(f"SSH key generated: {key_name} ({key_type})")
                        return [types.TextContent(type="text", text=result)]
                    except Exception as e:
                        return [types.TextContent(type="text", text=f"❌ Ключ создан, но ошибка чтения публичного ключа: {str(e)}")]
                else:
                    error_msg = f"❌ Ошибка генерации ключа: {stderr}"
                    self.logger.error(f"SSH keygen failed: {key_name} - {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except Exception as e:
                error_msg = f"Ошибка при генерации ключа: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_keys", description="Управление SSH ключами")
        def ssh_keys(
            action: Annotated[str, "Действие: list, delete, show"],
            key_name: Annotated[str, "Имя ключа (для delete, show)"] = ""
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                if action == "list":
                    # Список всех ключей
                    keys = []
                    for file in os.listdir(self.ssh_config_dir):
                        if file.endswith('.pub'):
                            key_name = file[:-4]  # Убираем .pub
                            private_key_path = os.path.join(self.ssh_config_dir, key_name)
                            if os.path.exists(private_key_path):
                                # Получаем информацию о ключе
                                try:
                                    result = subprocess.run(
                                        ['ssh-keygen', '-l', '-f', private_key_path],
                                        capture_output=True, text=True, timeout=10
                                    )
                                    if result.returncode == 0:
                                        key_info = result.stdout.strip()
                                        keys.append(f"🔑 {key_name}: {key_info}")
                                    else:
                                        keys.append(f"🔑 {key_name}: (не удалось получить информацию)")
                                except:
                                    keys.append(f"🔑 {key_name}: (ошибка чтения)")
                    
                    if keys:
                        result = "🔐 Список SSH ключей:\n" + "\n".join(keys)
                    else:
                        result = "🔐 SSH ключи не найдены"
                    
                    return [types.TextContent(type="text", text=result)]
                
                elif action == "delete":
                    if not key_name:
                        return [types.TextContent(type="text", text="❌ Необходимо указать имя ключа")]
                    
                    private_key_path = os.path.join(self.ssh_config_dir, key_name)
                    public_key_path = f"{private_key_path}.pub"
                    
                    deleted_files = []
                    if os.path.exists(private_key_path):
                        os.remove(private_key_path)
                        deleted_files.append("приватный ключ")
                    
                    if os.path.exists(public_key_path):
                        os.remove(public_key_path)
                        deleted_files.append("публичный ключ")
                    
                    if deleted_files:
                        result = f"✅ Ключ '{key_name}' удален ({', '.join(deleted_files)})"
                        self.logger.info(f"SSH key deleted: {key_name}")
                    else:
                        result = f"❌ Ключ '{key_name}' не найден"
                    
                    return [types.TextContent(type="text", text=result)]
                
                elif action == "show":
                    if not key_name:
                        return [types.TextContent(type="text", text="❌ Необходимо указать имя ключа")]
                    
                    public_key_path = os.path.join(self.ssh_config_dir, f"{key_name}.pub")
                    
                    if not os.path.exists(public_key_path):
                        return [types.TextContent(type="text", text=f"❌ Публичный ключ '{key_name}' не найден")]
                    
                    try:
                        with open(public_key_path, 'r') as f:
                            public_key = f.read().strip()
                        
                        result = f"🔑 Публичный ключ '{key_name}':\n{public_key}"
                        return [types.TextContent(type="text", text=result)]
                    except Exception as e:
                        return [types.TextContent(type="text", text=f"❌ Ошибка чтения ключа: {str(e)}")]
                
                else:
                    return [types.TextContent(type="text", text="❌ Неизвестное действие. Используйте: list, delete, show")]
                    
            except Exception as e:
                error_msg = f"Ошибка при управлении ключами: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_tunnel", description="Создать SSH туннель")
        def ssh_tunnel(
            host: Annotated[str, "Хост для подключения"],
            username: Annotated[str, "Имя пользователя"],
            local_port: Annotated[int, "Локальный порт"],
            remote_host: Annotated[str, "Удаленный хост для туннелирования"],
            remote_port: Annotated[int, "Удаленный порт"],
            action: Annotated[str, "Действие: create, stop, list"] = "create",
            ssh_port: Annotated[int, "Порт SSH"] = 22,
            key_file: Annotated[str, "Путь к файлу ключа (опционально)"] = ""
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                if action == "list":
                    if not self.active_tunnels:
                        return [types.TextContent(type="text", text="🔌 Активные туннели отсутствуют")]
                    
                    result = "🔌 Активные SSH туннели:\n"
                    for tunnel_id, tunnel_info in self.active_tunnels.items():
                        result += f"🌐 {tunnel_id}: {tunnel_info['local_port']} → {tunnel_info['remote_host']}:{tunnel_info['remote_port']}\n"
                        result += f"   Создан: {tunnel_info['created_at'].strftime('%Y-%m-%d %H:%M:%S')}\n"
                    
                    return [types.TextContent(type="text", text=result)]
                
                validated_host = self._validate_host(host)
                validated_ssh_port = self._validate_port(ssh_port)
                validated_username = self._validate_username(username)
                validated_local_port = self._validate_port(local_port)
                validated_remote_port = self._validate_port(remote_port)
                validated_remote_host = self._validate_host(remote_host)
                
                tunnel_id = f"{validated_username}@{validated_host}:{validated_local_port}→{validated_remote_host}:{validated_remote_port}"
                
                if action == "create":
                    # Проверка, что туннель не существует
                    if tunnel_id in self.active_tunnels:
                        return [types.TextContent(type="text", text=f"❌ Туннель уже существует: {tunnel_id}")]
                    
                    # Проверка доступности локального порта
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.bind(('localhost', validated_local_port))
                        sock.close()
                    except OSError:
                        return [types.TextContent(type="text", text=f"❌ Локальный порт {validated_local_port} уже используется")]
                    
                    # Подготовка SSH команды для туннеля
                    tunnel_command = [
                        'ssh', '-N', '-L', f"{validated_local_port}:{validated_remote_host}:{validated_remote_port}",
                        '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'
                    ]
                    
                    if key_file:
                        key_path = os.path.join(self.ssh_config_dir, key_file)
                        if os.path.exists(key_path):
                            tunnel_command.extend(['-i', key_path])
                        else:
                            return [types.TextContent(type="text", text=f"❌ Файл ключа не найден: {key_file}")]
                    
                    tunnel_command.extend(['-p', str(validated_ssh_port)])
                    tunnel_command.append(f"{validated_username}@{validated_host}")
                    
                    # Запуск туннеля в отдельном процессе
                    try:
                        process = subprocess.Popen(
                            tunnel_command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        
                        # Ждем немного для проверки успешности запуска
                        time.sleep(2)
                        
                        if process.poll() is None:  # Процесс все еще работает
                            self.active_tunnels[tunnel_id] = {
                                'process': process,
                                'local_port': validated_local_port,
                                'remote_host': validated_remote_host,
                                'remote_port': validated_remote_port,
                                'ssh_host': validated_host,
                                'ssh_port': validated_ssh_port,
                                'username': validated_username,
                                'created_at': datetime.datetime.now(self.tz_plus3)
                            }
                            
                            result = f"✅ SSH туннель создан: {tunnel_id}\n"
                            result += f"🔌 Локальный порт {validated_local_port} перенаправлен на {validated_remote_host}:{validated_remote_port}"
                            self.logger.info(f"SSH tunnel created: {tunnel_id}")
                            return [types.TextContent(type="text", text=result)]
                        else:
                            stderr = process.stderr.read()
                            error_msg = f"❌ Ошибка создания туннеля: {stderr}"
                            return [types.TextContent(type="text", text=error_msg)]
                            
                    except Exception as e:
                        error_msg = f"❌ Ошибка запуска туннеля: {str(e)}"
                        return [types.TextContent(type="text", text=error_msg)]
                
                elif action == "stop":
                    if tunnel_id not in self.active_tunnels:
                        return [types.TextContent(type="text", text=f"❌ Туннель не найден: {tunnel_id}")]
                    
                    tunnel_info = self.active_tunnels[tunnel_id]
                    process = tunnel_info['process']
                    
                    try:
                        process.terminate()
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    
                    del self.active_tunnels[tunnel_id]
                    
                    result = f"✅ SSH туннель остановлен: {tunnel_id}"
                    self.logger.info(f"SSH tunnel stopped: {tunnel_id}")
                    return [types.TextContent(type="text", text=result)]
                
                else:
                    return [types.TextContent(type="text", text="❌ Неизвестное действие. Используйте: create, stop, list")]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при работе с туннелем: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_config", description="Управление SSH конфигурацией")
        def ssh_config(
            action: Annotated[str, "Действие: show, add_host, remove_host"],
            host_alias: Annotated[str, "Псевдоним хоста"] = "",
            hostname: Annotated[str, "Реальный адрес хоста"] = "",
            username: Annotated[str, "Имя пользователя"] = "",
            port: Annotated[int, "Порт"] = 22,
            key_file: Annotated[str, "Файл ключа"] = ""
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                config_file = os.path.join(self.ssh_config_dir, "config")
                
                if action == "show":
                    if os.path.exists(config_file):
                        with open(config_file, 'r') as f:
                            config_content = f.read()
                        
                        result = f"📋 SSH конфигурация:\n{config_content}"
                    else:
                        result = "📋 SSH конфигурация не найдена"
                    
                    return [types.TextContent(type="text", text=result)]
                
                elif action == "add_host":
                    if not all([host_alias, hostname, username]):
                        return [types.TextContent(type="text", text="❌ Необходимо указать псевдоним, хост и пользователя")]
                    
                    # Создание записи конфигурации
                    config_entry = f"\nHost {host_alias}\n"
                    config_entry += f"    HostName {hostname}\n"
                    config_entry += f"    User {username}\n"
                    config_entry += f"    Port {port}\n"
                    
                    if key_file:
                        key_path = os.path.join(self.ssh_config_dir, key_file)
                        config_entry += f"    IdentityFile {key_path}\n"
                    
                    config_entry += "    BatchMode yes\n"
                    config_entry += "    ConnectTimeout 10\n\n"
                    
                    # Добавление в конфигурационный файл
                    with open(config_file, 'a') as f:
                        f.write(config_entry)
                    
                    result = f"✅ Хост '{host_alias}' добавлен в SSH конфигурацию"
                    self.logger.info(f"SSH config host added: {host_alias}")
                    return [types.TextContent(type="text", text=result)]
                
                elif action == "remove_host":
                    if not host_alias:
                        return [types.TextContent(type="text", text="❌ Необходимо указать псевдоним хоста")]
                    
                    if not os.path.exists(config_file):
                        return [types.TextContent(type="text", text="❌ SSH конфигурация не найдена")]
                    
                    # Чтение и фильтрация конфигурации
                    with open(config_file, 'r') as f:
                        lines = f.readlines()
                    
                    new_lines = []
                    skip_section = False
                    
                    for line in lines:
                        if line.strip().startswith(f"Host {host_alias}"):
                            skip_section = True
                            continue
                        elif line.strip().startswith("Host ") and skip_section:
                            skip_section = False
                            new_lines.append(line)
                        elif not skip_section:
                            new_lines.append(line)
                    
                    # Запись обновленной конфигурации
                    with open(config_file, 'w') as f:
                        f.writelines(new_lines)
                    
                    result = f"✅ Хост '{host_alias}' удален из SSH конфигурации"
                    self.logger.info(f"SSH config host removed: {host_alias}")
                    return [types.TextContent(type="text", text=result)]
                
                else:
                    return [types.TextContent(type="text", text="❌ Неизвестное действие. Используйте: show, add_host, remove_host")]
                    
            except Exception as e:
                error_msg = f"Ошибка при работе с конфигурацией: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_info", description="Показать информацию о подключениях и состоянии")
        def ssh_info() -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                result = "📊 Информация о SSH:\n\n"
                
                # Активные подключения
                result += "🔗 Активные подключения:\n"
                if self.active_connections:
                    for conn_key, conn_info in self.active_connections.items():
                        connected_time = datetime.datetime.now(self.tz_plus3) - conn_info['connected_at']
                        result += f"  • {conn_key} (подключен {connected_time.seconds // 60} мин назад)\n"
                else:
                    result += "  Нет активных подключений\n"
                
                result += "\n"
                
                # Активные туннели
                result += "🔌 Активные туннели:\n"
                if self.active_tunnels:
                    for tunnel_id, tunnel_info in self.active_tunnels.items():
                        created_time = datetime.datetime.now(self.tz_plus3) - tunnel_info['created_at']
                        result += f"  • {tunnel_id} (создан {created_time.seconds // 60} мин назад)\n"
                else:
                    result += "  Нет активных туннелей\n"
                
                result += "\n"
                
                # SSH ключи
                result += "🔑 SSH ключи:\n"
                key_count = 0
                if os.path.exists(self.ssh_config_dir):
                    for file in os.listdir(self.ssh_config_dir):
                        if file.endswith('.pub'):
                            key_count += 1
                            result += f"  • {file[:-4]}\n"
                
                if key_count == 0:
                    result += "  Ключи не найдены\n"
                
                return [types.TextContent(type="text", text=result)]
                
            except Exception as e:
                error_msg = f"Ошибка при получении информации: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="ssh_logs", description="Получить логи операций SSH")
        def ssh_logs() -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                if not os.path.exists(self.log_file):
                    return [types.TextContent(type="text", text="Лог-файл не найден")]

                with open(self.log_file, "r", encoding="utf-8") as f:
                    logs = f.read()

                if not logs.strip():
                    return [types.TextContent(type="text", text="Лог-файл пуст")]

                # Возвращаем последние 50 строк логов
                lines = logs.strip().split('\n')
                if len(lines) > 50:
                    result = "\n".join(lines[-50:])
                    result = "... (показаны последние 50 записей)\n\n" + result
                else:
                    result = logs

                return [types.TextContent(type="text", text=result)]
            except Exception as e:
                error_msg = f"Ошибка при чтении логов: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

    def __del__(self):
        """Очистка ресурсов при удалении объекта"""
        # Завершение всех активных туннелей
        for tunnel_id, tunnel_info in list(self.active_tunnels.items()):
            try:
                process = tunnel_info['process']
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        self.active_tunnels.clear()
