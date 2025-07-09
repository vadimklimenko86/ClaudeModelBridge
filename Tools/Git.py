from MCP_Tools import MCP_Tools
import mcp.types as types
import datetime
import os
import logging
import json
import subprocess
import re
from typing import Dict, Callable, Annotated, List, Optional
from pathlib import Path


class GitTools:

    def __init__(self, mcp: MCP_Tools) -> None:
        # Настройка часового пояса и рабочей директории
        self.tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))
        self.working_dir = "Data"  # "."
        self.log_file = os.path.join("Tools", "git.log")

        # Создание рабочей директории
        if not self.working_dir == None:
            os.makedirs(self.working_dir, exist_ok=True)

        # Настройка логирования
        self._setup_logging()

        # Регистрация инструментов
        self._register_tools(mcp)

        self.logger.info("GitTools initialized")

    def _setup_logging(self):
        """Настройка системы логирования"""
        self.logger = logging.getLogger('GitTools')
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

    def _validate_path(self, path: str) -> str:
        """
        Валидация и нормализация пути для предотвращения path traversal атак
        
        Args:
            path: Путь для валидации
            
        Returns:
            str: Безопасный нормализованный путь
            
        Raises:
            ValueError: При обнаружении небезопасного пути
        """
        if not path:
            raise ValueError("Путь не может быть пустым")

        # Удаление ведущих и завершающих пробелов
        path = path.strip()

        # Проверка на абсолютные пути
        if os.path.isabs(path):
            raise ValueError("Абсолютные пути запрещены")

        # Нормализация пути
        normalized = os.path.normpath(path)

        # Проверка на попытки выхода за пределы рабочей директории
        if normalized.startswith('..') or '/..' in normalized or '\\..\\' in normalized:
            raise ValueError("Попытка доступа за пределы рабочей директории")

        # Проверка на запрещенные символы (для Windows)
        forbidden_chars = '<>:"|?*'
        if any(char in normalized for char in forbidden_chars):
            raise ValueError(f"Путь содержит запрещенные символы: {forbidden_chars}")

        return normalized

    def _get_safe_path(self, path: str) -> str:
        """Получить безопасный полный путь к директории"""
        validated_path = self._validate_path(path)
        return os.path.join(self.working_dir, validated_path)

    def _run_git_command(self, command: List[str], cwd: str = None) -> tuple[bool, str, str]:
        """
        Выполнить git команду
        
        Args:
            command: Список аргументов команды
            cwd: Рабочая директория для выполнения команды
            
        Returns:
            tuple: (success, stdout, stderr)
        """
        try:
            if cwd is None:
                cwd = self.working_dir
            
            # Проверяем, что git установлен
            result = subprocess.run(
                ['git'] + command,
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=30
            )
            
            success = result.returncode == 0
            return success, result.stdout.strip(), result.stderr.strip()
            
        except subprocess.TimeoutExpired:
            return False, "", "Команда превысила лимит времени выполнения (30 сек)"
        except FileNotFoundError:
            return False, "", "Git не установлен или не найден в PATH"
        except Exception as e:
            return False, "", f"Ошибка выполнения команды: {str(e)}"

    def _register_tools(self, mcp: MCP_Tools):
        """Регистрация всех инструментов"""

        @mcp.register_tool(name="git_init", description="Инициализировать новый Git репозиторий")
        def git_init(
            path: Annotated[str, "Путь к директории для инициализации"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                os.makedirs(safe_path, exist_ok=True)
                
                success, stdout, stderr = self._run_git_command(['init'], safe_path)
                
                if success:
                    self.logger.info(f"Git repository initialized in: {path}")
                    return [types.TextContent(type="text", text=f"✅ Репозиторий Git инициализирован в '{path}'")]
                else:
                    error_msg = f"❌ Ошибка инициализации: {stderr}"
                    self.logger.error(f"Git init failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при инициализации репозитория: {str(e)}"
                self.logger.error(f"Failed to init repository '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_status", description="Показать статус Git репозитория")
        def git_status(
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                success, stdout, stderr = self._run_git_command(['status', '--porcelain', '-b'], safe_path)
                
                if success:
                    if not stdout:
                        result = "✅ Рабочая директория чистая"
                    else:
                        lines = stdout.split('\n')
                        branch_info = lines[0] if lines[0].startswith('##') else "## Unknown branch"
                        changes = [line for line in lines[1:] if line.strip()]
                        
                        result = f"📊 Статус репозитория:\n{branch_info}\n\n"
                        if changes:
                            result += "Изменения:\n"
                            for change in changes:
                                status = change[:2]
                                file_path = change[3:]
                                emoji = self._get_status_emoji(status)
                                result += f"{emoji} {file_path}\n"
                    
                    self.logger.info(f"Git status checked for: {path}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка получения статуса: {stderr}"
                    self.logger.error(f"Git status failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при получении статуса: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_add", description="Добавить файлы в индекс Git")
        def git_add(
            files: Annotated[str, "Файлы для добавления (разделенные пробелом, '.' для всех)"],
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                file_list = files.split() if files != '.' else ['.']
                
                success, stdout, stderr = self._run_git_command(['add'] + file_list, safe_path)
                
                if success:
                    result = f"✅ Файлы добавлены в индекс: {files}"
                    self.logger.info(f"Git add successful in {path}: {files}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка добавления файлов: {stderr}"
                    self.logger.error(f"Git add failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при добавлении файлов: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_commit", description="Создать коммит")
        def git_commit(
            message: Annotated[str, "Сообщение коммита"],
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                success, stdout, stderr = self._run_git_command(['commit', '-m', message], safe_path)
                
                if success:
                    result = f"✅ Коммит создан: {message}\n{stdout}"
                    self.logger.info(f"Git commit successful in {path}: {message}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка создания коммита: {stderr}"
                    self.logger.error(f"Git commit failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при создании коммита: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_push", description="Отправить изменения в удаленный репозиторий")
        def git_push(
            remote: Annotated[str, "Название удаленного репозитория"] = "origin",
            branch: Annotated[str, "Название ветки"] = "main",
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                success, stdout, stderr = self._run_git_command(['push', remote, branch], safe_path)
                
                if success:
                    result = f"✅ Изменения отправлены в {remote}/{branch}\n{stdout}"
                    self.logger.info(f"Git push successful in {path} to {remote}/{branch}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка отправки: {stderr}"
                    self.logger.error(f"Git push failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при отправке: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_pull", description="Получить изменения из удаленного репозитория")
        def git_pull(
            remote: Annotated[str, "Название удаленного репозитория"] = "origin",
            branch: Annotated[str, "Название ветки"] = "main",
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                success, stdout, stderr = self._run_git_command(['pull', remote, branch], safe_path)
                
                if success:
                    result = f"✅ Изменения получены из {remote}/{branch}\n{stdout}"
                    self.logger.info(f"Git pull successful in {path} from {remote}/{branch}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка получения: {stderr}"
                    self.logger.error(f"Git pull failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при получении: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_clone", description="Клонировать репозиторий")
        def git_clone(
            url: Annotated[str, "URL репозитория для клонирования"],
            directory: Annotated[str, "Название директории для клонирования (опционально)"] = "",
            path: Annotated[str, "Путь где создать клон"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                os.makedirs(safe_path, exist_ok=True)
                
                command = ['clone', url]
                if directory:
                    command.append(directory)
                
                success, stdout, stderr = self._run_git_command(command, safe_path)
                
                if success:
                    result = f"✅ Репозиторий клонирован: {url}\n{stdout}"
                    self.logger.info(f"Git clone successful: {url} to {path}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка клонирования: {stderr}"
                    self.logger.error(f"Git clone failed: {url} - {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при клонировании: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_branch", description="Управление ветками")
        def git_branch(
            action: Annotated[str, "Действие: list, create, delete, switch"],
            name: Annotated[str, "Название ветки (для create, delete, switch)"] = "",
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if action == "list":
                    success, stdout, stderr = self._run_git_command(['branch', '-a'], safe_path)
                    if success:
                        result = f"🌿 Список веток:\n{stdout}"
                    else:
                        result = f"❌ Ошибка получения списка веток: {stderr}"
                        
                elif action == "create":
                    if not name:
                        return [types.TextContent(type="text", text="❌ Необходимо указать название ветки")]
                    success, stdout, stderr = self._run_git_command(['branch', name], safe_path)
                    if success:
                        result = f"✅ Ветка '{name}' создана"
                    else:
                        result = f"❌ Ошибка создания ветки: {stderr}"
                        
                elif action == "delete":
                    if not name:
                        return [types.TextContent(type="text", text="❌ Необходимо указать название ветки")]
                    success, stdout, stderr = self._run_git_command(['branch', '-d', name], safe_path)
                    if success:
                        result = f"✅ Ветка '{name}' удалена"
                    else:
                        result = f"❌ Ошибка удаления ветки: {stderr}"
                        
                elif action == "switch":
                    if not name:
                        return [types.TextContent(type="text", text="❌ Необходимо указать название ветки")]
                    success, stdout, stderr = self._run_git_command(['checkout', name], safe_path)
                    if success:
                        result = f"✅ Переключились на ветку '{name}'"
                    else:
                        result = f"❌ Ошибка переключения на ветку: {stderr}"
                else:
                    return [types.TextContent(type="text", text="❌ Неизвестное действие. Используйте: list, create, delete, switch")]
                
                self.logger.info(f"Git branch {action} in {path}: {name}")
                return [types.TextContent(type="text", text=result)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при работе с ветками: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_log", description="Показать историю коммитов")
        def git_log(
            limit: Annotated[int, "Количество коммитов для показа"] = 10,
            oneline: Annotated[bool, "Краткий формат (одна строка на коммит)"] = True,
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                command = ['log', f'--max-count={limit}']
                if oneline:
                    command.append('--oneline')
                
                success, stdout, stderr = self._run_git_command(command, safe_path)
                
                if success:
                    if stdout:
                        result = f"📜 История коммитов (последние {limit}):\n{stdout}"
                    else:
                        result = "📜 История коммитов пуста"
                    self.logger.info(f"Git log checked for: {path}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка получения истории: {stderr}"
                    self.logger.error(f"Git log failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при получении истории: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_remote", description="Управление удаленными репозиториями")
        def git_remote(
            action: Annotated[str, "Действие: list, add, remove"],
            name: Annotated[str, "Название удаленного репозитория"] = "",
            url: Annotated[str, "URL удаленного репозитория (для add)"] = "",
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if action == "list":
                    success, stdout, stderr = self._run_git_command(['remote', '-v'], safe_path)
                    if success:
                        result = f"🌐 Удаленные репозитории:\n{stdout}" if stdout else "🌐 Удаленные репозитории не настроены"
                    else:
                        result = f"❌ Ошибка получения списка удаленных репозиториев: {stderr}"
                        
                elif action == "add":
                    if not name or not url:
                        return [types.TextContent(type="text", text="❌ Необходимо указать название и URL")]
                    success, stdout, stderr = self._run_git_command(['remote', 'add', name, url], safe_path)
                    if success:
                        result = f"✅ Удаленный репозиторий '{name}' добавлен: {url}"
                    else:
                        result = f"❌ Ошибка добавления удаленного репозитория: {stderr}"
                        
                elif action == "remove":
                    if not name:
                        return [types.TextContent(type="text", text="❌ Необходимо указать название репозитория")]
                    success, stdout, stderr = self._run_git_command(['remote', 'remove', name], safe_path)
                    if success:
                        result = f"✅ Удаленный репозиторий '{name}' удален"
                    else:
                        result = f"❌ Ошибка удаления удаленного репозитория: {stderr}"
                else:
                    return [types.TextContent(type="text", text="❌ Неизвестное действие. Используйте: list, add, remove")]
                
                self.logger.info(f"Git remote {action} in {path}: {name}")
                return [types.TextContent(type="text", text=result)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при работе с удаленными репозиториями: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_diff", description="Показать различия в файлах")
        def git_diff(
            staged: Annotated[bool, "Показать различия в staged файлах"] = False,
            file_path: Annotated[str, "Путь к конкретному файлу (опционально)"] = "",
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                command = ['diff']
                if staged:
                    command.append('--cached')
                if file_path:
                    command.append(file_path)
                
                success, stdout, stderr = self._run_git_command(command, safe_path)
                
                if success:
                    if stdout:
                        result = f"📋 Различия:\n{stdout}"
                    else:
                        result = "📋 Различий не найдено"
                    self.logger.info(f"Git diff checked for: {path}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка получения различий: {stderr}"
                    self.logger.error(f"Git diff failed in {path}: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при получении различий: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_config", description="Настройка Git конфигурации")
        def git_config(
            key: Annotated[str, "Ключ конфигурации (например, user.name)"],
            value: Annotated[str, "Значение конфигурации"],
            global_config: Annotated[bool, "Глобальная настройка"] = True,
            path: Annotated[str, "Путь к Git репозиторию"] = "."
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                command = ['config']
                if global_config:
                    command.append('--global')
                command.extend([key, value])
                
                success, stdout, stderr = self._run_git_command(command, safe_path)
                
                if success:
                    result = f"✅ Конфигурация установлена: {key} = {value}"
                    self.logger.info(f"Git config set: {key} = {value}")
                    return [types.TextContent(type="text", text=result)]
                else:
                    error_msg = f"❌ Ошибка установки конфигурации: {stderr}"
                    self.logger.error(f"Git config failed: {stderr}")
                    return [types.TextContent(type="text", text=error_msg)]
                    
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при настройке конфигурации: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]

        @mcp.register_tool(name="git_logs", description="Получить логи операций Git")
        def git_logs() -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
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

    def _get_status_emoji(self, status: str) -> str:
        """Получить эмодзи для статуса файла"""
        status_map = {
            'M ': '📝',  # Modified
            ' M': '📝',  # Modified
            'A ': '➕',  # Added
            ' A': '➕',  # Added
            'D ': '🗑️',  # Deleted
            ' D': '🗑️',  # Deleted
            'R ': '🔄',  # Renamed
            ' R': '🔄',  # Renamed
            'C ': '📋',  # Copied
            ' C': '📋',  # Copied
            '??': '❓',  # Untracked
            '!!': '🚫',  # Ignored
        }
        return status_map.get(status, '📄')
