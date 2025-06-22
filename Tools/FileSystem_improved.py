from Data.MCP_Tools import MCP_Tools
import mcp.types as types
import datetime
import os
import logging
import json
import shutil
from typing import Dict, Callable, Annotated
from pathlib import Path

class FileSystemTools:
    def __init__(self, mcp: MCP_Tools) -> None:
        # Настройка часового пояса и рабочей директории
        self.tz_plus3 = datetime.timezone(datetime.timedelta(hours=3))
        self.working_dir = "Data"
        self.log_file = os.path.join(self.working_dir, "filesystem.log")
        
        # Создание рабочей директории
        os.makedirs(self.working_dir, exist_ok=True)
        
        # Настройка логирования
        self._setup_logging()
        
        # Регистрация инструментов
        self._register_tools(mcp)
        
        self.logger.info("FileSystemTools initialized")
    
    def _setup_logging(self):
        """Настройка системы логирования"""
        self.logger = logging.getLogger('FileSystemTools')
        self.logger.setLevel(logging.INFO)
        
        # Очистка существующих handlers
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Форматтер для логов
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler для записи в файл
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Установка часового пояса для логов
        logging.Formatter.converter = lambda *args: datetime.datetime.now(self.tz_plus3).timetuple()
    
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
        if normalized.startswith('..') or '/..' in normalized or '\\\\..\\\\' in normalized:
            raise ValueError("Попытка доступа за пределы рабочей директории")
        
        # Проверка на запрещенные символы (для Windows)
        forbidden_chars = '<>:"|?*'
        if any(char in normalized for char in forbidden_chars):
            raise ValueError(f"Путь содержит запрещенные символы: {forbidden_chars}")
        
        # Полный путь к файлу
        full_path = os.path.join(self.working_dir, normalized)
        
        # Финальная проверка, что путь действительно находится в рабочей директории
        try:
            real_working_dir = os.path.realpath(self.working_dir)
            real_target_path = os.path.realpath(full_path)
            if not real_target_path.startswith(real_working_dir):
                raise ValueError("Попытка доступа за пределы рабочей директории")
        except OSError:
            # Файл может не существовать, это нормально
            pass
        
        return normalized
    
    def _get_safe_path(self, path: str) -> str:
        """Получить безопасный полный путь к файлу"""
        validated_path = self._validate_path(path)
        return os.path.join(self.working_dir, validated_path)
    
    def _register_tools(self, mcp: MCP_Tools):
        """Регистрация всех инструментов"""
        
        @mcp.register_tool(name="listfiles", description="Получить список файлов и папок")
        def listfiles() -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                items = []
                for item in os.listdir(self.working_dir):
                    if item == "filesystem.log":  # Скрываем лог-файл из обычного списка
                        continue
                    item_path = os.path.join(self.working_dir, item)
                    if os.path.isdir(item_path):
                        items.append(f"📁 {item}/")
                    else:
                        size = os.path.getsize(item_path)
                        items.append(f"📄 {item} ({self._format_size(size)})")
                
                result = "\\n".join(items) if items else "Директория пуста"
                self.logger.info("Listed files successfully")
                return [types.TextContent(type="text", text=result)]
            except Exception as e:
                error_msg = f"Ошибка при получении списка файлов: {str(e)}"
                self.logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="savefile", description="Сохранить файл")
        def savefile(
            path: Annotated[str, "Путь к файлу"],
            content: Annotated[str, "Содержимое файла"],
            encoding: Annotated[str, "Кодировка файла"] = "utf-8"
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                # Создание директорий при необходимости
                os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                
                with open(safe_path, "w", encoding=encoding) as f:
                    f.write(content)
                
                size = len(content.encode(encoding))
                self.logger.info(f"File saved: {path} ({self._format_size(size)})")
                return [types.TextContent(type="text", text=f"Файл '{path}' успешно сохранен")]
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при сохранении файла: {str(e)}"
                self.logger.error(f"Failed to save file '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="readfile", description="Прочитать файл")
        def readfile(
            path: Annotated[str, "Путь к файлу"],
            encoding: Annotated[str, "Кодировка файла"] = "utf-8"
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if not os.path.exists(safe_path):
                    error_msg = f"Файл '{path}' не найден"
                    self.logger.warning(f"File not found: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                with open(safe_path, "r", encoding=encoding) as f:
                    content = f.read()
                
                self.logger.info(f"File read: {path} ({self._format_size(len(content.encode(encoding)))})")
                return [types.TextContent(type="text", text=content)]
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except UnicodeDecodeError as e:
                error_msg = f"Ошибка декодирования файла '{path}': {str(e)}"
                self.logger.error(f"Encoding error for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при чтении файла: {str(e)}"
                self.logger.error(f"Failed to read file '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="deletefile", description="Удалить файл")
        def deletefile(
            path: Annotated[str, "Путь к файлу"]
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if not os.path.exists(safe_path):
                    error_msg = f"Файл '{path}' не найден"
                    self.logger.warning(f"Attempted to delete non-existent file: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                if os.path.isdir(safe_path):
                    error_msg = f"'{path}' является директорией. Используйте deletedir для удаления директорий"
                    self.logger.warning(f"Attempted to delete directory as file: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                os.remove(safe_path)
                self.logger.info(f"File deleted: {path}")
                return [types.TextContent(type="text", text=f"Файл '{path}' успешно удален")]
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при удалении файла: {str(e)}"
                self.logger.error(f"Failed to delete file '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="createdir", description="Создать директорию")
        def createdir(
            path: Annotated[str, "Путь к директории"]
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if os.path.exists(safe_path):
                    error_msg = f"Директория '{path}' уже существует"
                    self.logger.warning(f"Attempted to create existing directory: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                os.makedirs(safe_path, exist_ok=False)
                self.logger.info(f"Directory created: {path}")
                return [types.TextContent(type="text", text=f"Директория '{path}' успешно создана")]
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при создании директории: {str(e)}"
                self.logger.error(f"Failed to create directory '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="deletedir", description="Удалить директорию")
        def deletedir(
            path: Annotated[str, "Путь к директории"],
            recursive: Annotated[bool, "Рекурсивное удаление (удалить все содержимое)"] = False
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if not os.path.exists(safe_path):
                    error_msg = f"Директория '{path}' не найдена"
                    self.logger.warning(f"Attempted to delete non-existent directory: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                if not os.path.isdir(safe_path):
                    error_msg = f"'{path}' не является директорией"
                    self.logger.warning(f"Attempted to delete non-directory as directory: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                if recursive:
                    shutil.rmtree(safe_path)
                    self.logger.info(f"Directory deleted recursively: {path}")
                    return [types.TextContent(type="text", text=f"Директория '{path}' и все её содержимое успешно удалены")]
                else:
                    os.rmdir(safe_path)
                    self.logger.info(f"Empty directory deleted: {path}")
                    return [types.TextContent(type="text", text=f"Пустая директория '{path}' успешно удалена")]
            except OSError as e:
                if "Directory not empty" in str(e):
                    error_msg = f"Директория '{path}' не пуста. Используйте recursive=true для рекурсивного удаления"
                else:
                    error_msg = f"Ошибка при удалении директории: {str(e)}"
                self.logger.error(f"Failed to delete directory '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при удалении директории: {str(e)}"
                self.logger.error(f"Failed to delete directory '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="fileinfo", description="Получить информацию о файле или директории")
        def fileinfo(
            path: Annotated[str, "Путь к файлу или директории"]
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                safe_path = self._get_safe_path(path)
                
                if not os.path.exists(safe_path):
                    error_msg = f"Файл или директория '{path}' не найдены"
                    self.logger.warning(f"Attempted to get info for non-existent path: {path}")
                    return [types.TextContent(type="text", text=error_msg)]
                
                stat = os.stat(safe_path)
                is_dir = os.path.isdir(safe_path)
                
                # Форматирование времени с учетом часового пояса
                mtime = datetime.datetime.fromtimestamp(stat.st_mtime, self.tz_plus3)
                ctime = datetime.datetime.fromtimestamp(stat.st_ctime, self.tz_plus3)
                
                info = {
                    "Путь": path,
                    "Тип": "Директория" if is_dir else "Файл",
                    "Размер": self._format_size(stat.st_size) if not is_dir else "-",
                    "Последнее изменение": mtime.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "Создано": ctime.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "Права доступа": oct(stat.st_mode)[-3:]
                }
                
                if is_dir:
                    try:
                        items = os.listdir(safe_path)
                        info["Содержимое"] = f"{len(items)} элементов"
                    except PermissionError:
                        info["Содержимое"] = "Нет доступа"
                
                result = "\\n".join([f"{key}: {value}" for key, value in info.items()])
                self.logger.info(f"File info requested: {path}")
                return [types.TextContent(type="text", text=result)]
            except ValueError as e:
                error_msg = f"Ошибка валидации пути: {str(e)}"
                self.logger.warning(f"Path validation failed for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
            except Exception as e:
                error_msg = f"Ошибка при получении информации: {str(e)}"
                self.logger.error(f"Failed to get file info for '{path}': {str(e)}")
                return [types.TextContent(type="text", text=error_msg)]
        
        @mcp.register_tool(name="getlogs", description="Получить логи операций файловой системы")
        def getlogs() -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            try:
                if not os.path.exists(self.log_file):
                    return [types.TextContent(type="text", text="Лог-файл не найден")]
                
                with open(self.log_file, "r", encoding="utf-8") as f:
                    logs = f.read()
                
                if not logs.strip():
                    return [types.TextContent(type="text", text="Лог-файл пуст")]
                
                # Возвращаем последние 50 строк логов
                lines = logs.strip().split('\\n')
                if len(lines) > 50:
                    result = "\\n".join(lines[-50:])
                    result = "... (показаны последние 50 записей)\\n\\n" + result
                else:
                    result = logs
                
                return [types.TextContent(type="text", text=result)]
            except Exception as e:
                error_msg = f"Ошибка при чтении логов: {str(e)}"
                return [types.TextContent(type="text", text=error_msg)]
    
    def _format_size(self, size: int) -> str:
        """Форматирование размера файла в человекочитаемый вид"""
        for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} ТБ"
