#!/bin/bash

# Устанавливаем строгий режим выполнения
set -euo pipefail

# Переменные для цветного вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для вывода сообщений
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Функция инициализации настроек
settings() {
    # Базовые переменные
    PROJECT=""
    SLN_PATH=""
    OUTPUT_BASE_PATH="$HOME/Publish/TestPublish/"
    OUTPUT_PATH=""
    SERVICE_NAME=""
    DEPLOY_FOLDER=""
    TARGET=""
    RUNTIME="linux-x64"
    PUBLISH_TARGET_SLN=""
    SEND_CLOUD=""
    SSH_KEY_FILE=""
    
    # Массив проектов: "название;путь_к_проекту;файл_проекта;имя_службы;папка_на_сервере;сервер"
    declare -g -a PROJECTS=(
        "SshBackgroundWorker;$HOME/Github/SshBackgroundWorker/;SshBackgroundWorker.csproj;;;"
        "WebAPI;$HOME/Github/WebApi;WebApi/WebAPI.sln;WebApi;~/TestAPI3;klimenkov@213.171.27.113"
        "ReverseProxyManager;$HOME/Github/ReverseProxyManager;ReverseProxyManager.csproj;;;"
        "MCP;$HOME/Github/MCP;MCP.csproj;;;"
    )
    
    # Доступные runtime
    declare -g -a RUNTIMES=(
        "linux-x64"
        "linux-arm64"
        "win-x64"
        "osx-x64"
        "osx-arm64"
    )
}

# Функция получения значения или значения по умолчанию
get_value_or_default() {
    local value="$1"
    local default="$2"
    
    if [[ -n "$value" && "$value" != '""' ]]; then
        echo "$value"
    else
        echo "$default"
    fi
}

# Функция выбора runtime
select_runtime() {
    echo "================================"
    echo "Выберите runtime для публикации:"
    echo "================================"
    
    for i in "${!RUNTIMES[@]}"; do
        echo "$((i+1)). ${RUNTIMES[$i]}"
    done
    
    while true; do
        read -p "Введите номер runtime (1-${#RUNTIMES[@]}) [по умолчанию: 1]: " runtime_num
        
        # Если пользователь не ввел ничего, используем значение по умолчанию
        if [[ -z "$runtime_num" ]]; then
            runtime_num=1
        fi
        
        # Проверяем корректность ввода
        if [[ "$runtime_num" =~ ^[0-9]+$ ]] && [ "$runtime_num" -ge 1 ] && [ "$runtime_num" -le "${#RUNTIMES[@]}" ]; then
            RUNTIME="${RUNTIMES[$((runtime_num-1))]}"
            log_info "Выбран runtime: $RUNTIME"
            break
        else
            log_error "Неверный выбор. Попробуйте снова."
        fi
    done
}

# Функция запроса SSH ключа
ask_ssh_key() {
    read -p "Использовать SSH ключ для доступа к приватным репозиториям? (y/n) [n]: " use_ssh_key
    
    if [[ "$use_ssh_key" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Введите путь к SSH ключу [$HOME/.ssh/id_rsa]: " ssh_key_path
            
            # Если путь не введен, используем значение по умолчанию
            if [[ -z "$ssh_key_path" ]]; then
                ssh_key_path="$HOME/.ssh/id_rsa"
            fi
            
            # Проверяем существование файла ключа
            if [[ -f "$ssh_key_path" ]]; then
                SSH_KEY_FILE="$ssh_key_path"
                log_info "Будет использован SSH ключ: $SSH_KEY_FILE"
                
                # Добавляем ключ в ssh-agent если он не запущен
                if ! pgrep -x "ssh-agent" > /dev/null; then
                    eval "$(ssh-agent -s)"
                fi
                
                ssh-add "$SSH_KEY_FILE" 2>/dev/null || log_warning "Не удалось добавить ключ в ssh-agent"
                break
            else
                log_error "Файл ключа не найден: $ssh_key_path"
                read -p "Попробовать снова? (y/n): " retry
                if [[ ! "$retry" =~ ^[Yy]$ ]]; then
                    break
                fi
            fi
        done
    fi
}

# Функция выбора проекта
ask_project() {
    echo "================================"
    echo "Выберите проект для сборки:"
    echo "================================"
    
    for i in "${!PROJECTS[@]}"; do
        IFS=';' read -ra project_info <<< "${PROJECTS[$i]}"
        echo "$((i+1)). ${project_info[0]}"
    done
    
    while true; do
        read -p "Введите номер проекта (1-${#PROJECTS[@]}): " project_num
        
        if [[ "$project_num" =~ ^[0-9]+$ ]] && [ "$project_num" -ge 1 ] && [ "$project_num" -le "${#PROJECTS[@]}" ]; then
            # Парсим выбранный проект
            IFS=';' read -ra selected_project <<< "${PROJECTS[$((project_num-1))]}"
            
            PROJECT="${selected_project[0]}"
            SLN_PATH="${selected_project[1]}"
            PUBLISH_TARGET_SLN=$(get_value_or_default "${selected_project[2]}" ".")
            SERVICE_NAME="${selected_project[3]}"
            DEPLOY_FOLDER="${selected_project[4]}"
            TARGET="${selected_project[5]}"
            
            OUTPUT_PATH="${OUTPUT_BASE_PATH}${PROJECT}/"
            
            log_info "Выбран проект: $PROJECT"
            log_info "Путь к решению: $SLN_PATH"
            log_info "Файл проекта: $PUBLISH_TARGET_SLN"
            log_info "Выходной путь: $OUTPUT_PATH"
            if [[ -n "$SERVICE_NAME" ]]; then
                log_info "Имя службы: $SERVICE_NAME"
            fi
            if [[ -n "$DEPLOY_FOLDER" ]]; then
                log_info "Путь на сервере: $DEPLOY_FOLDER"
            fi
            if [[ -n "$TARGET" ]]; then
                log_info "Сервер: $TARGET"
            fi
            break
        else
            log_error "Неверный выбор. Попробуйте снова."
        fi
    done
}

# Функция обновления проекта из Git
refresh_project() {
    log_info "Синхронизация проекта с Git..."
    
    if [[ ! -d "$SLN_PATH" ]]; then
        log_error "Директория проекта не найдена: $SLN_PATH"
        exit 1
    fi
    
    cd "$SLN_PATH"
    
    # Проверяем, является ли директория Git репозиторием
    if [[ ! -d ".git" ]]; then
        log_warning "Директория не является Git репозиторием: $SLN_PATH"
        return 0
    fi
    
    # Настраиваем SSH для Git если указан ключ
    if [[ -n "$SSH_KEY_FILE" ]]; then
        export GIT_SSH_COMMAND="ssh -i $SSH_KEY_FILE -o IdentitiesOnly=yes"
    fi
    
    # Обновляем репозиторий
    if git pull --rebase; then
        log_success "Проект обновлен из Git"
    else
        log_warning "Не удалось обновить проект из Git"
    fi
    
    # Очищаем и восстанавливаем зависимости
    dotnet clean
    dotnet restore
}

# Функция публикации проекта
publish() {
    log_info "Публикация проекта..."
    
    local publish_output
    if [[ -n "$PUBLISH_OUTPUT" ]]; then
        publish_output="$PUBLISH_OUTPUT"
    else
        publish_output="${OUTPUT_PATH}${RUNTIME}"
    fi
    
    log_info "Директория публикации: $publish_output"
    
    # Создаем директорию для публикации
    mkdir -p "$publish_output"
    
    cd "$SLN_PATH"
    
    # Очищаем проект
    dotnet clean
    
    # Параметры сборки
    local build_params=(
        "$PUBLISH_TARGET_SLN"
        "--runtime" "$RUNTIME"
        "--self-contained"
        "--configuration" "Release"
    )
    
    log_info "Сборка проекта..."
    log_info "Команда: dotnet build ${build_params[*]}"
    
    if dotnet build "${build_params[@]}"; then
        log_success "Сборка завершена успешно"
    else
        log_error "Ошибка при сборке проекта"
        exit 1
    fi
    
    # Параметры публикации
    local publish_params=(
        "$PUBLISH_TARGET_SLN"
        "--runtime" "$RUNTIME"
        "--self-contained"
        "--configuration" "Release"
        "-o" "$publish_output"
        "/p:Beauty_EnabledOnBuild=false"
    )
    
    log_info "Публикация проекта..."
    log_info "Команда: dotnet publish ${publish_params[*]}"
    
    if dotnet publish "${publish_params[@]}"; then
        log_success "Публикация завершена. Файлы сохранены в $publish_output"
        
        # Делаем исполняемый файл исполняемым
        if [[ -f "$publish_output/$PROJECT" ]]; then
            chmod +x "$publish_output/$PROJECT"
            log_info "Установлены права на выполнение для $PROJECT"
        fi
    else
        log_error "Ошибка при публикации проекта"
        exit 1
    fi
    
    PUBLISH_OUTPUT="$publish_output"
}

# Функция отправки на удаленный сервер
send_to_cloud() {
    log_info "Отправка на сервер..."
    
    if [[ -z "$TARGET" ]]; then
        log_error "Не указан целевой сервер"
        return 1
    fi
    
    if [[ -z "$DEPLOY_FOLDER" ]]; then
        log_error "Не указана папка для развертывания"
        return 1
    fi
    
    # Параметры SSH
    local ssh_params=""
    local scp_params=""
    if [[ -n "$SSH_KEY_FILE" ]]; then
        ssh_params="-i $SSH_KEY_FILE"
        scp_params="-i $SSH_KEY_FILE"
    fi
    
    log_info "Сервер: $TARGET"
    log_info "Папка на сервере: $DEPLOY_FOLDER"
    
    # Останавливаем службу на сервере
    if [[ -n "$SERVICE_NAME" ]]; then
        log_info "Останавливаем службу $SERVICE_NAME..."
        ssh $ssh_params "$TARGET" "sudo systemctl stop $SERVICE_NAME" || log_warning "Не удалось остановить службу"
    fi
    
    # Очищаем каталог на сервере
    log_info "Очищаем каталог на сервере..."
    ssh $ssh_params "$TARGET" "rm -rf $DEPLOY_FOLDER/* && mkdir -p $DEPLOY_FOLDER" || {
        log_error "Не удалось очистить каталог на сервере"
        return 1
    }
    
    # Отправляем файлы на сервер
    log_info "Копируем файлы на сервер..."
    if scp $scp_params -r "$PUBLISH_OUTPUT"/* "$TARGET:$DEPLOY_FOLDER/"; then
        log_success "Файлы скопированы на сервер"
    else
        log_error "Ошибка при копировании файлов"
        return 1
    fi
    
    # Настраиваем права и запускаем службу
    if [[ -n "$SERVICE_NAME" ]]; then
        log_info "Настраиваем права и запускаем службу..."
        ssh $ssh_params "$TARGET" "chmod +x $DEPLOY_FOLDER/$PROJECT && sudo systemctl start $SERVICE_NAME && sudo systemctl status $SERVICE_NAME" || {
            log_warning "Возможные проблемы при запуске службы"
        }
    else
        # Просто устанавливаем права на выполнение
        ssh $ssh_params "$TARGET" "chmod +x $DEPLOY_FOLDER/$PROJECT" || log_warning "Не удалось установить права на выполнение"
    fi
    
    log_success "Отправка завершена успешно"
}

# Основная функция
main() {
    log_info "=== Скрипт сборки и публикации .NET проектов ==="
    
    # Проверяем наличие dotnet
    if ! command -v dotnet &> /dev/null; then
        log_error ".NET SDK не найден. Установите .NET SDK и повторите попытку."
        exit 1
    fi
    
    # Инициализируем настройки
    settings
    
    # Запрашиваем SSH ключ
    ask_ssh_key
    
    # Выбираем runtime
    select_runtime
    
    # Выбираем проект
    ask_project
    
    # Спрашиваем о отправке на сервер
    if [[ -n "$TARGET" ]]; then
        read -p "Отправить на сервер? (y/n) [n]: " SEND_CLOUD
    fi
    
    # Обновляем проект
    refresh_project
    
    # Публикуем проект
    publish
    
    # Отправляем на сервер если нужно
    if [[ "$SEND_CLOUD" =~ ^[Yy]$ ]]; then
        send_to_cloud
    fi
    
    log_success "Все операции завершены успешно!"
}

# Запускаем основную функцию
main "$@"
