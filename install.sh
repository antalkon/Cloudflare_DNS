#!/bin/bash

# Cloudflare DNS Manager - Quick Install Script
# Скрипт для быстрого развертывания на сервере

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции для красивого вывода
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Cloudflare DNS Manager - Установка${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Проверка зависимостей
check_requirements() {
    print_info "Проверка зависимостей..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker не установлен!"
        echo "Установите Docker: https://docs.docker.com/engine/install/"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose не установлен!"
        echo "Установите Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    print_success "Все зависимости найдены"
}

# Загрузка конфигурации
download_config() {
    print_info "Загрузка конфигурации..."
    
    # URL к репозиторию
    CONFIG_URL="https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/docker-compose.standalone.yml"
    
    if command -v wget &> /dev/null; then
        wget -q -O docker-compose.yml "$CONFIG_URL" || {
            print_error "Не удалось загрузить конфигурацию"
            exit 1
        }
    elif command -v curl &> /dev/null; then
        curl -s -o docker-compose.yml "$CONFIG_URL" || {
            print_error "Не удалось загрузить конфигурацию" 
            exit 1
        }
    else
        print_error "Нужен wget или curl для загрузки конфигурации"
        exit 1
    fi
    
    print_success "Конфигурация загружена"
}

# Генерация секретного ключа
generate_secret() {
    print_info "Генерация секретного ключа..."
    
    SECRET_KEY=""
    if command -v openssl &> /dev/null; then
        SECRET_KEY=$(openssl rand -hex 32)
    elif command -v python3 &> /dev/null; then
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    else
        SECRET_KEY="change-this-secret-key-$(date +%s)-$(whoami)"
        print_warning "Используется простой секретный ключ. Рекомендуется изменить его позже."
    fi
    
    echo "SECRET_KEY=$SECRET_KEY" > .env
    print_success "Секретный ключ сгенерирован"
}

# Интерактивная настройка
interactive_setup() {
    print_info "Интерактивная настройка (нажмите Enter для значений по умолчанию):"
    
    read -p "Домен для приложения (localhost): " DOMAIN_NAME
    DOMAIN_NAME=${DOMAIN_NAME:-localhost}
    echo "DOMAIN_NAME=$DOMAIN_NAME" >> .env
    
    read -p "Язык по умолчанию (ru/en) [ru]: " DEFAULT_LANGUAGE
    DEFAULT_LANGUAGE=${DEFAULT_LANGUAGE:-ru}
    echo "DEFAULT_LANGUAGE=$DEFAULT_LANGUAGE" >> .env
    
    read -p "Разрешить регистрацию новых пользователей? (true/false) [false]: " ALLOW_REGISTRATION
    ALLOW_REGISTRATION=${ALLOW_REGISTRATION:-false}
    echo "ALLOW_REGISTRATION=$ALLOW_REGISTRATION" >> .env
    
    print_success "Настройки сохранены в .env"
}

# Выбор профилей (упрощено)
select_profiles() {
    print_info "Используется стандартная конфигурация без дополнительных компонентов"
}

# Запуск приложения
start_application() {
    print_info "Запуск приложения..."
    
    docker-compose up -d
    
    print_success "Приложение запущено!"
}

# Показать информацию после установки
show_info() {
    echo
    print_header
    print_success "Установка завершена!"
    echo
    print_info "Приложение доступно по адресу:"
    if grep -q "DOMAIN_NAME" .env; then
        DOMAIN=$(grep DOMAIN_NAME .env | cut -d'=' -f2)
        echo "  http://$DOMAIN:5000"
    else
        echo "  http://localhost:5000"
    fi
    echo
    print_info "Данные для входа по умолчанию:"
    echo "  Логин: admin"
    echo "  Пароль: admin123"
    echo
    print_warning "Обязательно смените пароль после первого входа!"
    echo
    print_info "Полезные команды:"
    echo "  Просмотр логов:    docker-compose logs -f"
    echo "  Перезапуск:        docker-compose restart"
    echo "  Остановка:         docker-compose down"
    echo "  Обновление:        docker-compose pull && docker-compose up -d"
    echo
    print_info "Конфигурация сохранена в .env файле"
}

# Основная функция
main() {
    print_header
    
    # Проверка аргументов
    SKIP_INTERACTIVE=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            -y|--yes|--non-interactive)
                SKIP_INTERACTIVE=true
                shift
                ;;
            -h|--help)
                echo "Использование: $0 [OPTIONS]"
                echo "  -y, --yes              Пропустить интерактивные вопросы"
                echo "  -h, --help             Показать эту справку"
                exit 0
                ;;
            *)
                print_error "Неизвестная опция: $1"
                exit 1
                ;;
        esac
    done
    
    check_requirements
    download_config
    generate_secret
    
    if [ "$SKIP_INTERACTIVE" = false ]; then
        interactive_setup
        select_profiles
    else
        print_info "Используются настройки по умолчанию"
        echo "DOMAIN_NAME=localhost" >> .env
        echo "DEFAULT_LANGUAGE=ru" >> .env
        echo "ALLOW_REGISTRATION=false" >> .env
    fi
    
    start_application
    show_info
}

# Обработка прерывания
trap 'print_error "Установка прервана"; exit 1' INT

# Запуск
main "$@" 