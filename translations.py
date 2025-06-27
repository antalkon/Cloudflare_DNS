from flask import session

# Словарь переводов
TRANSLATIONS = {
    'ru': {
        # Общие
        'dns_manager': 'DNS Manager',
        'home': 'Главная',
        'settings': 'Настройки',
        'users': 'Пользователи',
        'logout': 'Выход',
        'login': 'Войти',
        'add': 'Добавить',
        'edit': 'Редактировать',
        'delete': 'Удалить',
        'save': 'Сохранить',
        'cancel': 'Отмена',
        'test': 'Тест',
        'active': 'Активен',
        'inactive': 'Неактивен',
        'yes': 'Да',
        'no': 'Нет',
        'loading': 'Загрузка...',
        'error': 'Ошибка',
        'success': 'Успешно',
        'warning': 'Внимание',
        'info': 'Информация',
        
        # Авторизация
        'login_title': 'Вход в систему',
        'username': 'Имя пользователя',
        'password': 'Пароль',
        'login_subtitle': 'Управление динамическими DNS записями',
        'default_credentials': 'Данные по умолчанию:',
        'change_password_warning': 'Обязательно измените пароль после первого входа!',
        'invalid_credentials': 'Неверное имя пользователя или пароль',
        
        # DNS конфигурации
        'dns_configurations': 'DNS Конфигурации',
        'add_domain': 'Добавить домен',
        'no_configurations': 'Конфигурации не найдены',
        'add_first_config': 'Добавьте первую конфигурацию для автоматического обновления DNS записей',
        'current_ip': 'Текущий IP:',
        'update_interval': 'Интервал обновления:',
        'minutes': 'мин',
        'ddns_source': 'DDNS источник:',
        'enabled': 'Включен',
        'last_update': 'Последнее обновление:',
        'never': 'Никогда',
        'update_now': 'Обновить сейчас',
        'start': 'Запустить',
        'stop': 'Остановить',
        'not_determined': 'Не определен',
        
        # Добавление конфигурации
        'add_dns_config': 'Добавить новую DNS конфигурацию',
        'cloudflare_token': 'Cloudflare API токен',
        'select_token': 'Выберите токен',
        'domain': 'Домен',
        'subdomain': 'Поддомен (необязательно)',
        'subdomain_placeholder': 'api, www, mail и т.д.',
        'subdomain_help': 'Оставьте пустым для корневого домена',
        'update_interval_minutes': 'Интервал обновления (минуты)',
        'interval_help': 'От 5 до 1440 минут (24 часа)',
        'ddns_url': 'DDNS URL (необязательно)',
        'ddns_placeholder': 'https://your-server.com/ip или http://192.168.1.100/ip',
        'ddns_help': 'URL для получения IP с другого сервера. Если не указан, будет использоваться IP текущего сервера',
        'ddns_tip': 'Для DDNS URL сервер должен возвращать IP адрес в виде текста или JSON с полями "ip" или "address".',
        'get_token_help': 'Получите токен в панели Cloudflare',
        'select_domain_from_account': 'Выберите домен из вашего аккаунта Cloudflare',
        'enter_token_first': 'Сначала введите токен',
        
        # Настройки
        'cloudflare_tokens': 'Cloudflare API Токены',
        'add_token': 'Добавить токен',
        'no_tokens': 'Нет токенов',
        'add_first_token': 'Добавьте Cloudflare API токен для начала работы',
        'token_name': 'Название токена',
        'token_name_placeholder': 'Например: Основной токен',
        'api_token': 'API токен',
        'active_token': 'Активный токен',
        'user_profile': 'Профиль пользователя',
        'user_type': 'Тип пользователя',
        'administrator': 'Администратор',
        'user': 'Пользователь',
        'new_password': 'Новый пароль',
        'new_password_placeholder': 'Оставьте пустым для сохранения текущего',
        'confirm_password': 'Подтвердите пароль',
        'confirm_password_placeholder': 'Повторите новый пароль',
        'save_changes': 'Сохранить изменения',
        'created': 'Создан:',
        'domains_count': 'Доменов:',
        
        # Уведомления
        'config_created': 'Конфигурация успешно создана!',
        'config_updated': 'Конфигурация успешно обновлена!',
        'config_deleted': 'Конфигурация удалена',
        'token_created': 'Токен добавлен!',
        'token_updated': 'Токен обновлен!',
        'token_deleted': 'Токен удален',
        'dns_updated': 'DNS запись обновлена успешно',
        'profile_updated': 'Профиль обновлен!',
        'token_activated': 'Токен активирован',
        'token_deactivated': 'Токен деактивирован',
        'config_started': 'Конфигурация запущена',
        'config_stopped': 'Конфигурация остановлена',
        
        # Ошибки
        'field_required': 'Поле {field} обязательно',
        'token_not_found': 'Токен не найден или неактивен',
        'domain_not_found': 'Домен {domain} не найден в этом токене',
        'token_invalid': 'Токен недействителен или не имеет доступа к зонам',
        'passwords_dont_match': 'Пароли не совпадают',
        'password_min_length': 'Пароль должен содержать минимум 6 символов',
        'no_changes': 'Нет изменений для сохранения',
        'confirm_delete': 'Вы уверены, что хотите удалить?',
        'token_in_use': 'Токен используется в {count} конфигурациях',
        
        # Общие фразы
        'back': 'Назад',
        'language': 'Язык',
        'optional': 'необязательно',
        'required': 'обязательно',
        'tip': 'Совет:',
    },
    
    'en': {
        # General
        'dns_manager': 'DNS Manager',
        'home': 'Home',
        'settings': 'Settings',
        'users': 'Users',
        'logout': 'Logout',
        'login': 'Login',
        'add': 'Add',
        'edit': 'Edit',
        'delete': 'Delete',
        'save': 'Save',
        'cancel': 'Cancel',
        'test': 'Test',
        'active': 'Active',
        'inactive': 'Inactive',
        'yes': 'Yes',
        'no': 'No',
        'loading': 'Loading...',
        'error': 'Error',
        'success': 'Success',
        'warning': 'Warning',
        'info': 'Information',
        
        # Authentication
        'login_title': 'Sign In',
        'username': 'Username',
        'password': 'Password',
        'login_subtitle': 'Dynamic DNS Records Management',
        'default_credentials': 'Default credentials:',
        'change_password_warning': 'Please change the password after first login!',
        'invalid_credentials': 'Invalid username or password',
        
        # DNS Configurations
        'dns_configurations': 'DNS Configurations',
        'add_domain': 'Add Domain',
        'no_configurations': 'No configurations found',
        'add_first_config': 'Add your first configuration for automatic DNS record updates',
        'current_ip': 'Current IP:',
        'update_interval': 'Update interval:',
        'minutes': 'min',
        'ddns_source': 'DDNS source:',
        'enabled': 'Enabled',
        'last_update': 'Last update:',
        'never': 'Never',
        'update_now': 'Update now',
        'start': 'Start',
        'stop': 'Stop',
        'not_determined': 'Not determined',
        
        # Add Configuration
        'add_dns_config': 'Add New DNS Configuration',
        'cloudflare_token': 'Cloudflare API Token',
        'select_token': 'Select token',
        'domain': 'Domain',
        'subdomain': 'Subdomain (optional)',
        'subdomain_placeholder': 'api, www, mail, etc.',
        'subdomain_help': 'Leave empty for root domain',
        'update_interval_minutes': 'Update interval (minutes)',
        'interval_help': 'From 5 to 1440 minutes (24 hours)',
        'ddns_url': 'DDNS URL (optional)',
        'ddns_placeholder': 'https://your-server.com/ip or http://192.168.1.100/ip',
        'ddns_help': 'URL to get IP from another server. If not specified, current server IP will be used',
        'ddns_tip': 'For DDNS URL, server should return IP address as text or JSON with "ip" or "address" fields.',
        'get_token_help': 'Get token from Cloudflare panel',
        'select_domain_from_account': 'Select domain from your Cloudflare account',
        'enter_token_first': 'Enter token first',
        
        # Settings
        'cloudflare_tokens': 'Cloudflare API Tokens',
        'add_token': 'Add Token',
        'no_tokens': 'No tokens',
        'add_first_token': 'Add Cloudflare API token to get started',
        'token_name': 'Token name',
        'token_name_placeholder': 'e.g.: Main token',
        'api_token': 'API Token',
        'active_token': 'Active token',
        'user_profile': 'User Profile',
        'user_type': 'User type',
        'administrator': 'Administrator',
        'user': 'User',
        'new_password': 'New password',
        'new_password_placeholder': 'Leave empty to keep current',
        'confirm_password': 'Confirm password',
        'confirm_password_placeholder': 'Repeat new password',
        'save_changes': 'Save Changes',
        'created': 'Created:',
        'domains_count': 'Domains:',
        
        # Notifications
        'config_created': 'Configuration created successfully!',
        'config_updated': 'Configuration updated successfully!',
        'config_deleted': 'Configuration deleted',
        'token_created': 'Token added!',
        'token_updated': 'Token updated!',
        'token_deleted': 'Token deleted',
        'dns_updated': 'DNS record updated successfully',
        'profile_updated': 'Profile updated!',
        'token_activated': 'Token activated',
        'token_deactivated': 'Token deactivated',
        'config_started': 'Configuration started',
        'config_stopped': 'Configuration stopped',
        
        # Errors
        'field_required': 'Field {field} is required',
        'token_not_found': 'Token not found or inactive',
        'domain_not_found': 'Domain {domain} not found in this token',
        'token_invalid': 'Token is invalid or has no access to zones',
        'passwords_dont_match': 'Passwords do not match',
        'password_min_length': 'Password must contain at least 6 characters',
        'no_changes': 'No changes to save',
        'confirm_delete': 'Are you sure you want to delete?',
        'token_in_use': 'Token is used in {count} configurations',
        
        # Common phrases
        'back': 'Back',
        'language': 'Language',
        'optional': 'optional',
        'required': 'required',
        'tip': 'Tip:',
    }
}

def get_current_language():
    """Получить текущий язык из сессии"""
    return session.get('language', 'ru')

def set_language(lang):
    """Установить язык в сессии"""
    if lang in TRANSLATIONS:
        session['language'] = lang
        return True
    return False

def t(key, **kwargs):
    """Функция перевода"""
    lang = get_current_language()
    translation = TRANSLATIONS.get(lang, TRANSLATIONS['ru']).get(key, key)
    
    # Подстановка переменных
    if kwargs:
        translation = translation.format(**kwargs)
    
    return translation

def get_available_languages():
    """Получить список доступных языков"""
    return {
        'ru': 'Русский',
        'en': 'English'
    } 