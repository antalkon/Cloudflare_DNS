# Cloudflare Dynamic DNS Manager

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)

**Современный веб-интерфейс для автоматического обновления DNS записей Cloudflare для серверов с динамическими IP адресами.**

## ✨ Особенности

- 🌍 **Многоязычность** - Поддержка русского и английского языков
- 🔐 **Безопасность** - Аутентификация пользователей и управление API токенами
- ⚡ **Автоматизация** - Автоматическое обновление DNS записей по расписанию
- 🎨 **Современный UI** - Адаптивный интерфейс с голубой минималистичной темой
- 🐳 **Docker Ready** - Готовые конфигурации для контейнеризации
- 📱 **Мобильная поддержка** - Полностью адаптивный дизайн
- 🔧 **DDNS поддержка** - Получение IP с внешних DDNS серверов
- 👥 **Мультипользовательский** - Поддержка нескольких пользователей с ролями

## 🚀 Быстрый старт

### 📦 Мгновенное развертывание (рекомендуется)

**Один файл - вся система:**
```bash
# Скачать и запустить автоматический установщик
curl -sSL https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/install.sh | bash

# Или с wget
wget -qO- https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/install.sh | bash
```

**Неинтерактивная установка:**
```bash
curl -sSL https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/install.sh | bash -s -- -y
```

**Ручная установка через Docker Compose:**
```bash
# Скачать standalone конфигурацию
wget https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/docker-compose.standalone.yml -O docker-compose.yml

# Запустить
docker-compose up -d
```

---

### 🔧 Разработка (Docker)

```bash
# Клонировать репозиторий
git clone https://github.com/antalkon/cloudflare-dns-manager.git
cd cloudflare-dns-manager

# Запустить с Docker Compose
docker-compose up -d
```

### 📋 Ручная установка

1. **Установить зависимости:**
```bash
pip install -r requirements.txt
```

2. **Запустить приложение:**
```bash
python app.py
```

---

**Приложение будет доступно по адресу:** `http://localhost:4545`

**Данные по умолчанию:**
- Логин: `admin`
- Пароль: `admin123`

⚠️ **Обязательно смените пароль после первого входа!**

## 📖 Подробная установка

### Системные требования

- Python 3.8 или выше
- SQLite (включен в Python)
- 512MB RAM (минимум)
- 100MB свободного места на диске

### Установка из исходного кода

1. **Клонировать репозиторий:**
```bash
git clone https://github.com/antalkon/cloudflare-dns-manager.git
cd cloudflare-dns-manager
```

2. **Создать виртуальное окружение:**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate  # Windows
```

3. **Установить зависимости:**
```bash
pip install -r requirements.txt
```

4. **Настроить переменные окружения (опционально):**
```bash
export SECRET_KEY="your-secret-key-here"
export FLASK_ENV="production"
```

5. **Запустить приложение:**
```bash
python app.py
```

### Standalone развертывание на сервере

**Полностью автоматическая установка:**
```bash
# Установка с интерактивным конфигуратором
curl -sSL https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/install.sh | bash

# Быстрая установка без вопросов
curl -sSL https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/install.sh | bash -s -- -y
```

**Ручная установка:**
```bash
# 1. Скачать конфигурацию
wget https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/docker-compose.standalone.yml -O docker-compose.yml

# 2. Настроить переменные (опционально)
echo "SECRET_KEY=$(openssl rand -hex 32)" > .env
echo "DOMAIN_NAME=your-domain.com" >> .env

# 3. Запустить
docker-compose up -d
```

### Docker Compose (Production)

Создайте файл `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  cloudflare-dns:
    build: .
    container_name: cloudflare-dns-manager
    restart: unless-stopped
    ports:
      - "80:4545"
    volumes:
      - ./data:/app/instance
    environment:
      - SECRET_KEY=your-very-secure-secret-key-here
      - FLASK_ENV=production
    networks:
      - dns-network

networks:
  dns-network:
    driver: bridge

volumes:
  dns-data:
    driver: local
```

Запуск:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

## 🚀 Развертывание на сервере (один файл)

Самый простой способ развернуть приложение на любом сервере с Docker:

1. **Создать директорию:**
```bash
mkdir cloudflare-dns && cd cloudflare-dns
```

2. **Скачать и запустить:**
```bash
bash <(curl -s https://raw.githubusercontent.com/antalkon/cloudflare-dns-manager/main/install.sh)
```

3. **Простая настройка:**
- Порт 4545 для веб-интерфейса
- Персистентное хранение данных

4. **Управление:**
```bash
# Просмотр логов
docker-compose logs -f

# Остановка
docker-compose down

# Обновление
docker-compose pull && docker-compose up -d

# Полная очистка (ВНИМАНИЕ: удалит все данные)
docker-compose down -v
```

## 🔧 Настройка

### 1. Получение Cloudflare API токена

1. Войдите в [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Перейдите в **My Profile** → **API Tokens**
3. Нажмите **Create Token**
4. Выберите шаблон **Custom token**
5. Настройте права:
   - **Permissions**: `Zone:Edit, DNS:Edit`
   - **Zone Resources**: `Include All zones` или выберите конкретные домены

### 2. Добавление токена в приложение

1. Войдите в веб-интерфейс
2. Перейдите в **Настройки**
3. В разделе **Cloudflare API Токены** нажмите **Добавить токен**
4. Введите название и токен
5. Сохраните

### 3. Создание DNS конфигурации

1. На главной странице нажмите **Добавить домен**
2. Выберите токен из списка
3. Выберите домен
4. Настройте параметры:
   - **Поддомен** (опционально): api, www, mail и т.д.
   - **Интервал обновления**: от 5 до 1440 минут
   - **DDNS URL** (опционально): для получения IP с другого сервера

## 🌐 Использование DDNS URL

Если ваш сервер находится за NAT или вы хотите получать IP с другого сервера:

```bash
# Примеры DDNS URL:
https://your-server.com/ip
http://192.168.1.100:8080/current-ip
https://api.ipify.org
```

Сервер должен возвращать:
- Простой текст с IP: `203.0.113.1`
- JSON с полем "ip": `{"ip": "203.0.113.1"}`
- JSON с полем "address": `{"address": "203.0.113.1"}`

## 🎨 Интерфейс

### Темы
Приложение использует современную голубую минималистичную тему с:
- Адаптивным дизайном
- Темными и светлыми элементами
- Анимированными переходами
- Мобильной оптимизацией

### Языки
- 🇷🇺 Русский
- 🇬🇧 English

Переключение языка доступно в верхнем меню.

## 🔐 Безопасность

### Пользователи и роли
- **Администратор**: полный доступ ко всем функциям
- **Пользователь**: доступ только к своим конфигурациям

### Рекомендации
1. Смените пароль администратора по умолчанию
2. Используйте сложные пароли
3. Регулярно ротируйте API токены
4. Используйте HTTPS в production
5. Ограничьте доступ по IP если возможно

## 📊 API

### Endpoints

```http
GET    /api/configs           # Получить конфигурации
POST   /api/configs           # Создать конфигурацию
PUT    /api/configs/{id}      # Обновить конфигурацию
DELETE /api/configs/{id}      # Удалить конфигурацию
POST   /api/configs/{id}/update # Обновить DNS вручную

GET    /api/tokens            # Получить токены
POST   /api/tokens            # Создать токен
PUT    /api/tokens/{id}       # Обновить токен
DELETE /api/tokens/{id}       # Удалить токен

GET    /api/zones/{token_id}  # Получить домены токена
```

## 🐳 Docker

### Сборка образа
```bash
docker build -t cloudflare-dns-manager .
```

### Запуск контейнера
```bash
docker run -d \
  --name cloudflare-dns \
  -p 4545:4545 \
  -v $(pwd)/data:/app/instance \
  -e SECRET_KEY="your-secret-key" \
  cloudflare-dns-manager
```

## 🔧 Разработка

### Структура проекта
```
cloudflare-dns-manager/
├── app.py                 # Основное приложение Flask
├── translations.py        # Система переводов
├── requirements.txt       # Python зависимости
├── Dockerfile            # Docker конфигурация
├── docker-compose.yml    # Docker Compose
├── templates/            # HTML шаблоны
│   ├── base.html
│   ├── index.html
│   ├── add_config.html
│   ├── edit_config.html
│   ├── settings.html
│   └── login.html
├── instance/             # База данных (создается автоматически)
└── README.md
```

### Добавление нового языка

1. Обновите `translations.py`:
```python
TRANSLATIONS = {
    'ru': { ... },
    'en': { ... },
    'de': {  # Новый язык
        'dns_manager': 'DNS Manager',
        # ... другие переводы
    }
}
```

2. Обновите функцию `get_available_languages()`:
```python
return {
    'ru': 'Русский',
    'en': 'English',
    'de': 'Deutsch'  # Новый язык
}
```

### Запуск в режиме разработки
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
python app.py
```

## ❓ Часто задаваемые вопросы

**Q: Как часто обновляются DNS записи?**
A: Интервал настраивается индивидуально для каждого домена от 5 до 1440 минут.

**Q: Можно ли использовать несколько токенов?**
A: Да, вы можете добавить несколько токенов и выбирать нужный при создании конфигурации.

**Q: Поддерживаются ли IPv6 адреса?**
A: В текущей версии поддерживаются только IPv4 адреса (A записи).

**Q: Что делать если IP не обновляется?**
A: Проверьте логи приложения, корректность API токена и доступность домена.

## 🐛 Устранение неисправностей

### База данных заблокирована
```bash
# Остановить приложение и удалить lock файл
rm instance/dns_manager.db-wal
rm instance/dns_manager.db-shm
```

### Сброс пароля администратора
```bash
# Удалить базу данных (потеряются все данные!)
rm instance/dns_manager.db
# Перезапустить приложение - будет создан пользователь по умолчанию
```

### Проблемы с Docker
```bash
# Просмотр логов
docker logs cloudflare-dns-manager

# Перезапуск контейнера
docker restart cloudflare-dns-manager
```

## 🤝 Участие в разработке

1. Fork репозиторий
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Создайте Pull Request

## 📝 Лицензия

Этот проект лицензирован под MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 🙏 Благодарности

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Bootstrap](https://getbootstrap.com/) - CSS framework
- [Cloudflare](https://www.cloudflare.com/) - DNS services
- [Font Awesome](https://fontawesome.com/) - Icons

## 📞 Поддержка

Если у вас есть вопросы или проблемы:

1. Проверьте [Issues](https://github.com/antalkon/cloudflare-dns-manager/issues)
2. Создайте новый Issue с подробным описанием
3. Приложите логи и скриншоты если возможно

---

⭐ **Если проект оказался полезным, поставьте звездочку!** 