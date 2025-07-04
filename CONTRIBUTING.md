# Contributing to Cloudflare Dynamic DNS Manager

Спасибо за интерес к участию в развитии проекта! 🎉

## 🚀 Как помочь проекту

### Способы участия
1. **Сообщения об ошибках** - если нашли баг, создайте Issue
2. **Предложения улучшений** - новые идеи и функции приветствуются
3. **Код** - Pull Request с исправлениями или новыми функциями
4. **Документация** - улучшение README, добавление примеров
5. **Переводы** - добавление новых языков интерфейса
6. **Тестирование** - проверка работы на разных ОС и конфигурациях

## 🐛 Сообщения об ошибках

### Перед созданием Issue проверьте:
- [ ] Проблема еще не была описана в существующих Issues
- [ ] Вы используете последнею версию проекта
- [ ] Проблема воспроизводится стабильно

### Шаблон для Bug Report:
```markdown
**Описание проблемы**
Краткое описание того, что произошло.

**Шаги для воспроизведения**
1. Перейти к '...'
2. Нажать на '...'
3. Увидеть ошибку

**Ожидаемое поведение**
Что должно было произойти.

**Скриншоты**
Если применимо, добавьте скриншоты.

**Окружение:**
- ОС: [e.g. Ubuntu 20.04]
- Python версия: [e.g. 3.9.7]
- Метод запуска: [Docker/локально]
- Версия проекта: [e.g. 1.0.0]

**Дополнительная информация**
Логи, конфигурации и другая полезная информация.
```

## 💡 Предложения улучшений

### Шаблон для Feature Request:
```markdown
**Описание функции**
Ясное описание того, что вы хотите добавить.

**Мотивация**
Почему эта функция нужна? Какую проблему она решает?

**Предлагаемое решение**
Как вы видите реализацию этой функции?

**Альтернативы**
Рассматривали ли другие варианты решения?

**Дополнительная информация**
Скриншоты, ссылки, примеры из других проектов.
```

## 🔧 Разработка

### Настройка окружения для разработки

1. **Fork репозиторий**
   ```bash
   # Клонировать ваш fork
   git clone https://github.com/YOUR_USERNAME/cloudflare-dns-manager.git
   cd cloudflare-dns-manager
   
   # Добавить upstream
   git remote add upstream https://github.com/ORIGINAL_OWNER/cloudflare-dns-manager.git
   ```

2. **Создать виртуальное окружение**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # или
   venv\Scripts\activate     # Windows
   ```

3. **Установить зависимости для разработки**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # если есть dev зависимости
   ```

4. **Настроить pre-commit hooks (опционально)**
   ```bash
   pre-commit install
   ```

### Структура проекта
```
cloudflare-dns-manager/
├── app.py                 # Основное Flask приложение
├── translations.py        # Система переводов
├── templates/            # HTML шаблоны
│   ├── base.html         # Базовый шаблон
│   ├── index.html        # Главная страница
│   ├── add_config.html   # Добавление конфигурации
│   ├── edit_config.html  # Редактирование
│   ├── settings.html     # Настройки
│   └── login.html        # Вход в систему
├── instance/             # База данных (создается автоматически)
├── requirements.txt      # Python зависимости
├── Dockerfile           # Docker конфигурация
├── docker-compose.yml   # Docker Compose
└── tests/               # Тесты (планируется)
```

### Запуск в режиме разработки
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
python app.py
```

### Стиль кода

#### Python
- Следуйте **PEP 8**
- Используйте **type hints** где возможно
- Максимальная длина строки: **88 символов** (Black formatter)
- Названия функций и переменных: **snake_case**
- Названия классов: **PascalCase**

#### HTML/CSS
- **2 spaces** для отступов
- **Семантический HTML5**
- **Mobile-first** подход
- Используйте **CSS переменные** для цветов и размеров

#### JavaScript
- **ES6+** синтаксис
- **2 spaces** для отступов
- **camelCase** для переменных и функций
- Используйте **const/let** вместо **var**

### Коммиты

#### Формат сообщений коммитов:
```
type(scope): краткое описание

Подробное описание (если нужно)

Fixes #123
```

#### Типы коммитов:
- `feat`: новая функция
- `fix`: исправление ошибки
- `docs`: изменения в документации
- `style`: форматирование, отсутствие изменений в коде
- `refactor`: рефакторинг кода
- `test`: добавление тестов
- `chore`: обновление зависимостей, конфигурации

#### Примеры:
```bash
feat(auth): добавить двухфакторную аутентификацию
fix(dns): исправить обновление DDNS записей
docs(readme): обновить инструкции по установке
style(ui): улучшить мобильную версию интерфейса
```

## 🌍 Добавление переводов

### Добавление нового языка:

1. **Обновить `translations.py`:**
   ```python
   TRANSLATIONS = {
       'ru': { ... },
       'en': { ... },
       'de': {  # Новый язык
           'dns_manager': 'DNS Manager',
           'home': 'Startseite',
           # ... другие переводы
       }
   }
   ```

2. **Обновить функцию языков:**
   ```python
   def get_available_languages():
       return {
           'ru': 'Русский',
           'en': 'English',
           'de': 'Deutsch'  # Новый язык
       }
   ```

3. **Протестировать переводы** во всех разделах интерфейса

## 🧪 Тестирование

### Ручное тестирование
- [ ] Создание/редактирование/удаление конфигураций
- [ ] Смена языка интерфейса
- [ ] Управление токенами
- [ ] Аутентификация пользователей  
- [ ] Мобильная версия
- [ ] Docker контейнер

### Автоматические тесты (планируется)
```bash
# Запуск тестов
python -m pytest

# С покрытием кода
python -m pytest --cov=app
```

## 📝 Pull Request Process

### Чеклист перед отправкой PR:
- [ ] Код соответствует стилю проекта
- [ ] Добавлены/обновлены переводы (если нужно)
- [ ] Протестированы изменения
- [ ] Обновлена документация (если нужно)
- [ ] Коммиты имеют понятные сообщения
- [ ] PR описывает что изменено и зачем

### Шаблон описания PR:
```markdown
## Описание
Краткое описание изменений.

## Тип изменений
- [ ] Bug fix (исправление ошибки)
- [ ] New feature (новая функция)
- [ ] Breaking change (изменения с нарушением обратной совместимости)
- [ ] Documentation update (обновление документации)

## Как тестировать
Шаги для проверки изменений:
1. ...
2. ...

## Скриншоты (если применимо)

## Чеклист
- [ ] Мой код следует стилю проекта
- [ ] Я провел самопроверку кода
- [ ] Я протестировал изменения
- [ ] Новый код покрыт тестами
- [ ] Обновлена документация

## Связанные Issues
Fixes #(номер issue)
```

## 🤝 Сообщество

### Будьте вежливы
- Используйте дружелюбный тон
- Будьте терпеливы с новичками
- Помогайте другим разработчикам
- Придерживайтесь [Кодекса поведения](CODE_OF_CONDUCT.md)

### Коммуникация
- **Issues** - для обсуждения багов и предложений
- **Pull Requests** - для обсуждения кода
- **Discussions** - для общих вопросов и идей

## 🏷️ Релизы

### Версионирование
Проект использует [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (например, 1.2.3)
- **MAJOR** - несовместимые изменения API
- **MINOR** - новая функциональность с обратной совместимостью  
- **PATCH** - исправления ошибок

### Процесс релиза
1. Обновить `CHANGELOG.md`
2. Создать тег версии
3. Автоматическая сборка Docker образа
4. Публикация релиза на GitHub

## ❓ Вопросы?

Если у вас есть вопросы:
1. Проверьте [FAQ в README](README.md#-частые-вопросы)
2. Поищите в существующих Issues
3. Создайте новый Issue с меткой "question"

---

Спасибо за вашу помощь в развитии проекта! 🚀 