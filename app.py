from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
import sqlite3
import os
import json
from datetime import datetime
import logging
from translations import t, get_current_language, set_language, get_available_languages

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Путь к базе данных в instance директории (для Docker volume)
instance_path = os.path.join(os.path.dirname(__file__), 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
    print(f"Создана директория: {instance_path}")
print(f"Путь к базе данных: {instance_path}")

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "dns_manager.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
scheduler = BackgroundScheduler()

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Регистрируем функцию перевода в шаблонах
@app.context_processor
def inject_translation():
    return {
        't': t,
        'get_current_language': get_current_language,
        'get_available_languages': get_available_languages
    }

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat()
        }

class CloudflareToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('tokens', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'domains_count': len(self.get_domains())
        }
    
    def get_domains(self):
        try:
            cf_api = CloudflareAPI(self.token)
            return cf_api.get_zones()
        except:
            return []

class DNSConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('cloudflare_token.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    subdomain = db.Column(db.String(255), nullable=True)  # None для корневого домена
    update_interval = db.Column(db.Integer, nullable=False, default=30)  # минуты
    is_active = db.Column(db.Boolean, default=True)
    last_ip = db.Column(db.String(45), nullable=True)
    last_update = db.Column(db.DateTime, nullable=True)
    ddns_url = db.Column(db.String(500), nullable=True)  # URL для DDNS проверки
    proxy_status = db.Column(db.String(10), nullable=False, default='auto')  # auto, on, off
    ttl = db.Column(db.Integer, nullable=True, default=None)  # None для auto, или секунды
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    token = db.relationship('CloudflareToken', backref=db.backref('dns_configs', lazy=True))
    user = db.relationship('User', backref=db.backref('dns_configs', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'token_id': self.token_id,
            'token_name': self.token.name if self.token else 'Удален',
            'domain': self.domain,
            'subdomain': self.subdomain,
            'update_interval': self.update_interval,
            'is_active': self.is_active,
            'last_ip': self.last_ip,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'ddns_url': self.ddns_url,
            'proxy_status': self.proxy_status,
            'ttl': self.ttl,
            'created_at': self.created_at.isoformat()
        }

class CloudflareAPI:
    def __init__(self, token):
        self.token = token
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def get_zones(self):
        """Получить все зоны (домены) пользователя"""
        try:
            response = requests.get(f"{self.base_url}/zones", headers=self.headers)
            response.raise_for_status()
            return response.json()['result']
        except Exception as e:
            logger.error(f"Ошибка получения зон: {e}")
            return []

    def get_dns_records(self, zone_id, name=None):
        """Получить DNS записи для зоны"""
        try:
            params = {"type": "A"}
            if name:
                params["name"] = name
            
            response = requests.get(f"{self.base_url}/zones/{zone_id}/dns_records", 
                                  headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()['result']
        except Exception as e:
            logger.error(f"Ошибка получения DNS записей: {e}")
            return []

    def update_dns_record(self, zone_id, record_id, name, ip, proxy_status='auto', ttl=None):
        """Обновить DNS запись"""
        try:
            data = {
                "type": "A",
                "name": name,
                "content": ip
            }
            
            # TTL настройки
            if ttl is None:
                data["ttl"] = 1  # Auto TTL
            else:
                data["ttl"] = ttl
            
            # Proxy настройки
            if proxy_status == 'auto':
                # Получаем текущие настройки записи
                current_record = self.get_dns_record_by_id(zone_id, record_id)
                if current_record:
                    data["proxied"] = current_record.get('proxied', False)
                else:
                    data["proxied"] = False
            elif proxy_status == 'on':
                data["proxied"] = True
                data["ttl"] = 1  # Проксированные записи должны иметь TTL = 1
            else:  # off
                data["proxied"] = False
            
            response = requests.put(f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                                  headers=self.headers, json=data)
            response.raise_for_status()
            return response.json()['success']
        except Exception as e:
            logger.error(f"Ошибка обновления DNS записи: {e}")
            return False

    def create_dns_record(self, zone_id, name, ip, proxy_status='auto', ttl=None):
        """Создать новую DNS запись"""
        try:
            data = {
                "type": "A",
                "name": name,
                "content": ip
            }
            
            # TTL настройки
            if ttl is None:
                data["ttl"] = 1  # Auto TTL
            else:
                data["ttl"] = ttl
            
            # Proxy настройки
            if proxy_status == 'on':
                data["proxied"] = True
                data["ttl"] = 1  # Проксированные записи должны иметь TTL = 1
            elif proxy_status == 'off':
                data["proxied"] = False
            else:  # auto
                data["proxied"] = False  # По умолчанию не проксируем новые записи
            
            response = requests.post(f"{self.base_url}/zones/{zone_id}/dns_records",
                                   headers=self.headers, json=data)
            response.raise_for_status()
            return response.json()['success']
        except Exception as e:
            logger.error(f"Ошибка создания DNS записи: {e}")
            return False
    
    def get_dns_record_by_id(self, zone_id, record_id):
        """Получить конкретную DNS запись по ID"""
        try:
            response = requests.get(f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                                  headers=self.headers)
            response.raise_for_status()
            return response.json()['result']
        except Exception as e:
            logger.error(f"Ошибка получения DNS записи: {e}")
            return None

def get_current_ip():
    """Получить текущий внешний IP адрес"""
    try:
        response = requests.get('https://api.ipify.org', timeout=10)
        response.raise_for_status()
        return response.text.strip()
    except:
        try:
            response = requests.get('https://icanhazip.com', timeout=10)
            response.raise_for_status()
            return response.text.strip()
        except Exception as e:
            logger.error(f"Ошибка получения IP: {e}")
            return None

def get_ip_from_ddns(ddns_url):
    """Получить IP адрес из DDNS URL"""
    try:
        response = requests.get(ddns_url, timeout=10)
        response.raise_for_status()
        
        # Попробуем извлечь IP из различных форматов ответа
        text = response.text.strip()
        
        # Если ответ содержит только IP
        if text.count('.') == 3 and all(part.isdigit() for part in text.split('.')):
            return text
            
        # Если ответ в JSON формате
        try:
            data = response.json()
            if 'ip' in data:
                return data['ip']
            elif 'address' in data:
                return data['address']
        except:
            pass
            
        # Попробуем найти IP в тексте с помощью регулярного выражения
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)
        if matches:
            return matches[0]
            
        return None
    except Exception as e:
        logger.error(f"Ошибка получения IP из DDNS {ddns_url}: {e}")
        return None

# Декораторы для авторизации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Доступ запрещен', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def create_default_user():
    """Создать пользователя по умолчанию если нет пользователей"""
    if User.query.count() == 0:
        user = User(username='admin', is_admin=True)
        user.set_password('admin123')
        db.session.add(user)
        db.session.commit()
        logger.info("Создан пользователь по умолчанию: admin/admin123")

def update_dns_record(config_id):
    """Обновить DNS запись для конкретной конфигурации"""
    try:
        config = DNSConfig.query.get(config_id)
        if not config or not config.is_active or not config.token:
            return False

        # Получаем текущий IP
        if config.ddns_url:
            current_ip = get_ip_from_ddns(config.ddns_url)
        else:
            current_ip = get_current_ip()

        if not current_ip:
            logger.error(f"Не удалось получить IP для конфигурации {config_id}")
            return False

        # Проверяем, изменился ли IP
        if config.last_ip == current_ip:
            logger.info(f"IP не изменился для {config.domain}/{config.subdomain}: {current_ip}")
            return True

        # Инициализируем Cloudflare API
        cf_api = CloudflareAPI(config.token.token)
        
        # Получаем зоны для поиска нужного домена
        zones = cf_api.get_zones()
        target_zone = None
        
        for zone in zones:
            if zone['name'] == config.domain:
                target_zone = zone
                break

        if not target_zone:
            logger.error(f"Домен {config.domain} не найден в Cloudflare")
            return False

        # Формируем полное имя записи
        record_name = config.domain if not config.subdomain else f"{config.subdomain}.{config.domain}"
        
        # Получаем существующие DNS записи
        records = cf_api.get_dns_records(target_zone['id'], record_name)
        
        success = False
        if records:
            # Обновляем существующую запись
            record = records[0]
            success = cf_api.update_dns_record(target_zone['id'], record['id'], record_name, current_ip,
                                             config.proxy_status, config.ttl)
        else:
            # Создаем новую запись
            success = cf_api.create_dns_record(target_zone['id'], record_name, current_ip,
                                             config.proxy_status, config.ttl)

        if success:
            config.last_ip = current_ip
            config.last_update = datetime.utcnow()
            db.session.commit()
            logger.info(f"DNS запись обновлена: {record_name} -> {current_ip}")
        else:
            logger.error(f"Ошибка обновления DNS записи для {record_name}")

        return success

    except Exception as e:
        logger.error(f"Ошибка при обновлении DNS записи {config_id}: {e}")
        return False

# Маршруты авторизации
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Принудительная проверка и создание таблиц
    try:
        # Пытаемся выполнить простой запрос к таблице user
        User.query.first()
    except Exception as e:
        print(f"Таблицы не найдены, создаем принудительно: {e}")
        try:
            db.drop_all()  # Удаляем все таблицы
            db.create_all()  # Создаем заново
            create_default_user()  # Создаем админа
            print("Таблицы пересозданы успешно")
        except Exception as e2:
            print(f"Ошибка пересоздания таблиц: {e2}")
            return f"Ошибка базы данных: {e2}", 500
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/set-language/<lang>')
def set_language_route(lang):
    if set_language(lang):
        return redirect(request.referrer or url_for('index'))
    return redirect(request.referrer or url_for('index'))

@app.route('/health')
def health_check():
    """Health check endpoint для мониторинга"""
    try:
        # Простая проверка базы данных
        db.session.execute('SELECT 1')
        db.session.commit()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 503

@app.route('/debug-db')
def debug_db():
    """Диагностика базы данных"""
    try:
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        db_info = {
            'database_uri': app.config['SQLALCHEMY_DATABASE_URI'],
            'tables': tables,
            'instance_path': instance_path,
            'db_file_exists': os.path.exists(os.path.join(instance_path, 'dns_manager.db'))
        }
        
        if 'user' in tables:
            user_count = User.query.count()
            db_info['user_count'] = user_count
        
        return jsonify(db_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/init-db')
def init_db_route():
    """Принудительная инициализация базы данных"""
    try:
        db.drop_all()
        db.create_all()
        create_default_user()
        
        return jsonify({
            'status': 'success',
            'message': 'База данных инициализирована',
            'tables_created': db.inspect(db.engine).get_table_names()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Маршруты веб-интерфейса
@app.route('/')
@login_required
def index():
    user = get_current_user()
    configs = DNSConfig.query.filter_by(user_id=user.id).all()
    return render_template('index.html', configs=configs, user=user)

@app.route('/add')
@login_required
def add_config():
    user = get_current_user()
    tokens = CloudflareToken.query.filter_by(user_id=user.id, is_active=True).all()
    return render_template('add_config.html', tokens=tokens, user=user)

@app.route('/edit/<int:config_id>')
@login_required
def edit_config(config_id):
    user = get_current_user()
    config = DNSConfig.query.filter_by(id=config_id, user_id=user.id).first_or_404()
    tokens = CloudflareToken.query.filter_by(user_id=user.id, is_active=True).all()
    return render_template('edit_config.html', config=config, tokens=tokens, user=user)

@app.route('/settings')
@login_required
def settings():
    user = get_current_user()
    tokens = CloudflareToken.query.filter_by(user_id=user.id).all()
    return render_template('settings.html', tokens=tokens, user=user)

@app.route('/users')
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

# API маршруты
@app.route('/api/configs', methods=['GET'])
@login_required
def get_configs():
    user = get_current_user()
    configs = DNSConfig.query.filter_by(user_id=user.id).all()
    return jsonify([config.to_dict() for config in configs])

@app.route('/api/configs', methods=['POST'])
@login_required
def create_config():
    try:
        data = request.get_json()
        user = get_current_user()
        
        # Валидация обязательных полей
        required_fields = ['token_id', 'domain']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Поле {field} обязательно'}), 400

        # Проверяем, что токен принадлежит пользователю
        token = CloudflareToken.query.filter_by(
            id=data['token_id'], 
            user_id=user.id, 
            is_active=True
        ).first()
        
        if not token:
            return jsonify({'error': 'Токен не найден или неактивен'}), 400

        # Проверяем токен Cloudflare
        cf_api = CloudflareAPI(token.token)
        zones = cf_api.get_zones()
        
        # Проверяем, что домен существует в аккаунте
        domain_exists = any(zone['name'] == data['domain'] for zone in zones)
        if not domain_exists:
            return jsonify({'error': f'Домен {data["domain"]} не найден в этом токене'}), 400

        config = DNSConfig(
            token_id=data['token_id'],
            domain=data['domain'],
            subdomain=data.get('subdomain'),
            update_interval=data.get('update_interval', 30),
            ddns_url=data.get('ddns_url'),
            proxy_status=data.get('proxy_status', 'auto'),
            ttl=data.get('ttl'),
            user_id=user.id
        )
        
        db.session.add(config)
        db.session.commit()

        # Добавляем задачу в планировщик
        add_scheduler_job(config)

        return jsonify(config.to_dict()), 201

    except Exception as e:
        logger.error(f"Ошибка создания конфигурации: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/configs/<int:config_id>', methods=['PUT'])
@login_required
def update_config(config_id):
    try:
        user = get_current_user()
        config = DNSConfig.query.filter_by(id=config_id, user_id=user.id).first_or_404()
        data = request.get_json()

        # Обновляем поля
        if 'token_id' in data:
            # Проверяем, что новый токен принадлежит пользователю
            token = CloudflareToken.query.filter_by(
                id=data['token_id'], 
                user_id=user.id, 
                is_active=True
            ).first()
            if token:
                config.token_id = data['token_id']
                
        if 'domain' in data:
            config.domain = data['domain']
        if 'subdomain' in data:
            config.subdomain = data['subdomain']
        if 'update_interval' in data:
            config.update_interval = data['update_interval']
        if 'ddns_url' in data:
            config.ddns_url = data['ddns_url']
        if 'proxy_status' in data:
            config.proxy_status = data['proxy_status']
        if 'ttl' in data:
            config.ttl = data['ttl']
        if 'is_active' in data:
            config.is_active = data['is_active']

        db.session.commit()

        # Обновляем задачу в планировщике
        remove_scheduler_job(config.id)
        add_scheduler_job(config)

        return jsonify(config.to_dict())

    except Exception as e:
        logger.error(f"Ошибка обновления конфигурации: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/configs/<int:config_id>', methods=['DELETE'])
@login_required
def delete_config(config_id):
    try:
        user = get_current_user()
        config = DNSConfig.query.filter_by(id=config_id, user_id=user.id).first_or_404()
        
        # Удаляем задачу из планировщика
        remove_scheduler_job(config.id)

        db.session.delete(config)
        db.session.commit()

        return jsonify({'message': 'Конфигурация удалена'})

    except Exception as e:
        logger.error(f"Ошибка удаления конфигурации: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/configs/<int:config_id>/update', methods=['POST'])
@login_required
def manual_update(config_id):
    try:
        user = get_current_user()
        config = DNSConfig.query.filter_by(id=config_id, user_id=user.id).first()
        if not config:
            return jsonify({'error': 'Конфигурация не найдена'}), 404
            
        success = update_dns_record(config_id)
        if success:
            return jsonify({'message': 'DNS запись обновлена успешно'})
        else:
            return jsonify({'error': 'Ошибка обновления DNS записи'}), 500
    except Exception as e:
        logger.error(f"Ошибка ручного обновления: {e}")
        return jsonify({'error': str(e)}), 500

# API для управления пользователями (только админы)
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    try:
        data = request.get_json()
        
        required_fields = ['username', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Поле {field} обязательно'}), 400

        # Проверяем уникальность имени пользователя
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Пользователь с таким именем уже существует'}), 400

        user = User(
            username=data['username'],
            is_admin=data.get('is_admin', False)
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()

        return jsonify(user.to_dict()), 201

    except Exception as e:
        logger.error(f"Ошибка создания пользователя: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if 'username' in data:
            # Проверяем уникальность нового имени
            existing = User.query.filter_by(username=data['username']).first()
            if existing and existing.id != user_id:
                return jsonify({'error': 'Пользователь с таким именем уже существует'}), 400
            user.username = data['username']
            
        if 'password' in data and data['password']:
            user.set_password(data['password'])
            
        if 'is_admin' in data:
            user.is_admin = data['is_admin']
            
        db.session.commit()
        return jsonify(user.to_dict())

    except Exception as e:
        logger.error(f"Ошибка обновления пользователя: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Нельзя удалить самого себя
        current_user = get_current_user()
        if user.id == current_user.id:
            return jsonify({'error': 'Нельзя удалить собственный аккаунт'}), 400
            
        # Проверяем, не остался ли это единственный админ
        if user.is_admin:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count <= 1:
                return jsonify({'error': 'Нельзя удалить последнего администратора'}), 400
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'Пользователь удален'})

    except Exception as e:
        logger.error(f"Ошибка удаления пользователя: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/zones/<int:token_id>')
@login_required
def get_zones_for_token(token_id):
    try:
        user = get_current_user()
        token = CloudflareToken.query.filter_by(
            id=token_id, 
            user_id=user.id, 
            is_active=True
        ).first()
        
        if not token:
            return jsonify({'error': 'Токен не найден'}), 404
            
        cf_api = CloudflareAPI(token.token)
        zones = cf_api.get_zones()
        return jsonify([{'id': zone['id'], 'name': zone['name']} for zone in zones])
    except Exception as e:
        logger.error(f"Ошибка получения зон: {e}")
        return jsonify({'error': str(e)}), 500

# API для управления токенами
@app.route('/api/tokens', methods=['GET'])
@login_required
def get_tokens():
    user = get_current_user()
    tokens = CloudflareToken.query.filter_by(user_id=user.id).all()
    return jsonify([token.to_dict() for token in tokens])

@app.route('/api/tokens', methods=['POST'])
@login_required
def create_token():
    try:
        data = request.get_json()
        user = get_current_user()
        
        required_fields = ['name', 'token']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Поле {field} обязательно'}), 400

        # Проверяем токен
        cf_api = CloudflareAPI(data['token'])
        zones = cf_api.get_zones()
        
        if not zones:
            return jsonify({'error': 'Токен недействителен или не имеет доступа к зонам'}), 400

        token = CloudflareToken(
            name=data['name'],
            token=data['token'],
            user_id=user.id
        )
        
        db.session.add(token)
        db.session.commit()

        return jsonify(token.to_dict()), 201

    except Exception as e:
        logger.error(f"Ошибка создания токена: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tokens/<int:token_id>', methods=['PUT'])
@login_required
def update_token(token_id):
    try:
        user = get_current_user()
        token = CloudflareToken.query.filter_by(
            id=token_id, 
            user_id=user.id
        ).first()
        
        if not token:
            return jsonify({'error': 'Токен не найден'}), 404
            
        data = request.get_json()
        
        if 'name' in data:
            token.name = data['name']
        if 'token' in data:
            # Проверяем новый токен
            cf_api = CloudflareAPI(data['token'])
            zones = cf_api.get_zones()
            if not zones:
                return jsonify({'error': 'Новый токен недействителен'}), 400
            token.token = data['token']
        if 'is_active' in data:
            token.is_active = data['is_active']
            
        db.session.commit()
        return jsonify(token.to_dict())

    except Exception as e:
        logger.error(f"Ошибка обновления токена: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tokens/<int:token_id>', methods=['DELETE'])
@login_required
def delete_token(token_id):
    try:
        user = get_current_user()
        token = CloudflareToken.query.filter_by(
            id=token_id, 
            user_id=user.id
        ).first()
        
        if not token:
            return jsonify({'error': 'Токен не найден'}), 404
            
        # Проверяем, не используется ли токен в конфигурациях
        configs_count = DNSConfig.query.filter_by(token_id=token_id).count()
        if configs_count > 0:
            return jsonify({'error': f'Токен используется в {configs_count} конфигурациях'}), 400
            
        db.session.delete(token)
        db.session.commit()
        
        return jsonify({'message': 'Токен удален'})

    except Exception as e:
        logger.error(f"Ошибка удаления токена: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-ddns', methods=['POST'])
def test_ddns():
    try:
        data = request.get_json()
        ddns_url = data.get('ddns_url')
        
        if not ddns_url:
            return jsonify({'error': 'DDNS URL не указан'}), 400
            
        ip = get_ip_from_ddns(ddns_url)
        if ip:
            return jsonify({'ip': ip, 'success': True})
        else:
            return jsonify({'error': 'Не удалось получить IP из DDNS URL'}), 400
            
    except Exception as e:
        logger.error(f"Ошибка тестирования DDNS: {e}")
        return jsonify({'error': str(e)}), 500

def init_scheduler():
    """Инициализация планировщика задач"""
    try:
        if not scheduler.running:
            scheduler.start()
            print("Планировщик запущен")
        
        # Загружаем все активные конфигурации и добавляем задачи
        configs = DNSConfig.query.filter_by(is_active=True).all()
        active_configs = []
        
        for config in configs:
            if config.token and config.token.is_active:
                try:
                    job_id = f'dns_update_{config.id}'
                    
                    # Удаляем старую задачу если есть
                    try:
                        scheduler.remove_job(job_id)
                    except:
                        pass
                    
                    # Добавляем новую задачу
                    scheduler.add_job(
                        func=scheduler_update_dns,
                        trigger=IntervalTrigger(minutes=config.update_interval),
                        args=[config.id],
                        id=job_id,
                        replace_existing=True,
                        max_instances=1
                    )
                    active_configs.append(config)
                    print(f"Добавлена задача для {config.domain} (каждые {config.update_interval} мин)")
                except Exception as e:
                    print(f"Ошибка добавления задачи для конфигурации {config.id}: {e}")
        
        print(f"Планировщик запущен с {len(active_configs)} активными задачами")
        logger.info(f"Планировщик запущен с {len(active_configs)} активными задачами")
        
    except Exception as e:
        print(f"Ошибка инициализации планировщика: {e}")
        logger.error(f"Ошибка инициализации планировщика: {e}")

def scheduler_update_dns(config_id):
    """Обертка для обновления DNS в планировщике"""
    try:
        with app.app_context():
            print(f"Планировщик: обновление DNS для конфигурации {config_id}")
            result = update_dns_record(config_id)
            if result:
                print(f"Планировщик: DNS успешно обновлен для конфигурации {config_id}")
            else:
                print(f"Планировщик: Ошибка обновления DNS для конфигурации {config_id}")
    except Exception as e:
        print(f"Планировщик: Критическая ошибка для конфигурации {config_id}: {e}")
        logger.error(f"Планировщик: Критическая ошибка для конфигурации {config_id}: {e}")

def add_scheduler_job(config):
    """Добавить задачу в планировщик"""
    try:
        if not config.is_active or not config.token or not config.token.is_active:
            return
            
        job_id = f'dns_update_{config.id}'
        
        # Удаляем старую задачу если есть
        try:
            scheduler.remove_job(job_id)
        except:
            pass
        
        # Добавляем новую задачу
        scheduler.add_job(
            func=scheduler_update_dns,
            trigger=IntervalTrigger(minutes=config.update_interval),
            args=[config.id],
            id=job_id,
            replace_existing=True,
            max_instances=1
        )
        print(f"Добавлена задача для {config.domain} (каждые {config.update_interval} мин)")
        
    except Exception as e:
        print(f"Ошибка добавления задачи для конфигурации {config.id}: {e}")
        logger.error(f"Ошибка добавления задачи для конфигурации {config.id}: {e}")

def remove_scheduler_job(config_id):
    """Удалить задачу из планировщика"""
    try:
        job_id = f'dns_update_{config_id}'
        scheduler.remove_job(job_id)
        print(f"Удалена задача для конфигурации {config_id}")
    except Exception as e:
        if "No job by the id" not in str(e):
            print(f"Ошибка удаления задачи для конфигурации {config_id}: {e}")
            logger.error(f"Ошибка удаления задачи для конфигурации {config_id}: {e}")

@app.route('/api/scheduler/status')
@login_required
def scheduler_status():
    """Статус планировщика"""
    try:
        jobs = []
        if scheduler.running:
            for job in scheduler.get_jobs():
                jobs.append({
                    'id': job.id,
                    'name': str(job.func),
                    'trigger': str(job.trigger),
                    'next_run': job.next_run_time.isoformat() if job.next_run_time else None
                })
        
        return jsonify({
            'running': scheduler.running,
            'jobs_count': len(jobs),
            'jobs': jobs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scheduler/restart', methods=['POST'])
@admin_required  
def restart_scheduler():
    """Перезапуск планировщика"""
    try:
        if scheduler.running:
            scheduler.shutdown()
        
        init_scheduler()
        
        return jsonify({'message': 'Планировщик перезапущен'})
    except Exception as e:
        logger.error(f"Ошибка перезапуска планировщика: {e}")
        return jsonify({'error': str(e)}), 500

def init_database():
    """Инициализация базы данных с дополнительными проверками"""
    with app.app_context():
        try:
            # Принудительно создаем все таблицы
            db.create_all()
            print("База данных инициализирована")
            
            # Проверяем что таблицы действительно созданы
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"Созданные таблицы: {tables}")
            
            # Создаем пользователя по умолчанию
            create_default_user()
            
        except Exception as e:
            print(f"Ошибка инициализации базы данных: {e}")
            import traceback
            traceback.print_exc()
            raise

if __name__ == '__main__':
    # Инициализируем базу данных
    init_database()
    
    # Инициализируем планировщик в контексте приложения
    with app.app_context():
        init_scheduler()
    
    # Запускаем веб-сервер
    app.run(host='0.0.0.0', port=4545, debug=False, threaded=True) 