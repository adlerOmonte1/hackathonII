import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps

# --- CONFIGURACIÓN ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_hackathon' # Cambia esto si quieres
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hackathon.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Si no estás logueado, te manda aquí

# --- BASE DE DATOS (MODELO DE USUARIO) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100)) # En hackathon guardamos texto plano para velocidad
    role = db.Column(db.String(20), default='user') # 'admin' o 'user'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DECORADOR DE ROLES (LA SEGURIDAD) ---
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role_name:
                flash('⛔ Acceso denegado: No tienes el rol necesario.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- RUTAS ---

@app.route('/', methods=['GET', 'POST'])
def login():
    # Si ya entró, lo mandamos a su dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos', 'warning')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # EL CEREBRO: Decide qué plantilla mostrar según el rol
    if current_user.role == 'admin':
        return render_template('dashboard_admin.html')
    else:
        return render_template('dashboard_user.html')

# --- RUTAS ESPECÍFICAS PROTEGIDAS (EJEMPLOS) ---

@app.route('/zona_admin')
@role_required('admin') # <--- Solo Admin entra aquí
def zona_admin():
    return "<h1>Área Secreta del Administrador</h1><a href='/dashboard'>Volver</a>"

# --- INICIALIZADOR (MAGIA) ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Crea la BD si no existe
        
        # Crea usuario ADMIN si no existe
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password='123', role='admin'))
            print("👑 Usuario ADMIN creado: admin / 123")
            
        # Crea usuario NORMAL si no existe
        if not User.query.filter_by(username='user').first():
            db.session.add(User(username='user', password='123', role='user'))
            print("👤 Usuario USER creado: user / 123")
            
        db.session.commit()
        
    app.run(debug=True)