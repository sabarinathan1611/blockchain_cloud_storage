from flask import Flask,session,flash,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,current_user,logout_user
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from .config import get_config
import os
from flask_cors import CORS
from logging.handlers import RotatingFileHandler
from sqlalchemy import event
from flask_apscheduler import APScheduler
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from datetime import timedelta,datetime
import logging

db = SQLAlchemy()

mail = Mail()
scheduler=APScheduler()
csrf = CSRFProtect()
# DB_NAME = "database.db"
engine=None
Session=None


def create_app(mode='default'):
    app = Flask(__name__)

    app.config.from_object(get_config(mode))

    # Configure the upload folder
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))
    up_folder=os.path.join('static','uploads')
    dc_folder=os.path.join('static','Decrypt')
    UPLOAD_FOLDER = os.path.join(APP_ROOT, up_folder)
    
    DECRYPT_FOLDER=os.path.join(APP_ROOT, dc_folder)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['DECRYPT_FOLDER'] = DECRYPT_FOLDER
    app.config['STATIC_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    key=os.path.join('static','key')
    KEY_FOLDER = os.path.join(app.root_path, key)
    app.config['KEY_FOLDER'] = KEY_FOLDER
    print("app.root_path : ",app.root_path)
    # Initialize database
    db.init_app(app)
    # migrate = Migrate(app, db)  

    # Initialize CSRF protection
    csrf.init_app(app)
    cors = CORS(app, resources={r"/*": {"origins": "0.0.0.0", "supports_credentials": True}})
  

    # Initialize Flask-Mail
    mail.init_app(app)
    scheduler.init_app(app)
    scheduler.start()

    # Register blueprints
    from .auth import auth
    from .view import view

    app.register_blueprint(view, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    # Import models and create tables
    from .models import User, Text, File
    with app.app_context():
        db.create_all()

    # Initialize login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    login_manager.refresh_view = 'auth.login'
    @app.before_request
    def before_request():
        if current_user.is_authenticated:
            now = datetime.now()  # Naive datetime
            if 'last_active' in session:
                last_active_str = session['last_active']
                if isinstance(last_active_str, str):  # Ensure it's a string before conversion
                    last_active = datetime.fromisoformat(last_active_str)  # Convert stored string back to datetime
                    if (now - last_active).seconds > 12000:  # 2 minutes
                        logout_user()
                        flash('You have been logged out due to inactivity.')
                        return redirect(url_for('auth.login'))
            session['last_active'] = now.isoformat() 

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    create_database(app)
    engine = create_engine(str(app.config['SQLALCHEMY_DATABASE_URI']))
    Session = sessionmaker(bind=engine)

    return app

def create_database(app):
    with app.app_context():
        db.create_all()
    print('Initialized Database!')

