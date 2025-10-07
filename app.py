import io
import os
import secrets
import logging
import atexit
import requests  
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, send_file

from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from sqlalchemy import func
from threading import Thread
from PIL import Image
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# ========== ENVIRONMENT SETUP ==========
load_dotenv()

# ========== FLASK APP INITIALIZATION ==========
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))

# PRODUCTION: Use DATABASE_URL from environment (Supabase/Render auto-inject)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    "postgresql+psycopg2://postgres:admin123@localhost/memorybox"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['AVATAR_FOLDER'] = 'avatars'
app.config['MAX_AVATAR_SIZE'] = 2 * 1024 * 1024  # 2MB

# Create folders (important for ephemeral filesystem)
os.makedirs(app.config['AVATAR_FOLDER'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_size": 2,                 # ✅ Reduce because of limited connections
    "max_overflow": 3,              # ✅ Reduce overflow
    "pool_timeout": 30,
    "connect_args": {
        "connect_timeout": 10,
        "options": "-c statement_timeout=30000"
    }
}


db = SQLAlchemy(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# ========== CLOUDFLARE R2 SETUP (Optional - for persistent storage) ==========
R2_ENABLED = all([
    os.getenv('R2_ACCOUNT_ID'),
    os.getenv('R2_ACCESS_KEY_ID'),
    os.getenv('R2_SECRET_ACCESS_KEY'),
    os.getenv('R2_BUCKET')
])

if R2_ENABLED:
    import boto3
    from botocore.config import Config
    
    R2_ACCOUNT_ID = os.getenv('R2_ACCOUNT_ID')
    R2_BUCKET = os.getenv('R2_BUCKET')
    R2_PUBLIC_URL = os.getenv('R2_PUBLIC_URL', f'https://{R2_BUCKET}.r2.dev')
    
    s3_client = boto3.client(
        's3',
        endpoint_url=f'https://9669ffc3dad563cb890c4a8a7e361bc5.r2.cloudflarestorage.com',
        aws_access_key_id=os.getenv('R2_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('R2_SECRET_ACCESS_KEY'),
        config=Config(signature_version='s3v4'),
        region_name='auto'
    )
    app.logger.info("✅ Cloudflare R2 storage enabled")
else:
    s3_client = None
    app.logger.warning("⚠️ Cloudflare R2 not configured, using local storage")

# ========== DATABASE MODELS ==========
class User(db.Model):
    """User model for authentication and user management"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_blocked = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    avatar_color = db.Column(db.String(7), default='#6366f1')
    bio = db.Column(db.String(500), default='')
    contact_info = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    photos = db.relationship('Photo', backref='uploader', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='user', lazy=True, cascade='all, delete-orphan')
    avatar_filename = db.Column(db.String(200), default=None)

    def get_avatar_url(self):
        if self.avatar_filename:
            if R2_ENABLED:
                return f"{R2_PUBLIC_URL}/avatars/{self.avatar_filename}"
            return url_for('avatar_file', filename=self.avatar_filename)
        return None
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_total_likes(self):
        return db.session.query(func.count(Like.id)).join(Photo).filter(Photo.user_id == self.id).scalar()
    
    def get_comment_count(self):
        return len(self.comments)

    def get_rank_badge(self):
        users_by_likes = db.session.query(
            User.id,
            func.count(Like.id).label('total_likes')
        ).join(Photo, User.id == Photo.user_id).join(Like, Photo.id == Like.photo_id).group_by(User.id).order_by(func.count(Like.id).desc()).all()
        
        rank = next((i + 1 for i, u in enumerate(users_by_likes) if u[0] == self.id), None)
        
        if rank == 1:
            return {'badge': '🥇', 'class': 'gold-medal'}
        elif rank == 2:
            return {'badge': '🥈', 'class': 'silver-medal'}
        elif rank == 3:
            return {'badge': '🥉', 'class': 'bronze-medal'}
        return None
    
    def is_top_creator(self):
        max_photos = db.session.query(func.count(Photo.id)).group_by(Photo.user_id).order_by(func.count(Photo.id).desc()).first()
        if max_photos:
            user_photos = len(self.photos)
            return user_photos > 0 and user_photos == max_photos[0]
        return False
    
    def is_most_liked(self):
        max_likes = db.session.query(func.count(Like.id)).join(Photo).group_by(Photo.user_id).order_by(func.count(Like.id).desc()).first()
        if max_likes:
            user_likes = self.get_total_likes()
            return user_likes > 0 and user_likes == max_likes[0]
        return False
    

class Photo(db.Model):
    """Photo model for storing uploaded images"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    caption = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.relationship('Like', backref='photo', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='photo', lazy=True, cascade='all, delete-orphan')

    __table_args__ = (
        db.Index('idx_photo_upload_time', 'upload_time'),
        db.Index('idx_photo_user_id', 'user_id'),
        db.Index('idx_photo_user_time', 'user_id', 'upload_time'),
    )
    
    def get_like_count(self):
        return len(self.likes)
    
    def is_liked_by(self, user_id):
        return any(like.user_id == user_id for like in self.likes)
    
    def get_comment_count(self):
        return len(self.comments)
    
    def get_photo_url(self):
        """Get photo URL (R2 or local)"""
        if R2_ENABLED:
            return f"{R2_PUBLIC_URL}/photos/{self.filename}"
        return url_for('uploaded_file', filename=self.filename)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'photo_url': self.get_photo_url(),
            'caption': self.caption,
            'user_id': self.user_id,
            'upload_time': self.upload_time.replace(microsecond=0).isoformat() + "Z",
            'like_count': self.get_like_count(),
            'comment_count': self.get_comment_count(),
            'uploader': {
                'id': self.uploader.id,
                'username': self.uploader.username,
                'avatar_color': self.uploader.avatar_color,
                'avatar_url': self.uploader.get_avatar_url(),
                'is_verified': self.uploader.is_verified
            }
        }


class Like(db.Model):
    """Like model for photo reactions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_like_photo_user', 'photo_id', 'user_id'),
    )
    
class Comment(db.Model):
    """Comment model for photo comments"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_comment_photo', 'photo_id'),
        db.Index('idx_comment_created', 'created_at'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'text': self.text,
            'created_at': self.created_at.replace(microsecond=0).isoformat() + 'Z' if self.created_at else None,
            'user': {
                'id': self.user.id,
                'username': self.user.username,
                'avatar_color': self.user.avatar_color,
                'avatar_url': self.user.get_avatar_url(),
                'is_verified': self.user.is_verified
            }
        }

# ========== HELPER FUNCTIONS ==========
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def upload_to_r2(file_obj, key):
    """Upload file to Cloudflare R2"""
    if not R2_ENABLED:
        return False
    
    try:
        s3_client.upload_fileobj(
            file_obj,
            R2_BUCKET,
            key,
            ExtraArgs={'ContentType': 'image/jpeg'}
        )
        return True
    except Exception as e:
        app.logger.error(f"R2 upload failed: {e}")
        return False

def delete_from_r2(key):
    """Delete file from R2"""
    if not R2_ENABLED:
        return False
    
    try:
        s3_client.delete_object(Bucket=R2_BUCKET, Key=key)
        return True
    except Exception as e:
        app.logger.error(f"R2 delete failed: {e}")
        return False

AVATAR_SIZE = 300
AVATAR_QUALITY = 85

def process_avatar(file_data):
    """
    Process and optimize uploaded avatar image.
    Args:
        file_data: BytesIO object containing image data
    Returns:
        BytesIO object containing processed JPEG image
    """
    try:
        # Ensure file_data is at start
        file_data.seek(0)
        
        # Open image from BytesIO
        img = Image.open(file_data)
        img.load()  # Load image data into memory
        
        # Convert to RGB if needed
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
            img = background
        
        # Crop to square
        width, height = img.size
        size = min(width, height)
        left = (width - size) // 2
        top = (height - size) // 2
        img = img.crop((left, top, left + size, top + size))
        
        # Resize
        img = img.resize((AVATAR_SIZE, AVATAR_SIZE), Image.Resampling.LANCZOS)
        
        # Save to BytesIO
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=AVATAR_QUALITY, optimize=True)
        output.seek(0)
        
        return output
    except Exception as e:
        raise ValueError(f"Invalid image format: {e}")
    finally:
        # Ensure input file_data is not closed here
        pass

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if user and user.is_blocked:
            session.clear()
            flash('Account is blocked', 'danger')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin permission required', 'danger')
            return redirect(url_for('gallery'))
        
        return f(*args, **kwargs)
    return decorated_function

def time_ago(upload_time):
    now = datetime.utcnow()
    diff = now - upload_time
    
    seconds = diff.total_seconds()
    if seconds < 60: return "Just now"
    minutes = seconds / 60
    if minutes < 60: return f"{int(minutes)} minutes ago"
    hours = minutes / 60
    if hours < 24: return f"{int(hours)} hours ago"
    days = hours / 24
    if days < 7: return f"{int(days)} days ago"
    weeks = days / 7
    if weeks < 4: return f"{int(weeks)} weeks ago"
    months = days / 30
    if months < 12: return f"{int(months)} months ago"
    years = days / 365
    return f"{int(years)} years ago"

def get_username_html(user):
    html = f'<span class="username-display'
    
    if user.is_most_liked():
        html += ' username-hot'
    elif user.is_top_creator():
        html += ' username-creator'
    
    html += f'">{user.username}</span>'
    
    if user.is_verified:
        html += ' <i class="fa-solid fa-circle-check verified-icon"></i>'
    
    rank_badge = user.get_rank_badge()
    if rank_badge:
        html += f' <span class="rank-medal-inline">{rank_badge["badge"]}</span>'
    
    return html

def get_user_badges(user):
    badges = []
    
    if user.role == 'admin':
        badges.append({
            'class': 'role-badge-admin',
            'icon': 'bi-shield-fill',
            'text': 'Admin'
        })
    
    if user.is_most_liked():
        badges.append({
            'class': 'role-badge-most-liked',
            'icon': 'bi-fire',
            'text': 'Most Liked'
        })
    elif user.is_top_creator():
        badges.append({
            'class': 'role-badge-top-creator',
            'icon': 'bi-star-fill',
            'text': 'Top Creator'
        })
    
    return badges

def get_carousel_badges(user, photo_count):
    badges = []
    
    if user.role == 'admin':
        badges.append({'icon': '🛡️', 'text': 'Admin', 'class': 'bg-shield'})
    
    if user.is_most_liked():
        badges.append({'icon': '🔥', 'text': 'Most Liked', 'class': 'bg-fire'})
    
    if user.is_top_creator():
        badges.append({'icon': '⭐', 'text': 'Top Creator', 'class': 'bg-star'})
    
    if user.is_verified:
        badges.append({'icon': '✔', 'text': 'Verified', 'class': 'bg-check'})
    
    rank_badge = user.get_rank_badge()
    if rank_badge:
        if rank_badge['badge'] == '🥇':
            badges.append({'icon': '🥇', 'text': 'Gold Medal', 'class': 'bg-medal'})
        elif rank_badge['badge'] == '🥈':
            badges.append({'icon': '🥈', 'text': 'Silver Medal', 'class': 'bg-diamond'})
        elif rank_badge['badge'] == '🥉':
            badges.append({'icon': '🥉', 'text': 'Bronze Medal', 'class': 'bg-lightning'})
    
    if photo_count >= 10:
        badges.append({'icon': '💎', 'text': 'Prolific', 'class': 'bg-diamond'})
    
    if user.get_total_likes() >= 50:
        badges.append({'icon': '👑', 'text': 'Popular', 'class': 'bg-crown'})
        
    return badges

def get_current_user():
    if 'user_id' not in session:
        return None
    try:
        return User.query.get(session['user_id'])
        db.session.expunge_all()
    except Exception:
        db.session.rollback()  # ✅ rollback if db connection is lost
        app.logger.error(f"⚠️ DB reconnect: {e}")
        return None

app.jinja_env.globals.update(
    time_ago=time_ago, 
    get_username_html=get_username_html, 
    get_user_badges=get_user_badges,
    get_carousel_badges=get_carousel_badges,
    get_current_user=get_current_user
)

# ========== ROUTES ==========
def get_user(user_id):
    return User.query.get(user_id)

@app.context_processor
def inject_get_user():
    return dict(get_user=get_user)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('gallery'))
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('gallery'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash('Please fill in all fields', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')
        
        colors = ['#6366f1', '#ec4899', '#f59e0b', '#10b981', '#8b5cf6', '#ef4444', '#06b6d4', '#f97316']
        user = User(username=username, email=email, avatar_color=secrets.choice(colors))
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('gallery'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.is_blocked:
                flash('Account is blocked', 'danger')
                return render_template('login.html')
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            return redirect(url_for('gallery'))
        else:
            flash('Wrong username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/gallery')
@login_required
def gallery():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    pagination = Photo.query.options(
        db.joinedload(Photo.uploader),
        db.joinedload(Photo.likes),
        db.joinedload(Photo.comments)
    ).order_by(Photo.upload_time.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    data = {
        'photos': pagination.items,
        'photos_json': [p.to_dict() for p in pagination.items],
        'current_user': User.query.get(session['user_id']),
        'pagination': pagination
    }
    return render_template('gallery.html', **data)

@app.route('/gallery/photo/<int:photo_id>')
@login_required
def gallery_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    all_photos = Photo.query.order_by(Photo.upload_time.desc()).all()
    
    try:
        photo_index = next(i for i, p in enumerate(all_photos) if p.id == photo_id)
    except StopIteration:
        photo_index = 0
    
    page = 1
    per_page = 50
    pagination = Photo.query.options(
        db.joinedload(Photo.uploader),
        db.joinedload(Photo.likes),
        db.joinedload(Photo.comments)
    ).order_by(Photo.upload_time.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    data = {
        'photos': pagination.items,
        'photos_json': [p.to_dict() for p in pagination.items],
        'current_user': User.query.get(session['user_id']),
        'pagination': pagination,
        'open_photo_index': photo_index
    }
    return render_template('gallery.html', **data)
# ========== IMAGE PROCESSING ==========
executor = ThreadPoolExecutor(max_workers=3)

def optimize_image(filepath: str, filename: str, photo_id: int) -> None:
    try:
        if not os.path.exists(filepath):
            app.logger.warning(f"⚠️ File not found: {filepath}")
            return
        
        with open(filepath, 'rb') as f:
            img = Image.open(f)
            img.load()  # ⭐ QUAN TRỌNG
        
        if img.width > 1920 or img.height > 1920:
            img.thumbnail((1920, 1920), Image.Resampling.LANCZOS)
        
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=90, optimize=True)
        output.seek(0)
        
        if R2_ENABLED:
            upload_to_r2(output, f'photos/{filename}')
            
            output.seek(0)
            img_thumb = Image.open(output)
            img_thumb.load()
            img_thumb.thumbnail((300, 300), Image.Resampling.LANCZOS)
            
            thumb_output = io.BytesIO()
            img_thumb.save(thumb_output, format='JPEG', quality=85, optimize=True)
            thumb_output.seek(0)
            upload_to_r2(thumb_output, f'photos/thumb_{filename}')
        
        app.logger.info(f"✅ Optimized photo {photo_id}")
        
    except Exception as e:
        app.logger.error(f"❌ Error processing photo {photo_id}: {e}")

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(request.url)
        
        file = request.files['photo']
        caption = request.form.get('caption', '').strip()
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            filename = f"{secrets.token_hex(8)}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            photo = Photo(
                filename=filename,
                caption=caption if caption else None,
                user_id=session['user_id']
            )
            db.session.add(photo)
            db.session.commit()

            # Process in background
            try:
                if executor._shutdown:
                    app.logger.warning("⚠️ Executor shut down, processing synchronously")
                    optimize_image(filepath, filename, photo.id)
                else:
                    executor.submit(optimize_image, filepath, filename, photo.id)
            except Exception as e:
                app.logger.error(f"❌ Executor error: {e}")
                optimize_image(filepath, filename, photo.id)

            flash('Photo uploaded successfully!', 'success')
            return redirect(url_for('gallery'))
        else:
            flash('Only JPG, PNG, GIF allowed', 'danger')

    return render_template('upload.html')

@app.teardown_appcontext
def shutdown_session(exception=None):
    try:
        db.session.remove()
    except Exception as e:
        app.logger.error(f"Error closing session: {e}")

@app.after_request
def after_request(response):
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    finally:
        db.session.remove()
    return response

@app.route('/download/<int:photo_id>')
@login_required
def download_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    filename = photo.filename

    if R2_ENABLED:
        file_url = f"{R2_PUBLIC_URL}/photos/{filename}"
        
        try:
            r = requests.get(file_url, stream=True, timeout=30)
            if r.status_code != 200:
                app.logger.error(f"R2 fetch failed: {r.status_code}")
                flash('Unable to download photo', 'danger')
                return redirect(url_for('gallery'))
            
            file_data = io.BytesIO(r.content)
            
            return send_file(
                file_data,
                mimetype='image/jpeg',
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            app.logger.error(f"Download error: {e}")
            flash('Download failed', 'danger')
            return redirect(url_for('gallery'))
    else:
        # Local storage fallback
        local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(local_path):
            flash('File not found', 'danger')
            return redirect(url_for('gallery'))
        
        return send_file(local_path, as_attachment=True, download_name=filename)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded photo — redirect to R2 if available."""
    if R2_ENABLED:
        return redirect(f"{R2_PUBLIC_URL}/photos/{filename}", code=302)
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    """Serve local files (fallback if R2 not enabled)"""
    if not os.path.exists(local_path):
        return jsonify({'error': 'File not found'}), 404
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/photo/<int:photo_id>/delete', methods=['POST'])
@login_required
def delete_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    user = User.query.get(session['user_id'])
    
    if photo.user_id != session['user_id'] and user.role != 'admin':
        flash('Permission denied', 'danger')
        return redirect(url_for('gallery'))
    
    # Delete from R2
    if R2_ENABLED:
        delete_from_r2(f'photos/{photo.filename}')
        delete_from_r2(f'photos/thumb_{photo.filename}')
    
    # Delete local file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    db.session.delete(photo)
    db.session.commit()

    flash('Photo deleted', 'success')
    return redirect(url_for('gallery'))

@app.route('/photo/<int:photo_id>/like', methods=['POST'])
@login_required
def like_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    user_id = session['user_id']
    
    existing_like = Like.query.filter_by(user_id=user_id, photo_id=photo_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'liked': False, 'like_count': photo.get_like_count()})
    else:
        new_like = Like(user_id=user_id, photo_id=photo_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'liked': True, 'like_count': photo.get_like_count()})

@app.route('/profile')
@login_required
def profile():
    return redirect(url_for('view_user_profile', user_id=session['user_id']))

@app.route('/avatars/<filename>')
def avatar_file(filename):
    """Serve user avatars — redirect to R2 if available."""
    if R2_ENABLED:
        return redirect(f"{R2_PUBLIC_URL}/avatars/{filename}", code=302)
    local_path = os.path.join(app.config['AVATAR_FOLDER'], filename)
    if not os.path.exists(local_path):
        return jsonify({'error': 'Avatar not found'}), 404
    return send_from_directory(app.config['AVATAR_FOLDER'], filename)

@app.route('/user/<int:user_id>/upload-avatar', methods=['POST'])
@login_required
def upload_avatar(user_id):
    if user_id != session['user_id']:
        return jsonify({'error': 'Permission denied'}), 403
    
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file'}), 400

    file = request.files['avatar']
    
    if file.filename == '':
        return jsonify({'error': 'No file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid format'}), 400

    try:
        # Read file into memory ONCE
        file_bytes = file.read()
        
        # Check size
        if len(file_bytes) > app.config['MAX_AVATAR_SIZE']:
            return jsonify({'error': 'File too large (max 2MB)'}), 400
        
        # Create BytesIO from bytes
        file_data = io.BytesIO(file_bytes)
        
        # Process the avatar
        processed_image = process_avatar(file_data)
        
        filename = f"avatar_{user_id}_{secrets.token_hex(8)}.jpg"
        
        # Save local copy
        filepath = os.path.join(app.config['AVATAR_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            processed_image.seek(0)
            f.write(processed_image.read())
        
        # Upload to R2 if enabled
        if R2_ENABLED:
            # Create a new BytesIO for R2 upload to avoid reusing closed file
            processed_image.seek(0)
            upload_to_r2(io.BytesIO(processed_image.read()), f'avatars/{filename}')
        
        # Delete old avatar
        user = User.query.get(user_id)
        if user.avatar_filename:
            if R2_ENABLED:
                delete_from_r2(f'avatars/{user.avatar_filename}')
            old_path = os.path.join(app.config['AVATAR_FOLDER'], user.avatar_filename)
            if os.path.exists(old_path):
                os.remove(old_path)

        user.avatar_filename = filename
        db.session.commit()
        
        return jsonify({
            'success': True,
            'avatar_url': user.get_avatar_url()
        }), 200
        
    except ValueError as ve:
        app.logger.error(f"Avatar validation error: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Avatar upload error: {str(e)}")
        return jsonify({'error': f'Processing error: {str(e)}'}), 500

@app.route('/user/<int:user_id>/delete-avatar', methods=['DELETE'])
@login_required
def delete_avatar(user_id):
    if user_id != session['user_id']:
        return jsonify({'error': 'Permission denied'}), 403
    
    user = User.query.get(user_id)
    
    if user.avatar_filename:
        if R2_ENABLED:
            delete_from_r2(f'avatars/{user.avatar_filename}')
        
        filepath = os.path.join(app.config['AVATAR_FOLDER'], user.avatar_filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        
        user.avatar_filename = None
        db.session.commit()
    
    return jsonify({'success': True}), 200

@app.route('/user/<int:user_id>')
@login_required
def view_user_profile(user_id):
    user = User.query.get_or_404(user_id)
    user_photos = Photo.query.filter_by(user_id=user.id).order_by(Photo.upload_time.desc()).all()
    photos_dict = [photo.to_dict() for photo in user_photos]
    is_own_profile = (user_id == session['user_id'])
    
    return render_template('user.html', user=user, photos=user_photos, photos_json=photos_dict, is_own_profile=is_own_profile)

@app.route('/user/<int:user_id>/edit', methods=['POST'])
@login_required
def edit_profile(user_id):
    if user_id != session['user_id']:
        flash('Permission denied', 'danger')
        return redirect(url_for('view_user_profile', user_id=user_id))
    
    user = User.query.get_or_404(user_id)
    bio = request.form.get('bio', '').strip()
    contact_info = request.form.get('contact_info', '').strip()
    
    if len(bio) > 500:
        flash('Bio too long (max 500 chars)', 'danger')
        return redirect(url_for('view_user_profile', user_id=user_id))
    
    if len(contact_info) > 200:
        flash('Contact info too long (max 200 chars)', 'danger')
        return redirect(url_for('view_user_profile', user_id=user_id))
    
    user.bio = bio
    user.contact_info = contact_info
    db.session.commit()

    flash('Profile updated!', 'success')
    return redirect(url_for('view_user_profile', user_id=user_id))

@app.route('/leaderboard')
@login_required
def leaderboard():
    top_users = db.session.query(
        User,
        func.count(Like.id).label('total_likes')
    ).join(Photo, User.id == Photo.user_id).join(Like, Photo.id == Like.photo_id).group_by(User.id).order_by(func.count(Like.id).desc()).limit(20).all()
    
    return render_template('leaderboard.html', top_users=top_users)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        user = User.query.get(session['user_id'])
        
        if not user.check_password(current_password):
            flash('Current password incorrect', 'danger')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return render_template('change_password.html')
        
        user.set_password(new_password)
        db.session.commit()

        flash('Password changed!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    photos = Photo.query.order_by(Photo.upload_time.desc()).all()
    
    stats = {
        'total_users': len(users),
        'active_users': len([u for u in users if not u.is_blocked]),
        'blocked_users': len([u for u in users if u.is_blocked]),
        'total_photos': len(photos),
        'total_likes': Like.query.count(),
        'total_comments': Comment.query.count()
    }
    
    top_users = sorted(users, key=lambda u: len(u.photos), reverse=True)[:5]
    
    return render_template('admin.html', 
                         users=users, 
                         photos=photos, 
                         stats=stats,
                         top_users=top_users)

@app.route('/admin/user/<int:user_id>/toggle-block', methods=['POST'])
@admin_required
def toggle_block_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('Cannot block yourself', 'danger')
        return redirect(url_for('admin_panel'))
    
    if user.role == 'admin':
        flash('Cannot block admin', 'danger')
        return redirect(url_for('admin_panel'))
    
    user.is_blocked = not user.is_blocked
    db.session.commit()

    status = 'blocked' if user.is_blocked else 'unblocked'
    flash(f'User {user.username} {status}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/create-admin', methods=['POST'])
@admin_required
def create_admin():
    user_id = request.form.get('user_id')
    user = User.query.get_or_404(user_id)
    
    if user.role == 'admin':
        flash(f'{user.username} already admin', 'info')
    else:
        user.role = 'admin'
        db.session.commit()
        flash(f'{user.username} promoted to admin', 'success')

    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/toggle-verify', methods=['POST'])
@admin_required
def toggle_verify_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()

    status = 'verified' if user.is_verified else 'unverified'
    flash(f'User {user.username} {status}', 'success')
    return redirect(url_for('admin_panel'))

# ========== COMMENT ROUTES ==========
@app.route('/photo/<int:photo_id>/comments', methods=['GET'])
@login_required
def get_comments(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    comments = Comment.query.filter_by(photo_id=photo_id).order_by(Comment.created_at.asc()).all()
    return jsonify([comment.to_dict() for comment in comments])

@app.route('/photo/<int:photo_id>/comment', methods=['POST'])
@login_required
def add_comment(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    data = request.get_json()
    
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    if len(text) > 1000:
        return jsonify({'error': 'Comment too long (max 1000 chars)'}), 400

    comment = Comment(
        user_id=session['user_id'],
        photo_id=photo_id,
        text=text
    )
    db.session.add(comment)
    db.session.commit()
    
    return jsonify(comment.to_dict()), 201

@app.route('/comment/<int:comment_id>/delete', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    user = User.query.get(session['user_id'])
    
    if comment.user_id != session['user_id'] and user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403
    
    db.session.delete(comment)
    db.session.commit()
    
    return jsonify({'success': True}), 200

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    flash('Permission denied', 'danger')
    return redirect(url_for('gallery'))

@atexit.register
def shutdown_executor():
    try:
        app.logger.info("🛑 Shutting down executor...")
        executor.shutdown(wait=True, cancel_futures=False)
        app.logger.info("✅ Executor shutdown cleanly")
    except Exception as e:
        app.logger.warning(f"⚠️ Executor shutdown error: {e}")


# ========== HEALTH CHECK ==========
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test DB connection
        db.session.execute(db.text('SELECT 1'))
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# ========== MAIN ==========
if __name__ == '__main__':
    app.run(
        debug=os.getenv('FLASK_DEBUG', 'False') == 'True',
        host=os.getenv('FLASK_HOST', '0.0.0.0'),
        port=int(os.getenv('FLASK_PORT', 5000))
    )
    
    