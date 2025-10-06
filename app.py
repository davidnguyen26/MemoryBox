import io
import os
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from sqlalchemy import func
from threading import Thread
from PIL import Image
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from flask import request

# ========== ENVIRONMENT SETUP ==========
# Loading environment variables from .env file
load_dotenv()

# ========== FLASK APP INITIALIZATION ==========
# Initialize Flask application with configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql+psycopg2://postgres:admin123@localhost/memorybox"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB limit
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['AVATAR_FOLDER'] = 'avatars'
app.config['MAX_AVATAR_SIZE'] = 2 * 1024 * 1024  # 2MB
os.makedirs(app.config['AVATAR_FOLDER'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# ========== DATABASE MODELS ==========
# Database model definitions for User, Photo, Like, and Comment
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
            return url_for('avatar_file', filename=self.avatar_filename)
        return None
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_total_likes(self):
        """Total likes on all user photos"""
        return db.session.query(func.count(Like.id)).join(Photo).filter(Photo.user_id == self.id).scalar()
    
    def get_comment_count(self):
        return len(self.comments)

    def get_rank_badge(self):
        """Return badge based on rank"""
        # Lấy top users theo likes
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
        """Check user is top creator (most photos)"""
        max_photos = db.session.query(func.count(Photo.id)).group_by(Photo.user_id).order_by(func.count(Photo.id).desc()).first()
        if max_photos:
            user_photos = len(self.photos)
            return user_photos > 0 and user_photos == max_photos[0]
        return False
    
    def is_most_liked(self):
        """Check user is most liked"""
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
        db.Index('idx_photo_user_time', 'user_id', 'upload_time'),  # Add this
    )
    
    def get_like_count(self):
        return len(self.likes)
    
    def is_liked_by(self, user_id):
        return any(like.user_id == user_id for like in self.likes)
    
    def get_comment_count(self):
        return len(self.comments)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'caption': self.caption,
            'user_id': self.user_id,
            'upload_time': self.upload_time.replace(microsecond=0).isoformat() + "Z",
            'like_count': self.get_like_count(),
            'comment_count': self.get_comment_count(),
            'uploader': {
                'id': self.uploader.id,
                'username': self.uploader.username,
                'avatar_color': self.uploader.avatar_color,
                'avatar_filename': self.uploader.avatar_filename, 
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
                'avatar_filename': self.user.avatar_filename,
                'is_verified': self.user.is_verified
            }
        }
    

# ========== HELPER FUNCTIONS ==========
# Utility functions for file handling, authentication, and UI rendering
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Constants for avatar processing
from typing import BinaryIO, IO

AVATAR_SIZE = 300  # pixels
AVATAR_QUALITY = 85  # JPEG quality
AVATAR_MAX_SIZE_BYTES = 2 * 1024 * 1024  # 2MB

def process_avatar(file: BinaryIO) -> IO[bytes]:
    """
    Process and optimize uploaded avatar image.
    
    Args:
        file: Uploaded file object
        
    Returns:
        BytesIO object containing optimized JPEG
        
    Raises:
        ValueError: If image format is unsupported
    """
    try:
        img = Image.open(file)
    except Exception as e:
        raise ValueError(f"Invalid image format: {e}")
    
    # Convert RGBA/palette to RGB
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
    
    # Resize and optimize
    img = img.resize((AVATAR_SIZE, AVATAR_SIZE), Image.Resampling.LANCZOS)
    
    output = io.BytesIO()
    img.save(output, format='JPEG', quality=AVATAR_QUALITY, optimize=True)
    output.seek(0)
    
    return output

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
            flash('Cần quyền admin', 'danger')
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
    """
    Return HTML for username with badges and effects
    Used everywhere to display user name
    """
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
    """
    Return list of role badges for user
    Used to display role badges consistently
    """
    badges = []
    
    # Admin badge (highest priority)
    if user.role == 'admin':
        badges.append({
            'class': 'role-badge-admin',
            'icon': 'bi-shield-fill',
            'text': 'Admin'
        })
    
    # Achievement badges
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
    """
    Return list of badges for animated carousel
    Includes achievements, ranks, and milestone badges
    """
    badges = []
    
    # Admin badge
    if user.role == 'admin':
        badges.append({'icon': '🛡️', 'text': 'Admin', 'class': 'bg-shield'})
    
    # Achievement badges
    if user.is_most_liked():
        badges.append({'icon': '🔥', 'text': 'Most Liked', 'class': 'bg-fire'})
    
    if user.is_top_creator():
        badges.append({'icon': '⭐', 'text': 'Top Creator', 'class': 'bg-star'})
    
    # Verified badge
    if user.is_verified:
        badges.append({'icon': '✓', 'text': 'Verified', 'class': 'bg-check'})
    
    # Rank medals
    rank_badge = user.get_rank_badge()
    if rank_badge:
        if rank_badge['badge'] == '🥇':
            badges.append({'icon': '🥇', 'text': 'Gold Medal', 'class': 'bg-medal'})
        elif rank_badge['badge'] == '🥈':
            badges.append({'icon': '🥈', 'text': 'Silver Medal', 'class': 'bg-diamond'})
        elif rank_badge['badge'] == '🥉':
            badges.append({'icon': '🥉', 'text': 'Bronze Medal', 'class': 'bg-lightning'})
    
    # Milestone badges
    if photo_count >= 10:
        badges.append({'icon': '💎', 'text': 'Prolific', 'class': 'bg-diamond'})
    
    if user.get_total_likes() >= 50:
        badges.append({'icon': '👑', 'text': 'Popular', 'class': 'bg-crown'})
        
    return badges

def get_current_user():
    """Helper to get current logged in user"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def clear_all_gallery_caches():
    """Clear gallery cache for all users"""
    # Since cache keys are user-specific, we need to clear all possible gallery caches
    # Alternatively, switch to a global cache key to simplify this
    users = User.query.all()
    for user in users:
        cache_key = f'gallery_photos_{user.id}'
        cache.delete(cache_key)

# Inject helper functions into Jinja globals
app.jinja_env.globals.update(
    time_ago=time_ago, 
    get_username_html=get_username_html, 
    get_user_badges=get_user_badges,
    get_carousel_badges=get_carousel_badges,
    get_current_user=get_current_user
)

# ========== ROUTES ==========
# Application routes for handling HTTP requests
def get_user(user_id):
    """Helper function to get user by ID"""
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
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email is already registered', 'danger')
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
        'pagination': pagination  # Để frontend xử lý next/prev
    }
    return render_template('gallery.html', **data)

# ========== ASYNC IMAGE PROCESSING ==========
# Background image processing with ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=4)

def optimize_image(filepath: str, photo_id: int) -> None:
    """Background task: optimize uploaded image (resize + thumbnail)."""
    try:
        # Generate thumbnail (300x300)
        img = Image.open(filepath)
        img.thumbnail((300, 300), Image.Resampling.LANCZOS)
        thumb_path = os.path.splitext(filepath)[0] + "_thumb.jpg"
        img.save(thumb_path, 'JPEG', quality=85, optimize=True)

        # Optimize original image (resize if too large)
        img_full = Image.open(filepath)
        if img_full.width > 1920 or img_full.height > 1920:
            img_full.thumbnail((1920, 1920), Image.Resampling.LANCZOS)
        img_full.save(filepath, 'JPEG', quality=90, optimize=True)

        app.logger.info(f"✅ Optimized image for photo {photo_id}")

    except Exception as e:
        app.logger.error(f"❌ Error processing image {photo_id}: {str(e)}", exc_info=True)
        

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('Không có file', 'danger')
            return redirect(request.url)
        
        file = request.files['photo']
        caption = request.form.get('caption', '').strip()
        
        if file.filename == '':
            flash('Không có file', 'danger')
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

            # Executor process background image optimization
            executor.submit(optimize_image, filepath, photo.id)

            cache.delete('gallery_photos_global')

            flash('Photo uploaded successfully!', 'success')
            return redirect(url_for('gallery'))
        else:
            flash('Only JPG, PNG, GIF files are allowed', 'danger')

    return render_template('upload.html')

@app.teardown_appcontext
def shutdown_executor(exception=None):
    """Gracefully shutdown background executor."""
    executor.shutdown(wait=False)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/photo/<int:photo_id>/delete', methods=['POST'])
@login_required
def delete_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    user = User.query.get(session['user_id'])
    
    if photo.user_id != session['user_id'] and user.role != 'admin':
        flash('You do not have permission to delete this photo', 'danger')
        return redirect(url_for('gallery'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    db.session.delete(photo)
    db.session.commit()

    cache.delete('gallery_photos_global')

    flash('Photo deleted successfully!', 'success')
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
    """Redirect to user profile"""
    return redirect(url_for('view_user_profile', user_id=session['user_id']))

@app.route('/avatars/<filename>')
def avatar_file(filename):
    return send_from_directory(app.config['AVATAR_FOLDER'], filename)

@app.route('/user/<int:user_id>/upload-avatar', methods=['POST'])
@login_required
def upload_avatar(user_id):
    if user_id != session['user_id']:
        return jsonify({'error': 'You do not have permission'}), 403
    
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['avatar']
    
    if file.filename == '':
        return jsonify({'error': 'No file uploaded'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Just accept JPG, PNG, GIF files'}), 400

    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset
    
    if size > app.config['MAX_AVATAR_SIZE']:
        return jsonify({'error': 'File too large (max 2MB)'}), 400
    
    try:
        # Process and optimize image
        processed_image = process_avatar(file)

        # Create unique filename
        filename = f"avatar_{user_id}_{secrets.token_hex(8)}.jpg"
        filepath = os.path.join(app.config['AVATAR_FOLDER'], filename)

        # Save file
        with open(filepath, 'wb') as f:
            f.write(processed_image.read())

        # Delete old avatar if exists
        user = User.query.get(user_id)
        if user.avatar_filename:
            old_path = os.path.join(app.config['AVATAR_FOLDER'], user.avatar_filename)
            if os.path.exists(old_path):
                os.remove(old_path)

        # Update database
        user.avatar_filename = filename
        db.session.commit()
        
        return jsonify({
            'success': True,
            'avatar_url': url_for('avatar_file', filename=filename)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error processing image: {str(e)}'}), 500

@app.route('/user/<int:user_id>/delete-avatar', methods=['DELETE'])
@login_required
def delete_avatar(user_id):
    if user_id != session['user_id']:
        return jsonify({'error': 'You do not have permission'}), 403
    
    user = User.query.get(user_id)
    
    if user.avatar_filename:
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
        flash('You do not have permission to edit this profile', 'danger')
        return redirect(url_for('view_user_profile', user_id=user_id))
    
    user = User.query.get_or_404(user_id)
    bio = request.form.get('bio', '').strip()
    contact_info = request.form.get('contact_info', '').strip()
    
    if len(bio) > 500:
        flash('Bio must be at most 500 characters', 'danger')
        return redirect(url_for('view_user_profile', user_id=user_id))
    
    if len(contact_info) > 200:
        flash('Contact information must be at most 200 characters', 'danger')
        return redirect(url_for('view_user_profile', user_id=user_id))
    
    user.bio = bio
    user.contact_info = contact_info
    db.session.commit()

    flash('Profile information updated successfully!', 'success')
    return redirect(url_for('view_user_profile', user_id=user_id))

@app.route('/leaderboard')
@login_required
def leaderboard():
    """Leaderboard of top users by likes"""
    # Get top users by total likes
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
            flash('Current password is incorrect', 'danger')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('change_password.html')
        
        user.set_password(new_password)
        db.session.commit()

        flash('Password changed successfully!', 'success')
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
    
    # Top users by photo count
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
        flash('You cannot block yourself', 'danger')
        return redirect(url_for('admin_panel'))
    
    if user.role == 'admin':
        flash('You cannot block another admin', 'danger')
        return redirect(url_for('admin_panel'))
    
    user.is_blocked = not user.is_blocked
    db.session.commit()

    status = 'blocked' if user.is_blocked else 'unblocked'
    app.logger.info(f"Admin {session['username']} {status} user {user.username} (ID: {user.id})")
    flash(f'User {user.username} has been {status}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/create-admin', methods=['POST'])
@admin_required
def create_admin():
    user_id = request.form.get('user_id')
    user = User.query.get_or_404(user_id)
    
    if user.role == 'admin':
        flash(f'User {user.username} is already an admin', 'info')
    else:
        user.role = 'admin'
        db.session.commit()
        flash(f'User {user.username} has been promoted to admin', 'success')

    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/toggle-verify', methods=['POST'])
@admin_required
def toggle_verify_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()

    status = 'verified' if user.is_verified else 'unverified'
    flash(f'User {user.username} has been {status}', 'success')
    return redirect(url_for('admin_panel'))

# ========== COMMENT ROUTES ==========
# Routes for handling photo comments
@app.route('/photo/<int:photo_id>/comments', methods=['GET'])
@login_required
def get_comments(photo_id):
    """Get list of comments for a photo"""
    photo = Photo.query.get_or_404(photo_id)
    comments = Comment.query.filter_by(photo_id=photo_id).order_by(Comment.created_at.asc()).all()
    return jsonify([comment.to_dict() for comment in comments])

@app.route('/photo/<int:photo_id>/comment', methods=['POST'])
@login_required
def add_comment(photo_id):
    """Add a new comment"""
    photo = Photo.query.get_or_404(photo_id)
    data = request.get_json()
    
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    if len(text) > 1000:
        return jsonify({'error': 'Comment must be at most 1000 characters'}), 400

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
    """Xóa comment"""
    comment = Comment.query.get_or_404(comment_id)
    user = User.query.get(session['user_id'])
    
    # Only allow deleting own comments or admin
    if comment.user_id != session['user_id'] and user.role != 'admin':
        return jsonify({'error': 'You do not have permission to delete this comment'}), 403
    
    db.session.delete(comment)
    db.session.commit()
    
    return jsonify({'success': True}), 200

# ========== ERROR HANDLING ==========
# Custom error pages for 404, 500, and 403
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page"""
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    """Custom 403 error page"""
    flash('You do not have permission to access this resource', 'danger')
    return redirect(url_for('gallery'))


# ========== MAIN EXECUTION ==========
# Run the Flask application
if __name__ == '__main__':
    app.run(
        debug=os.getenv('FLASK_DEBUG', 'False') == 'True',
        host=os.getenv('FLASK_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_PORT', 5000))
    )