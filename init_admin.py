from app import app, db, User
from werkzeug.security import generate_password_hash


# Initialize database and create default admin user
with app.app_context():
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            avatar_color='#ef4444',
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        print("[+] ✅ Admin created: admin / admin123")
        print("[+] ⚠️  Please change password after first login!")
    else:
        print("[=] Admin already exists.")
