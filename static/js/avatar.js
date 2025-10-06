// ========== AVATAR UPLOAD SYSTEM ==========

class AvatarUploader {
    constructor(userId) {
        this.userId = userId;
        this.selectedFile = null;
        this.maxSize = 2 * 1024 * 1024; // 2MB
        this.allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        this.init();
    }

    init() {
        this.setupElements();
        this.attachEventListeners();
    }

    setupElements() {
        this.fileInput = document.getElementById('avatarFileInput');
        this.uploadArea = document.getElementById('avatarUploadArea');
        this.preview = document.getElementById('avatarPreviewLarge');
        this.uploadBtn = document.getElementById('avatarUploadBtn');
        this.deleteBtn = document.getElementById('avatarDeleteBtn');
        this.loading = document.getElementById('avatarLoading');
    }

    attachEventListeners() {
        // File input
        if (this.fileInput) {
            this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }

        // Drag and drop
        if (this.uploadArea) {
            this.uploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
            this.uploadArea.addEventListener('dragleave', () => this.handleDragLeave());
            this.uploadArea.addEventListener('drop', (e) => this.handleDrop(e));
            this.uploadArea.addEventListener('click', () => this.fileInput?.click());
        }

        // Buttons
        if (this.uploadBtn) {
            this.uploadBtn.addEventListener('click', () => this.uploadAvatar());
        }

        if (this.deleteBtn) {
            this.deleteBtn.addEventListener('click', () => this.deleteAvatar());
        }
    }

    handleFileSelect(e) {
        const file = e.target.files[0];
        if (file) this.processFile(file);
    }

    handleDragOver(e) {
        e.preventDefault();
        this.uploadArea?.classList.add('dragover');
    }

    handleDragLeave() {
        this.uploadArea?.classList.remove('dragover');
    }

    handleDrop(e) {
        e.preventDefault();
        this.uploadArea?.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) this.processFile(file);
    }

    processFile(file) {
        // Validate type
        if (!this.allowedTypes.includes(file.type)) {
            this.showError('Chỉ chấp nhận file JPG, PNG, GIF');
            return;
        }

        // Validate size
        if (file.size > this.maxSize) {
            this.showError('File quá lớn! Tối đa 2MB');
            return;
        }

        this.selectedFile = file;
        this.previewFile(file);
        
        if (this.uploadBtn) {
            this.uploadBtn.disabled = false;
        }
    }

    previewFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            if (this.preview) {
                let img = this.preview.querySelector('img');
                if (!img) {
                    img = document.createElement('img');
                    this.preview.appendChild(img);
                }
                img.src = e.target.result;
                img.style.display = 'block';
                
                // Hide letter
                const letter = this.preview.querySelector('span');
                if (letter) letter.style.display = 'none';
            }
        };
        reader.readAsDataURL(file);
    }

    async uploadAvatar() {
        if (!this.selectedFile) return;

        const formData = new FormData();
        formData.append('avatar', this.selectedFile);

        this.showLoading(true);
        this.uploadBtn.disabled = true;

        try {
            const response = await fetch(`/user/${this.userId}/upload-avatar`, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                this.showSuccess('Avatar đã được cập nhật!');
                
                // Update all avatars on page
                this.updateAllAvatars(data.avatar_url);
                
                if (this.deleteBtn) {
                    this.deleteBtn.disabled = false;
                }
                
                // Close modal if exists
                const modal = bootstrap.Modal.getInstance(document.getElementById('editModal'));
                if (modal) {
                    setTimeout(() => modal.hide(), 1000);
                }
                
                // Reload page to update all instances
                setTimeout(() => window.location.reload(), 1500);
            } else {
                this.showError(data.error || 'Upload thất bại');
                this.uploadBtn.disabled = false;
            }
        } catch (error) {
            this.showError('Lỗi kết nối: ' + error.message);
            this.uploadBtn.disabled = false;
        } finally {
            this.showLoading(false);
        }
    }

    async deleteAvatar() {
        if (!confirm('Bạn có chắc muốn xóa avatar?')) return;

        this.showLoading(true);

        try {
            const response = await fetch(`/user/${this.userId}/delete-avatar`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showSuccess('Avatar đã được xóa');
                
                // Reset preview
                if (this.preview) {
                    const img = this.preview.querySelector('img');
                    if (img) img.style.display = 'none';
                    
                    const letter = this.preview.querySelector('span');
                    if (letter) letter.style.display = 'block';
                }
                
                if (this.deleteBtn) {
                    this.deleteBtn.disabled = true;
                }
                
                // Reload page
                setTimeout(() => window.location.reload(), 1500);
            } else {
                this.showError('Xóa thất bại');
            }
        } catch (error) {
            this.showError('Lỗi kết nối: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }

    updateAllAvatars(avatarUrl) {
        // Update all avatar elements on page
        const avatars = document.querySelectorAll('[data-user-id="' + this.userId + '"]');
        avatars.forEach(avatar => {
            let img = avatar.querySelector('img');
            if (!img) {
                img = document.createElement('img');
                avatar.appendChild(img);
            }
            img.src = avatarUrl + '?t=' + Date.now(); // Cache bust
            img.style.display = 'block';
            
            const letter = avatar.querySelector('span:not(.verified-icon):not(.rank-medal-inline)');
            if (letter) letter.style.display = 'none';
        });
    }

    showLoading(show) {
        if (this.loading) {
            this.loading.classList.toggle('active', show);
        }
    }

    showError(message) {
        // Use existing flash message system
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const container = document.querySelector('.modal-body') || document.querySelector('.container');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
            setTimeout(() => alertDiv.remove(), 5000);
        }
    }

    showSuccess(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-success alert-dismissible fade show';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const container = document.querySelector('.modal-body') || document.querySelector('.container');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
            setTimeout(() => alertDiv.remove(), 5000);
        }
    }
}

// ========== LAZY LOAD AVATARS ==========

function lazyLoadAvatars() {
    const avatars = document.querySelectorAll('img[data-avatar-src]');
    
    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.avatarSrc;
                    img.removeAttribute('data-avatar-src');
                    img.setAttribute('data-avatar-loaded', 'true');
                    observer.unobserve(img);
                }
            });
        }, {
            rootMargin: '50px'
        });
        
        avatars.forEach(img => observer.observe(img));
    } else {
        // Fallback for older browsers
        avatars.forEach(img => {
            img.src = img.dataset.avatarSrc;
            img.removeAttribute('data-avatar-src');
        });
    }
}

// ========== INITIALIZE ==========

document.addEventListener('DOMContentLoaded', () => {
    // Initialize avatar uploader if on profile page
    const userId = document.querySelector('[data-current-user-id]')?.dataset.currentUserId;
    if (userId && document.getElementById('avatarFileInput')) {
        window.avatarUploader = new AvatarUploader(userId);
    }
    
    // Lazy load avatars
    lazyLoadAvatars();
});