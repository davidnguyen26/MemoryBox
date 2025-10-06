// ========== GALLERY PAGE JAVASCRIPT ==========

const photos = window.GALLERY_PHOTOS || [];
let currentPhotoIndex = 0;
const currentUserId = window.CURRENT_USER_ID;
const isAdmin = window.IS_ADMIN || false;

// ========== LIGHTBOX FUNCTIONS ==========

function openLightbox(index) {
    currentPhotoIndex = index;
    updateLightbox();
    document.getElementById('lightbox').classList.add('active');
    document.body.style.overflow = 'hidden';

    const photo = photos[currentPhotoIndex];
    history.pushState({ photoIndex: index }, '', `/gallery/photo/${photo.id}`);
}

function closeLightbox() {
    document.getElementById('lightbox').classList.remove('active');
    document.body.style.overflow = '';
    history.pushState({}, '', '/gallery');
}

function navigateLightbox(direction) {
    currentPhotoIndex += direction;
    if (currentPhotoIndex < 0) currentPhotoIndex = photos.length - 1;
    if (currentPhotoIndex >= photos.length) currentPhotoIndex = 0;
    updateLightbox();

    const photo = photos[currentPhotoIndex];
    history.pushState({ photoIndex: currentPhotoIndex }, '', `/gallery/photo/${photo.id}`);
}

function updateLightbox() {
    const photo = photos[currentPhotoIndex];

    document.getElementById('lightboxImage').src = `/uploads/${photo.filename}`;

    const avatar = document.getElementById('sidebarAvatar');
    avatar.style.background = photo.uploader.avatar_color;
    avatar.textContent = photo.uploader.username[0].toUpperCase();
    avatar.dataset.userId = photo.uploader.id;

    let usernameHTML = photo.uploader.username;
    if (photo.uploader.is_verified) {
        usernameHTML += ' <i class="fa-solid fa-circle-check" style="color: #3b82f6; font-size: 0.85rem;"></i>';
    }

    const usernameLink = document.getElementById('sidebarUsernameLink');
    usernameLink.innerHTML = usernameHTML;
    usernameLink.href = `/user/${photo.uploader.id}`;

    const sidebarTimeEl = document.getElementById('sidebarTime');
    sidebarTimeEl.innerHTML = '';
    const clockIcon = document.createElement('i');
    clockIcon.className = 'bi bi-clock';
    sidebarTimeEl.appendChild(clockIcon);
    sidebarTimeEl.appendChild(document.createTextNode(' ' + getTimeAgo(photo.upload_time)));

    const captionSection = document.getElementById('sidebarCaption');
    if (photo.caption) {
        captionSection.style.display = 'block';
        document.getElementById('captionText').textContent = photo.caption;
    } else {
        captionSection.style.display = 'none';
    }

    document.getElementById('likeCount').textContent = photo.like_count;

    loadComments(photo.id);
}

function goToUserProfile() {
    const userId = document.getElementById('sidebarAvatar').dataset.userId;
    window.location.href = `/user/${userId}`;
}

// ========== SHARE FUNCTIONS ==========

function getCurrentPhotoUrl() {
    const photo = photos[currentPhotoIndex];
    return `${window.location.origin}/gallery/photo/${photo.id}`;
}

function toggleShareMenu() {
    const menu = document.getElementById('shareMenu');
    menu.style.display = (menu.style.display === 'none' || menu.style.display === '') ? 'block' : 'none';
}

function shareToFacebook() {
    const url = getCurrentPhotoUrl();
    window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`, '_blank', 'width=600,height=400');
}

function shareToTwitter() {
    const url = getCurrentPhotoUrl();
    const photo = photos[currentPhotoIndex];
    const text = photo.caption ? `${photo.caption} - MemoryBox` : 'Check out this photo on MemoryBox!';
    window.open(`https://twitter.com/intent/tweet?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`, '_blank', 'width=600,height=400');
}

function copyLink() {
    const url = getCurrentPhotoUrl();
    navigator.clipboard.writeText(url).then(() => {
        const btn = event.target.closest('.share-btn');
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check2"></i>';
        btn.style.background = '#10b981';
        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.background = '';
        }, 2000);
    });
}

// ========== COMMENT FUNCTIONS ==========

async function loadComments(photoId) {
    try {
        const response = await fetch(`/photo/${photoId}/comments`);
        const comments = await response.json();

        const commentsList = document.getElementById('commentsList');
        const commentCount = document.getElementById('commentCountSidebar');

        let totalCount = comments.length;
        comments.forEach(c => totalCount += (c.replies ? c.replies.length : 0));
        commentCount.textContent = totalCount;

        if (comments.length === 0) {
            commentsList.innerHTML = `
                <div class="empty-comments">
                    <i class="bi bi-chat-dots"></i>
                    <p>Chưa có bình luận nào</p>
                </div>
            `;
            return;
        }

        commentsList.innerHTML = comments.map(c => renderComment(c)).join('');

        const commentsSection = document.getElementById('commentsSection');
        commentsSection.scrollTop = commentsSection.scrollHeight;

    } catch (error) {
        console.error('Error loading comments:', error);
    }
}

function renderComment(comment, isReply = false) {
    const canDelete = comment.user.id === currentUserId || isAdmin;
    const commentClass = isReply ? 'comment comment-reply' : 'comment';

    let html = `
        <div class="${commentClass}" id="comment-${comment.id}">
            <div class="comment-avatar" style="background: ${comment.user.avatar_color}" onclick="window.location.href='/user/${comment.user.id}'">
                ${comment.user.username[0].toUpperCase()}
            </div>
            <div class="comment-content">
                <div class="comment-header">
                    <span class="comment-author">
                        <a href="/user/${comment.user.id}">${comment.user.username}</a>
                        ${comment.user.is_verified ? '<i class="fa-solid fa-circle-check" style="color: #3b82f6; font-size: 0.7rem;"></i>' : ''}
                    </span>
                    <span class="comment-time">${getTimeAgo(comment.created_at)}</span>
                </div>
                <div class="comment-text">${escapeHtml(comment.text)}</div>
                <div class="comment-actions">
                    ${canDelete ? `<button class="comment-action-btn comment-delete" onclick="deleteComment(${comment.id})">Xóa</button>` : ''}
                </div>
            </div>
        </div>
    `;

    return html;
}

async function submitComment() {
    const input = document.getElementById('commentInput');
    const text = input.value.trim();

    if (!text) return;

    const photo = photos[currentPhotoIndex];

    try {
        const response = await fetch(`/photo/${photo.id}/comment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });

        if (response.ok) {
            input.value = '';
            input.style.height = 'auto';
            loadComments(photo.id);
            photo.comment_count = (photo.comment_count || 0) + 1;
            updateCommentCount(photo.id, photo.comment_count);
        }
    } catch (error) {
        console.error('Error submitting comment:', error);
    }
}

async function deleteComment(commentId) {
    if (!confirm('Xóa bình luận này?')) return;

    try {
        const response = await fetch(`/comment/${commentId}/delete`, {
            method: 'DELETE'
        });

        if (response.ok) {
            const photo = photos[currentPhotoIndex];
            loadComments(photo.id);
        }
    } catch (error) {
        console.error('Error deleting comment:', error);
    }
}

function updateCommentCount(photoId, count) {
    const cards = document.querySelectorAll('.photo-card');
    const photoIndex = photos.findIndex(p => p.id === photoId);
    if (photoIndex !== -1 && cards[photoIndex]) {
        const countSpan = cards[photoIndex].querySelector('.comment-count');
        if (countSpan) countSpan.textContent = count;
    }
}

// ========== EVENT LISTENERS ==========

document.addEventListener('DOMContentLoaded', () => {
    // Open lightbox if photo_id in URL
    if (window.OPEN_PHOTO_INDEX !== null) {
        openLightbox(window.OPEN_PHOTO_INDEX);
    }

    // Keyboard navigation
    document.addEventListener('keydown', e => {
        const lightbox = document.getElementById('lightbox');
        if (!lightbox.classList.contains('active')) return;

        if (e.key === 'ArrowLeft') navigateLightbox(-1);
        if (e.key === 'ArrowRight') navigateLightbox(1);
        if (e.key === 'Escape') closeLightbox();
    });

    // Auto-resize comment input
    const commentInput = document.getElementById('commentInput');
    if (commentInput) {
        commentInput.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 100) + 'px';
        });

        commentInput.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                submitComment();
            }
        });
    }

    // Browser back/forward
    window.addEventListener('popstate', (e) => {
        if (e.state && e.state.photoIndex !== undefined) {
            openLightbox(e.state.photoIndex);
        } else {
            closeLightbox();
        }
    });

    // Load comment counts
    loadCommentCounts();
});

async function loadCommentCounts() {
    for (let i = 0; i < photos.length; i++) {
        const photo = photos[i];
        try {
            const response = await fetch(`/photo/${photo.id}/comments`);
            const comments = await response.json();
            let totalCount = comments.length;
            photo.comment_count = totalCount;
            updateCommentCount(photo.id, totalCount);
        } catch (error) {
            console.error(`Error loading comment count for photo ${photo.id}:`, error);
        }
    }
}