// ========== COMMON FUNCTIONS ==========

/**
 * Format bytes to readable size
 */
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 10) / 10 + ' ' + sizes[i];
}

/**
 * Parse server time to Date object
 */
function parseServerTime(t) {
    if (!t) return null;
    return new Date(t);
}

/**
 * Get time ago string from upload time
 */
function getTimeAgo(uploadTime) {
    const uploaded = parseServerTime(uploadTime);
    if (!uploaded || isNaN(uploaded)) return '—';

    const now = new Date();
    const diffMs = now - uploaded;
    const diffMin = Math.floor(diffMs / 60000);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);

    if (diffMin < 1) return 'Vừa xong';
    if (diffMin < 60) return `${diffMin} phút trước`;
    if (diffHour < 24) return `${diffHour} giờ trước`;
    if (diffDay < 7) return `${diffDay} ngày trước`;
    if (diffDay < 30) return `${Math.floor(diffDay / 7)} tuần trước`;
    if (diffDay < 365) return `${Math.floor(diffDay / 30)} tháng trước`;
    return `${Math.floor(diffDay / 365)} năm trước`;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Like/Unlike photo
 */
async function toggleLike(photoId, button) {
    try {
        const response = await fetch(`/photo/${photoId}/like`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        button.classList.toggle('active', data.liked);
        const likeCountEl = button.querySelector('.like-count');
        if (likeCountEl) {
            likeCountEl.textContent = data.like_count;
        }

        return data;
    } catch (error) {
        console.error('Error toggling like:', error);
        return null;
    }
}

// ========== AUTO-DISMISS ALERTS ==========
document.addEventListener('DOMContentLoaded', () => {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});