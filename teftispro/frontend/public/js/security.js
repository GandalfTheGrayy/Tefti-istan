/* ========================================
   TeftişPro Security Utilities (Faz 3.1)
   XSS koruması: safeText, safeHTML
   DOMPurify yüklü olmalı (CDN veya npm)
   ======================================== */

/**
 * Kullanıcı girdisini HTML'de güvenli göstermek için escape eder.
 * innerHTML'de kullanıcı/API verisi için kullanılmalı.
 * @param {string} dirty - Escape edilecek metin
 * @returns {string} HTML-safe string
 */
window.safeText = function (dirty) {
  if (dirty == null || dirty === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(dirty);
  return div.innerHTML;
};

/**
 * Sınırlı HTML etiketlerine izin verir (b, i, em, strong, br, p, ul, ol, li).
 * DOMPurify yoksa safeText kullanır.
 * @param {string} dirty - Sanitize edilecek HTML
 * @returns {string} Güvenli HTML
 */
window.safeHTML = function (dirty) {
  if (dirty == null || dirty === undefined) return '';
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'br', 'p', 'ul', 'ol', 'li'],
      ALLOWED_ATTR: []
    });
  }
  return window.safeText(dirty);
};
