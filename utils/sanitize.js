/*  Node + Browser compatible sanitizer
    Uses `sanitize-html` on server and
     */
import sanitizeHtml from 'sanitize-html';

export const safeHTML = (dirty = '') =>
  sanitizeHtml(dirty, {
    allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
    allowedAttributes: {}
  });