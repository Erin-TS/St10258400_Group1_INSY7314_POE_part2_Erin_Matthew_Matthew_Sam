/*  Server-side HTML sanitizer
    Uses the `sanitize-html` library to sanitize user input.
     */
import sanitizeHtml from 'sanitize-html';

export const safeHTML = (dirty = '') =>
  sanitizeHtml(dirty, {
    allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
    allowedAttributes: {}
  });