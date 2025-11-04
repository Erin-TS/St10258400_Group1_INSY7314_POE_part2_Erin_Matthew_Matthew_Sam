/*  Server-side HTML sanitizer
 *  Uses the `sanitize-html` library to sanitize user input before saving or displaying.
 *  This helps prevent XSS attacks by allowing only a safe subset of HTML tags and attributes.
 */
import sanitizeHtml from 'sanitize-html';

export const safeHTML = (dirty = '') =>
  sanitizeHtml(dirty, {
    allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
    allowedAttributes: {}
  });