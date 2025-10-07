import DOMPurify from 'dompurify';

export const safeHTML = (dirty = '') =>
  DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: []
  });

// centralised XSS protection using DOMPurify. Any user input that is rendered as HTML should be sanitized using this function.  