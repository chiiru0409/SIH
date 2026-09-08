/**
 * sanitize.ts — Defense-in-depth sanitization for untrusted email content.
 * Prevents XSS, script injection, iframe execution, and active link execution.
 */

export function sanitizeHtml(html: string): string {
  if (!html) return '';

  // 1. Remove script tags and contents
  let clean = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

  // 2. Remove style tags (to avoid CSS injection attacks)
  clean = clean.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');

  // 3. Remove inline event handlers like onclick, onload, onerror
  clean = clean.replace(/\son\w+\s*=\s*(['"]).*?\1/gi, '');
  clean = clean.replace(/\son\w+\s*=\s*[^>\s]+/gi, '');

  // 4. Remove iframe, embed, object, applet, meta, link, base, svg, math, form, input, button, select, textarea tags
  clean = clean.replace(/<(iframe|embed|object|applet|meta|link|base|svg|math|form|input|button|select|textarea)[^>]*>/gi, '');
  clean = clean.replace(/<\/(iframe|embed|object|applet|meta|link|base|svg|math|form|input|button|select|textarea)>/gi, '');

  // 5. Defang javascript:, data:, vbscript: links
  clean = clean.replace(/href\s*=\s*['"]\s*(javascript|data|vbscript):[^'"]*['"]/gi, 'href="#"');

  // 6. Force target="_blank", rel="noopener noreferrer nofollow", and defang click
  clean = clean.replace(/<a\b/gi, '<a target="_blank" rel="noopener noreferrer nofollow" onclick="return false;"');

  return clean;
}

export function defangUrl(url: string): string {
  if (!url) return '';
  return url
    .replace(/^https?:\/\//i, (match) => (match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'))
    .replace(/\./g, '[.]');
}

export function defangIp(ip: string): string {
  if (!ip) return '';
  return ip.replace(/\./g, '[.]');
}

