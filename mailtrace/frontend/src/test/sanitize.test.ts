import { describe, it, expect } from 'vitest';
import { sanitizeHtml, defangUrl, defangIp } from '../lib/sanitize';

describe('Sanitization and Defanging Utilities', () => {
  it('strips <script> tags and malicious inline handlers', () => {
    const malicious = `<div>Hello <script>alert("XSS")</script><img src="x" onerror="stealCookies()" /><a href="javascript:alert(1)">Click</a></div>`;
    const clean = sanitizeHtml(malicious);

    expect(clean).not.toContain('<script>');
    expect(clean).not.toContain('alert("XSS")');
    expect(clean).not.toContain('onerror=');
    expect(clean).not.toContain('javascript:');
    expect(clean).toContain('Hello');
  });

  it('strips form elements, svg, and defangs links with click blocker', () => {
    const malicious = `<form action="http://evil.com"><input type="text" name="pwd"/><button>Submit</button></form><svg><circle /></svg><a href="https://legit.com">Link</a>`;
    const clean = sanitizeHtml(malicious);

    expect(clean).not.toContain('<form');
    expect(clean).not.toContain('<input');
    expect(clean).not.toContain('<button');
    expect(clean).not.toContain('<svg');
    expect(clean).toContain('onclick="return false;"');
  });

  it('defangs URLs properly without altering paths', () => {
    expect(defangUrl('http://evil.com/login')).toBe('hxxp://evil[.]com/login');
    expect(defangUrl('https://secure-bank.example.org/auth')).toBe('hxxps://secure-bank[.]example[.]org/auth');
  });

  it('defangs IP addresses', () => {
    expect(defangIp('192.168.1.1')).toBe('192[.]168[.]1[.]1');
    expect(defangIp('8.8.8.8')).toBe('8[.]8[.]8[.]8');
  });
});

