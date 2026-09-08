import { describe, it, expect } from 'vitest';
import { formatBytes, formatDate, truncateHash, getSeverityBadgeStyles } from '../lib/utils';

describe('General Utilities & Styling Helpers', () => {
  it('formats byte sizes cleanly', () => {
    expect(formatBytes(0)).toBe('0 Bytes');
    expect(formatBytes(1024)).toBe('1 KB');
    expect(formatBytes(1048576)).toBe('1 MB');
    expect(formatBytes(5242880)).toBe('5 MB');
  });

  it('truncates SHA-256 hashes gracefully', () => {
    const hash = 'a6b350648c668478d8a7c06cb3884b2591605ec103a3d548325a7cd022649b38';
    expect(truncateHash(hash, 6)).toBe('a6b350…649b38');
    expect(truncateHash('', 6)).toBe('');
  });

  it('returns valid severity badge styling configs', () => {
    const crit = getSeverityBadgeStyles('CRITICAL');
    expect(crit.text).toContain('red');

    const high = getSeverityBadgeStyles('HIGH');
    expect(high.text).toContain('orange');

    const med = getSeverityBadgeStyles('MEDIUM');
    expect(med.text).toContain('amber');

    const low = getSeverityBadgeStyles('LOW');
    expect(low.text).toContain('emerald');
  });
});
