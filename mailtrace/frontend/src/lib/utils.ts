import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatDate(dateStr?: any): string {
  if (!dateStr) return 'UNAVAILABLE';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return typeof dateStr === 'string' ? dateStr : String(dateStr);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return typeof dateStr === 'string' ? dateStr : String(dateStr || 'UNAVAILABLE');
  }
}

export function truncateHash(hash?: any, length: number = 8): string {
  if (!hash) return '';
  const str = typeof hash === 'string' ? hash : String(hash);
  if (str.length <= length * 2) return str;
  return `${str.slice(0, length)}…${str.slice(-length)}`;
}

export function getSeverityBadgeStyles(severity?: string | null): {
  bg: string;
  text: string;
  border: string;
  glow: string;
} {
  const sev = (severity || '').toUpperCase();
  switch (sev) {
    case 'CRITICAL':
      return {
        bg: 'bg-red-950/50',
        text: 'text-red-400',
        border: 'border-red-500/40',
        glow: 'shadow-[0_0_12px_rgba(239,68,68,0.25)]',
      };
    case 'HIGH':
      return {
        bg: 'bg-orange-950/50',
        text: 'text-orange-400',
        border: 'border-orange-500/40',
        glow: 'shadow-[0_0_12px_rgba(249,115,22,0.2)]',
      };
    case 'MEDIUM':
      return {
        bg: 'bg-amber-950/50',
        text: 'text-amber-400',
        border: 'border-amber-500/40',
        glow: 'shadow-[0_0_12px_rgba(245,158,11,0.15)]',
      };
    case 'LOW':
      return {
        bg: 'bg-emerald-950/50',
        text: 'text-emerald-400',
        border: 'border-emerald-500/40',
        glow: 'shadow-[0_0_12px_rgba(16,185,129,0.15)]',
      };
    case 'INFO':
    default:
      return {
        bg: 'bg-slate-900/60',
        text: 'text-cyan-400',
        border: 'border-cyan-500/30',
        glow: 'shadow-[0_0_8px_rgba(6,182,212,0.15)]',
      };
  }
}

export async function calculateSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
