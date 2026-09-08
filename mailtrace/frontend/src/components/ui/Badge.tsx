import React from 'react';
import { cn, getSeverityBadgeStyles } from '../../lib/utils';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'severity' | 'fact' | 'inference' | 'success' | 'warning' | 'danger' | 'outline';
  severity?: string | null;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  className,
  variant = 'default',
  severity,
  size = 'md',
  ...props
}) => {
  if (variant === 'severity' && severity) {
    const styles = getSeverityBadgeStyles(severity);
    return (
      <span
        className={cn(
          'cyber-badge',
          styles.bg,
          styles.text,
          styles.border,
          styles.glow,
          size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2.5 py-1',
          className
        )}
        {...props}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 animate-pulse-subtle" />
        {children || severity}
      </span>
    );
  }

  if (variant === 'fact') {
    return (
      <span
        className={cn(
          'cyber-badge bg-emerald-950/60 text-emerald-400 border-emerald-500/40 glow-emerald-sm',
          size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5',
          className
        )}
        title="Empirical deterministic observation directly extracted from email evidence"
        {...props}
      >
        FACT
      </span>
    );
  }

  if (variant === 'inference') {
    return (
      <span
        className={cn(
          'cyber-badge bg-purple-950/60 text-purple-300 border-purple-500/40 shadow-[0_0_8px_rgba(168,85,247,0.2)]',
          size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5',
          className
        )}
        title="Heuristic or model-derived behavioral inference from multiple indicators"
        {...props}
      >
        INFERENCE
      </span>
    );
  }

  const variants: Record<string, string> = {
    default: 'bg-cyber-panel text-cyan-400 border-cyber-border',
    success: 'bg-emerald-950/50 text-emerald-400 border-emerald-500/40 glow-emerald-sm',
    warning: 'bg-amber-950/50 text-amber-400 border-amber-500/40 glow-amber-sm',
    danger: 'bg-red-950/50 text-red-400 border-red-500/40 glow-red-sm',
    outline: 'bg-transparent text-slate-400 border-slate-700',
  };

  const styleClass = variants[variant] || variants.default;

  return (
    <span
      className={cn(
        'cyber-badge',
        styleClass,
        size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2.5 py-1',
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
};
