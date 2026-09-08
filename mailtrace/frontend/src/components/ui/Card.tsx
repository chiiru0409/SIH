import React from 'react';
import { cn } from '../../lib/utils';

export interface CardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  interactive?: boolean;
  glow?: 'cyan' | 'red' | 'amber' | 'emerald' | 'none';
  headerActions?: React.ReactNode;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
}

export const Card: React.FC<CardProps> = ({
  children,
  className,
  interactive = false,
  glow = 'none',
  headerActions,
  title,
  subtitle,
  icon,
  ...props
}) => {
  const glowStyles = {
    cyan: 'hover:border-cyan-500/40 hover:shadow-[0_0_20px_rgba(0,240,255,0.15)]',
    red: 'hover:border-red-500/40 hover:shadow-[0_0_20px_rgba(239,68,68,0.15)]',
    amber: 'hover:border-amber-500/40 hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
    emerald: 'hover:border-emerald-500/40 hover:shadow-[0_0_20px_rgba(160,185,129,0.15)]',
    none: '',
  };

  return (
    <div
      className={cn(
        'rounded-lg p-5',
        interactive ? 'cyber-panel-interactive cursor-pointer' : 'cyber-panel',
        glowStyles[glow],
        className
      )}
      {...props}
    >
      {(title || headerActions) && (
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-cyber-border/70">
          <div className="flex items-center space-x-2.5">
            {icon && <span className="text-cyber-cyan shrink-0">{icon}</span>}
            <div>
              {typeof title === 'string' ? (
                <h3 className="font-mono text-xs uppercase tracking-wider font-semibold text-slate-200">
                  {title}
                </h3>
              ) : (
                title
              )}
              {subtitle && (
                <p className="text-[11px] text-slate-400 mt-0.5">{subtitle}</p>
              )}
            </div>
          </div>
          {headerActions && <div className="shrink-0">{headerActions}</div>}
        </div>
      )}
      {children}
    </div>
  );
};
