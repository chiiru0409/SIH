import React from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'info' | 'success' | 'warning' | 'error';
  title?: string;
  icon?: boolean;
}

export const Alert: React.FC<AlertProps> = ({
  children,
  className,
  variant = 'info',
  title,
  icon = true,
  ...props
}) => {
  const configs = {
    info: {
      bg: 'bg-cyan-950/40 border-cyan-500/40 text-cyan-200',
      iconEl: <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />,
      titleColor: 'text-cyan-300',
    },
    success: {
      bg: 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200',
      iconEl: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />,
      titleColor: 'text-emerald-300',
    },
    warning: {
      bg: 'bg-amber-950/40 border-amber-500/40 text-amber-200',
      iconEl: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />,
      titleColor: 'text-amber-300',
    },
    error: {
      bg: 'bg-red-950/40 border-red-500/40 text-red-200',
      iconEl: <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />,
      titleColor: 'text-red-300',
    },
  };

  const config = configs[variant];

  return (
    <div
      className={cn('flex items-start space-x-3 p-4 rounded-lg border text-xs leading-relaxed', config.bg, className)}
      role="alert"
      {...props}
    >
      {icon && config.iconEl}
      <div className="flex-1 space-y-1">
        {title && <h4 className={cn('font-mono font-bold tracking-wide uppercase', config.titleColor)}>{title}</h4>}
        <div>{children}</div>
      </div>
    </div>
  );
};
