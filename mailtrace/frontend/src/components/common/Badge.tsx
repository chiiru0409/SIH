import React from 'react';
import { ThreatSeverity, ThreatCategory, AuthStatus } from '../../types/email';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'severity' | 'status' | 'protocol' | 'neutral' | 'outline' | 'risk';
  severity?: ThreatSeverity | 'BENIGN';
  protocolStatus?: AuthStatus;
  category?: ThreatCategory;
  size?: 'xs' | 'sm' | 'md';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  severity,
  protocolStatus,
  size = 'sm',
  className = ''
}) => {
  const sizeClasses = {
    xs: 'px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider',
    sm: 'px-2 py-0.5 text-xs font-mono font-medium',
    md: 'px-2.5 py-1 text-xs font-mono font-semibold'
  }[size];

  let colorClasses = 'bg-cyber-slate/50 text-slate-300 border border-slate-700/60';

  if (variant === 'severity' && severity) {
    switch (severity) {
      case 'CRITICAL':
        colorClasses = 'bg-threat-critical/15 text-threat-critical border border-threat-critical/40 shadow-glow-critical';
        break;
      case 'HIGH':
        colorClasses = 'bg-threat-high/15 text-threat-high border border-threat-high/40 shadow-glow-high';
        break;
      case 'MEDIUM':
        colorClasses = 'bg-threat-medium/15 text-threat-medium border border-threat-medium/40';
        break;
      case 'LOW':
        colorClasses = 'bg-threat-low/15 text-threat-low border border-threat-low/40';
        break;
      case 'BENIGN':
        colorClasses = 'bg-threat-benign/15 text-threat-benign border border-threat-benign/40 shadow-glow-benign';
        break;
    }
  } else if (variant === 'protocol' && protocolStatus) {
    switch (protocolStatus) {
      case 'PASS':
        colorClasses = 'bg-threat-benign/15 text-threat-benign border border-threat-benign/40';
        break;
      case 'FAIL':
      case 'PERMERROR':
        colorClasses = 'bg-threat-critical/15 text-threat-critical border border-threat-critical/40';
        break;
      case 'SOFTFAIL':
      case 'TEMPERROR':
        colorClasses = 'bg-threat-medium/15 text-threat-medium border border-threat-medium/40';
        break;
      case 'NONE':
        colorClasses = 'bg-slate-800 text-slate-400 border border-slate-700';
        break;
    }
  } else if (variant === 'outline') {
    colorClasses = 'border border-cyber-accent/30 text-cyber-accent bg-cyber-accent/5';
  }

  return (
    <span
      className={`inline-flex items-center gap-1 rounded font-mono select-none ${sizeClasses} ${colorClasses} ${className}`}
    >
      {children}
    </span>
  );
};
