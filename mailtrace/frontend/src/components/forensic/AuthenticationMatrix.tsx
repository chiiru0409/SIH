import React from 'react';
import { ShieldCheck, ShieldX, HelpCircle, ShieldAlert, Key, Globe, Check } from 'lucide-react';
import { Card } from '../ui/Card';
import type { AuthenticationStatus } from '../../types/api';

export interface AuthenticationMatrixProps {
  auth?: AuthenticationStatus | null;
  alignment?: {
    spf_aligned?: boolean | null;
    dkim_aligned?: boolean | null;
    dmarc_aligned?: boolean | null;
    dmarc_pass?: boolean | null;
    header_from_domain?: string | null;
    envelope_from_domain?: string | null;
    dkim_domain?: string | null;
  } | null;
  className?: string;
}

export const AuthenticationMatrix: React.FC<AuthenticationMatrixProps> = ({
  auth,
  alignment,
  className,
}) => {
  const getStatusBadge = (status?: any) => {
    let s = 'UNKNOWN';
    if (typeof status === 'string') {
      s = status.toUpperCase();
    } else if (status && typeof status === 'object') {
      s = String(status.result || status.status || status.verdict || status.value || 'UNKNOWN').toUpperCase();
    }

    if (s === 'PASS') {
      return {
        label: 'PASS',
        bg: 'bg-emerald-950/60 text-emerald-400 border-emerald-500/50 glow-emerald-sm',
        icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
      };
    }
    if (s === 'FAIL' || s === 'SOFTFAIL' || s === 'PERMERROR') {
      return {
        label: s,
        bg: 'bg-red-950/60 text-red-400 border-red-500/50 glow-red-sm',
        icon: <ShieldX className="w-4 h-4 text-red-400" />,
      };
    }
    return {
      label: s || 'UNKNOWN',
      bg: 'bg-slate-900/60 text-slate-400 border-slate-700',
      icon: <HelpCircle className="w-4 h-4 text-slate-400" />,
    };
  };

  const getAlignmentBadge = (aligned?: boolean | null) => {
    if (aligned === true) {
      return {
        label: 'ALIGNED',
        bg: 'bg-emerald-950/40 text-emerald-400 border-emerald-500/30',
      };
    }
    if (aligned === false) {
      return {
        label: 'MISALIGNED',
        bg: 'bg-amber-950/40 text-amber-400 border-amber-500/30',
      };
    }
    return {
      label: 'UNKNOWN',
      bg: 'bg-slate-900/40 text-slate-400 border-slate-800',
    };
  };

  const spfStatus = getStatusBadge(auth?.spf);
  const dkimStatus = getStatusBadge(auth?.dkim);
  const dmarcStatus = getStatusBadge(auth?.dmarc);

  const spfAlign = getAlignmentBadge(alignment?.spf_aligned);
  const dkimAlign = getAlignmentBadge(alignment?.dkim_aligned);

  return (
    <Card
      title="AUTHENTICATION & ALIGNMENT MATRIX"
      subtitle="RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC) validation"
      icon={<Key className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* SPF Card */}
        <div className="p-4 rounded-xl bg-cyber-surface border border-cyber-border space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-sm font-extrabold text-slate-100">SPF</span>
              <span className="text-[10px] font-mono text-slate-400">Sender Policy Framework</span>
            </div>
            {spfStatus.icon}
          </div>

          <div className="space-y-2 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Status:</span>
              <span className={`font-mono text-xs font-bold px-2.5 py-0.5 rounded border uppercase ${spfStatus.bg}`}>
                {spfStatus.label}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Alignment:</span>
              <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${spfAlign.bg}`}>
                {spfAlign.label}
              </span>
            </div>

            {alignment?.envelope_from_domain && (
              <div className="pt-2 border-t border-cyber-border/40 text-[10px] font-mono text-slate-400 truncate">
                <span className="text-slate-500">Envelope: </span>
                <span className="text-slate-200">{alignment.envelope_from_domain}</span>
              </div>
            )}
          </div>
        </div>

        {/* DKIM Card */}
        <div className="p-4 rounded-xl bg-cyber-surface border border-cyber-border space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-sm font-extrabold text-slate-100">DKIM</span>
              <span className="text-[10px] font-mono text-slate-400">DomainKeys Identified Mail</span>
            </div>
            {dkimStatus.icon}
          </div>

          <div className="space-y-2 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Status:</span>
              <span className={`font-mono text-xs font-bold px-2.5 py-0.5 rounded border uppercase ${dkimStatus.bg}`}>
                {dkimStatus.label}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Alignment:</span>
              <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${dkimAlign.bg}`}>
                {dkimAlign.label}
              </span>
            </div>

            {alignment?.dkim_domain && (
              <div className="pt-2 border-t border-cyber-border/40 text-[10px] font-mono text-slate-400 truncate">
                <span className="text-slate-500">DKIM Domain: </span>
                <span className="text-slate-200">{alignment.dkim_domain}</span>
              </div>
            )}
          </div>
        </div>

        {/* DMARC Card */}
        <div className="p-4 rounded-xl bg-cyber-surface border border-cyber-border space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-sm font-extrabold text-slate-100">DMARC</span>
              <span className="text-[10px] font-mono text-slate-400">Domain-based Auth Policy</span>
            </div>
            {dmarcStatus.icon}
          </div>

          <div className="space-y-2 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Status:</span>
              <span className={`font-mono text-xs font-bold px-2.5 py-0.5 rounded border uppercase ${dmarcStatus.bg}`}>
                {dmarcStatus.label}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Header From:</span>
              <span className="font-mono text-[10px] text-slate-300 truncate max-w-[140px]">
                {alignment?.header_from_domain || 'UNAVAILABLE'}
              </span>
            </div>

            <div className="pt-2 border-t border-cyber-border/40 text-[10px] font-mono text-slate-400 flex items-center justify-between">
              <span className="text-slate-500">Policy Evaluation:</span>
              <span className={alignment?.dmarc_pass ? 'text-emerald-400 font-bold' : 'text-slate-400 font-bold'}>
                {alignment?.dmarc_pass ? 'PASS' : 'REJECT / NONE / FAIL'}
              </span>
            </div>
          </div>
        </div>

      </div>
    </Card>
  );
};
