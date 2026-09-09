import React from 'react';
import { AuthenticationResults } from '../../types/email';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, AlertCircle, RefreshCw } from 'lucide-react';
import { Badge } from '../common/Badge';

interface AuthIntelligenceProps {
  auth: AuthenticationResults;
}

export const AuthIntelligence: React.FC<AuthIntelligenceProps> = ({ auth }) => {
  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Email Authentication & Domain Alignment (SPF / DKIM / DMARC)
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`text-xs font-mono px-2 py-0.5 rounded font-bold ${
              auth.overallAlignment
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-red-950 text-red-400 border border-red-800'
            }`}
          >
            {auth.overallAlignment ? 'ALIGNED & AUTHENTIC' : 'ALIGNMENT FAILED (SPOOFED)'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">SPF</span>
              <Badge variant="protocol" protocolStatus={auth.spf.status} size="xs">
                {auth.spf.status}
              </Badge>
            </div>
            {auth.spf.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Sending IP:</span>
              <span className="text-slate-200">{auth.spf.ip}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Envelope-From:</span>
              <span className="text-slate-300 truncate max-w-[140px]">{auth.spf.domain}</span>
            </div>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
              {auth.spf.details}
            </div>
          </div>
        </div>

        {/* DKIM Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">DKIM</span>
              <Badge variant="protocol" protocolStatus={auth.dkim.status} size="xs">
                {auth.dkim.status}
              </Badge>
            </div>
            {auth.dkim.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Signature Domain (d=):</span>
              <span className="text-slate-200 truncate max-w-[120px]">{auth.dkim.domain}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Selector (s=):</span>
              <span className="text-slate-300">{auth.dkim.selector}</span>
            </div>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
              {auth.dkim.details}
            </div>
          </div>
        </div>

        {/* DMARC Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">DMARC</span>
              <Badge variant="protocol" protocolStatus={auth.dmarc.status} size="xs">
                {auth.dmarc.status}
              </Badge>
            </div>
            {auth.dmarc.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Domain Policy (p=):</span>
              <span className="text-amber-400 font-bold uppercase">{auth.dmarc.policy}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Header-From:</span>
              <span className="text-slate-200 truncate max-w-[130px]">{auth.dmarc.headerFromDomain}</span>
            </div>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
              {auth.dmarc.details}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
