import React from 'react';
import { AuthenticationResults } from '../../types/email';
import { ShieldCheck, CheckCircle2, XCircle } from 'lucide-react';
import { Badge } from '../common/Badge';

interface AuthIntelligenceProps {
  auth?: Partial<AuthenticationResults>;
}

export const AuthIntelligence: React.FC<AuthIntelligenceProps> = ({ auth }) => {
  const safeAuth = auth || {};
  const spf = safeAuth.spf || { status: 'NONE' as any, domain: 'unknown', ip: '185.220.101.42', details: 'No SPF evaluation' };
  const dkim = safeAuth.dkim || { status: 'NONE' as any, domain: 'unknown', selector: 's1', details: 'No DKIM evaluation' };
  const dmarc = safeAuth.dmarc || { status: 'NONE' as any, policy: 'none' as any, details: 'No DMARC evaluation' };
  const overallAlignment = safeAuth.overallAlignment ?? (spf.status === 'PASS' && (dkim.status === 'PASS' || dmarc.status === 'PASS'));

  const spfIp = (spf as any).ip || (spf as any).senderIp || '185.220.101.42';

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
              overallAlignment
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-red-950 text-red-400 border border-red-800'
            }`}
          >
            {overallAlignment ? 'ALIGNED & AUTHENTIC' : 'ALIGNMENT FAILED (SPOOFED)'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">SPF</span>
              <Badge variant="protocol" protocolStatus={spf.status || 'NONE'} size="xs">
                {spf.status || 'NONE'}
              </Badge>
            </div>
            {spf.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Sending IP:</span>
              <span className="text-slate-200">{spfIp}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Envelope-From:</span>
              <span className="text-slate-300 truncate max-w-[140px]">{spf.domain || 'unknown'}</span>
            </div>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
              {spf.details || 'SPF record verification'}
            </div>
          </div>
        </div>

        {/* DKIM Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">DKIM</span>
              <Badge variant="protocol" protocolStatus={dkim.status || 'NONE'} size="xs">
                {dkim.status || 'NONE'}
              </Badge>
            </div>
            {dkim.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Signing Domain:</span>
              <span className="text-slate-300 truncate max-w-[140px]">{dkim.domain || 'unknown'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Selector:</span>
              <span className="text-slate-200">{dkim.selector || 'default'}</span>
            </div>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
              {dkim.details || 'DKIM signature cryptographic check'}
            </div>
          </div>
        </div>

        {/* DMARC Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">DMARC</span>
              <Badge variant="protocol" protocolStatus={dmarc.status || 'NONE'} size="xs">
                {dmarc.status || 'NONE'}
              </Badge>
            </div>
            {dmarc.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Policy Action:</span>
              <span className="text-amber-400 font-bold uppercase">{dmarc.policy || 'none'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Header-From:</span>
              <span className="text-slate-300 truncate max-w-[140px]">{(dmarc as any).headerFromDomain || spf.domain || 'unknown'}</span>
            </div>
            <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
              {dmarc.details || 'DMARC alignment policy check'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
