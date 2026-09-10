import React, { useState } from 'react';
import { AuthenticationResults } from '../../types/email';
import { ShieldCheck, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronUp, Lock } from 'lucide-react';
import { Badge } from '../common/Badge';
import { safeStr } from '../../lib/utils';

interface AuthIntelligenceProps {
  auth?: Partial<AuthenticationResults>;
}

export const AuthIntelligence: React.FC<AuthIntelligenceProps> = ({ auth }) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);
  const safeAuth = auth || {};
  const spf = safeAuth.spf || { status: 'NONE' as any, domain: 'unknown', ip: '185.220.101.42', details: 'No SPF evaluation' };
  const dkim = safeAuth.dkim || { status: 'NONE' as any, domain: 'unknown', selector: 's1', details: 'No DKIM evaluation' };
  const dmarc = safeAuth.dmarc || { status: 'NONE' as any, policy: 'none' as any, details: 'No DMARC evaluation' };
  const overallAlignment = Boolean(safeAuth.overallAlignment ?? (spf.status === 'PASS' && (dkim.status === 'PASS' || dmarc.status === 'PASS')));

  const spfIp = safeStr((spf as any).ip || (spf as any).senderIp || '185.220.101.42');
  const spfDomain = safeStr(spf.domain || 'unknown');
  const spfDetails = safeStr(spf.details || 'SPF record verification');

  const dkimDomain = safeStr(dkim.domain || 'unknown');
  const dkimSelector = safeStr(dkim.selector || 'default');
  const dkimDetails = safeStr(dkim.details || 'DKIM signature cryptographic check');

  const dmarcPolicy = safeStr(dmarc.policy || 'none');
  const dmarcFrom = safeStr((dmarc as any).headerFromDomain || spf.domain || 'unknown');
  const dmarcDetails = safeStr(dmarc.details || 'DMARC alignment policy check');

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Email Authentication & Domain Alignment
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`text-xs font-mono px-2.5 py-0.5 rounded-full font-bold ${
              overallAlignment
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-red-950 text-red-400 border border-red-800 animate-pulse'
            }`}
          >
            {overallAlignment ? 'ALIGNED & AUTHENTIC' : 'SPOOFING DETECTED (AUTH FAILED)'}
          </span>
        </div>
      </div>

      {/* PLAIN-ENGLISH EXECUTIVE SUMMARY BANNER */}
      <div className={`p-3.5 rounded-lg border font-mono text-xs flex items-start gap-3 ${
        overallAlignment
          ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
          : 'bg-red-950/20 border-red-500/30 text-red-300'
      }`}>
        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold uppercase text-[11px] block">
            {overallAlignment ? 'Domain Identity Verified' : 'Authentication Failure: Unauthorized Relay'}
          </span>
          <p className="text-[11px] text-slate-300 font-sans mt-0.5 leading-relaxed">
            {overallAlignment
              ? 'The sending server is cryptographically authorized and aligned with the domain policy.'
              : 'The sending server is not authorized to deliver on behalf of the claimed domain. The sender identity is spoofed.'}
          </p>
        </div>
      </div>

      {/* 3 HIGH-LEVEL PROTOCOL CARDS WITH PLAIN-ENGLISH EXPLANATIONS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">SPF</span>
              <Badge variant="protocol" protocolStatus={spf.status || 'NONE'} size="xs">
                {safeStr(spf.status || 'NONE')}
              </Badge>
            </div>
            {spf.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>
          <p className="text-[11px] text-slate-400 font-sans leading-tight">
            Checks whether the sending server is authorized to send email for this domain.
          </p>
          <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-300">
            <span className="text-slate-500 text-[10px] block uppercase">Sending Node IP</span>
            <span className="text-cyan-400 font-bold">{spfIp}</span>
          </div>
        </div>

        {/* DKIM Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">DKIM</span>
              <Badge variant="protocol" protocolStatus={dkim.status || 'NONE'} size="xs">
                {safeStr(dkim.status || 'NONE')}
              </Badge>
            </div>
            {dkim.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>
          <p className="text-[11px] text-slate-400 font-sans leading-tight">
            Checks whether the message carries a valid cryptographic signature from the claimed domain.
          </p>
          <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-300">
            <span className="text-slate-500 text-[10px] block uppercase">Signature Domain</span>
            <span className="text-slate-200">{dkimDomain}</span>
          </div>
        </div>

        {/* DMARC Card */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-200">DMARC</span>
              <Badge variant="protocol" protocolStatus={dmarc.status || 'NONE'} size="xs">
                {safeStr(dmarc.status || 'NONE')}
              </Badge>
            </div>
            {dmarc.status === 'PASS' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400" />
            )}
          </div>
          <p className="text-[11px] text-slate-400 font-sans leading-tight">
            Checks whether the sender identity aligns with the domain's authentication policy.
          </p>
          <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-300">
            <span className="text-slate-500 text-[10px] block uppercase">Policy Enforcement</span>
            <span className="text-red-400 font-bold uppercase">{dmarcPolicy}</span>
          </div>
        </div>
      </div>

      {/* PROGRESSIVE DISCLOSURE TOGGLE FOR RAW AUTH HEADERS */}
      <div className="pt-2 border-t border-slate-800/60">
        <button
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-300 hover:text-cyan-400 transition-colors"
        >
          <span className="font-bold flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showTechnicalDetails ? 'Hide Raw Authentication Headers' : 'View Raw Authentication Headers & Alignment Telemetry'}</span>
          </span>
          {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {showTechnicalDetails && (
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2 font-mono text-xs mt-3 animate-in fade-in">
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">SPF Details:</span>
              <span className="text-slate-200">{spfDetails}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">DKIM Selector & Details:</span>
              <span className="text-slate-200">{dkimSelector} • {dkimDetails}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">DMARC Evaluated From:</span>
              <span className="text-slate-200">{dmarcFrom} • {dmarcDetails}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
