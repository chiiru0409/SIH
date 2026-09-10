import React from 'react';
import { UserX, CheckCircle2, AlertTriangle, UserCheck, ShieldAlert, ArrowRight } from 'lucide-react';
import { EmailMetadata } from '../../types/email';
import { InvestigationCase } from '../../types/investigation';
import { safeStr } from '../../lib/utils';

interface IdentityAnalysisProps {
  email: EmailMetadata;
  investigationCase: InvestigationCase;
}

export const IdentityAnalysis: React.FC<IdentityAnalysisProps> = ({ email, investigationCase }) => {
  const headers = email.headers || {};
  const fromHeader = safeStr(headers.from || email.senderAddress || 'unknown@domain.com');
  const returnPath = safeStr(headers.returnPath || fromHeader);
  const replyTo = safeStr((email as any).replyTo || (headers as any).replyTo || fromHeader);
  
  // Extract display name and email address
  let displayName = '';
  let fromAddress = fromHeader;
  if (fromHeader.includes('<') && fromHeader.includes('>')) {
    const parts = fromHeader.split('<');
    displayName = parts[0].trim().replace(/^["']|["']$/g, '');
    fromAddress = parts[1].replace('>', '').trim();
  }

  const fromDomain = fromAddress.includes('@') ? fromAddress.split('@')[1] : 'unknown';
  const returnDomain = returnPath.includes('@') ? returnPath.split('@')[1] : fromDomain;
  const replyToDomain = replyTo.includes('@') ? replyTo.split('@')[1] : fromDomain;

  const hasReplyToMismatch = replyToDomain.toLowerCase() !== fromDomain.toLowerCase();
  const hasReturnPathMismatch = returnDomain.toLowerCase() !== fromDomain.toLowerCase();
  const isSpoofedDisplayName = displayName.length > 0 && (
    displayName.toLowerCase().includes('microsoft') ||
    displayName.toLowerCase().includes('director') ||
    displayName.toLowerCase().includes('officer') ||
    displayName.toLowerCase().includes('security') ||
    displayName.toLowerCase().includes('helpdesk') ||
    displayName.toLowerCase().includes('admin')
  ) && !fromDomain.includes('microsoft.com') && !fromDomain.includes('gov.in');

  const hasDiscrepancy = hasReplyToMismatch || hasReturnPathMismatch || isSpoofedDisplayName;

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <UserX className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Sender Identity & Header Discrepancy Analysis
          </h3>
        </div>
        <span
          className={`text-xs font-mono px-2 py-0.5 rounded font-bold ${
            hasDiscrepancy
              ? 'bg-red-950 text-red-400 border border-red-800'
              : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
          }`}
        >
          {hasDiscrepancy ? 'IDENTITY DISCREPANCY DETECTED' : 'IDENTITY CONSISTENT'}
        </span>
      </div>

      {/* Identity Breakdown Table */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
            RFC-822 Identity Headers
          </div>

          <div className="space-y-2">
            <div>
              <span className="text-slate-500 block text-[10px]">Claimed Display Name:</span>
              <span className="text-slate-200 font-semibold">{displayName || '(No Display Name Declared)'}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Header-From Address:</span>
              <span className="text-cyan-400">{fromAddress}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Reply-To Target:</span>
              <span className={hasReplyToMismatch ? 'text-red-400 font-bold' : 'text-slate-300'}>
                {replyTo}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Envelope Return-Path:</span>
              <span className={hasReturnPathMismatch ? 'text-amber-400' : 'text-slate-300'}>
                {returnPath}
              </span>
            </div>
          </div>
        </div>

        {/* Anomaly Evaluation Cards */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
          <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
            Discrepancy Checks & Spoof Indicators
          </div>

          <div className="space-y-2">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {isSpoofedDisplayName ? (
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                <div>
                  <div className="font-bold text-slate-200">Display Name Spoofing</div>
                  <div className="text-[10px] text-slate-400">
                    {isSpoofedDisplayName ? 'Brand/VIP impersonation detected' : 'No deceptive display name keywords'}
                  </div>
                </div>
              </div>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${isSpoofedDisplayName ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                {isSpoofedDisplayName ? 'ANOMALY' : 'PASS'}
              </span>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {hasReplyToMismatch ? (
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                <div>
                  <div className="font-bold text-slate-200">Reply-To Routing Mismatch</div>
                  <div className="text-[10px] text-slate-400">
                    {hasReplyToMismatch ? 'Reply routed to separate external mailbox' : 'Reply-To aligns with Header-From'}
                  </div>
                </div>
              </div>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${hasReplyToMismatch ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                {hasReplyToMismatch ? 'DIVERGENT' : 'ALIGNED'}
              </span>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {hasReturnPathMismatch ? (
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                <div>
                  <div className="font-bold text-slate-200">Return-Path Alignment</div>
                  <div className="text-[10px] text-slate-400">
                    {hasReturnPathMismatch ? 'Envelope bounce domain diverges from sender' : 'Bounce address matches sender domain'}
                  </div>
                </div>
              </div>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${hasReturnPathMismatch ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                {hasReturnPathMismatch ? 'MISMATCH' : 'MATCH'}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-slate-400">
        <strong className="text-slate-300">Forensic Disclaimer:</strong> Identity analysis reflects technical discrepancies across RFC-822 headers; does not constitute legal proof of individual human identity.
      </div>
    </div>
  );
};
