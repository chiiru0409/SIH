import React from 'react';
import { UserCheck, AlertTriangle, ArrowRight, ShieldCheck, Mail, GitCompare } from 'lucide-react';
import { Card } from '../ui/Card';
import type { EmailHeaderInfo } from '../../types/api';

export interface IdentityInspectorProps {
  email?: EmailHeaderInfo | null;
  alignmentData?: any;
  flags?: {
    reply_to_mismatch?: boolean;
    return_path_mismatch?: boolean;
    missing_message_id?: boolean;
    [key: string]: boolean | undefined;
  } | null;
  className?: string;
}

export const IdentityInspector: React.FC<IdentityInspectorProps> = ({
  email,
  alignmentData,
  flags,
  className,
}) => {
  if (!email) {
    return (
      <Card title="Identity Forensics" className={className}>
        <div className="py-6 text-center text-xs font-mono text-slate-500">
          IDENTITY DATA UNAVAILABLE
        </div>
      </Card>
    );
  }

  const fromEmail = email.from || 'UNAVAILABLE';
  const replyTo = email.reply_to;
  const returnPath = email.return_path;
  const messageId = email.message_id || 'UNAVAILABLE';

  const hasReplyMismatch = flags?.reply_to_mismatch || (replyTo && fromEmail && replyTo.toLowerCase() !== fromEmail.toLowerCase());
  const hasReturnMismatch = flags?.return_path_mismatch || (returnPath && fromEmail && returnPath.toLowerCase() !== fromEmail.toLowerCase());

  return (
    <Card
      title="IDENTITY & HEADER DISCREPANCY FORENSICS"
      subtitle="Header From, Reply-To, Return-Path, and Message-ID domain verification"
      icon={<UserCheck className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-4">
        
        {/* Visual Identity Flow Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          
          {/* Header From */}
          <div className="p-3.5 rounded-lg bg-cyber-surface border border-cyber-border space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
              DISPLAY / HEADER FROM
            </span>
            <div className="font-mono text-xs font-bold text-slate-100 break-all">
              {fromEmail}
            </div>
            {email.from_display && (
              <div className="text-[11px] text-cyan-400 font-sans italic">
                "{email.from_display}"
              </div>
            )}
          </div>

          {/* Reply-To */}
          <div className={`p-3.5 rounded-lg bg-cyber-surface border space-y-1 ${
            hasReplyMismatch ? 'border-amber-500/50 bg-amber-950/20' : 'border-cyber-border'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                REPLY-TO DESTINATION
              </span>
              {hasReplyMismatch && (
                <span className="text-[9px] font-mono font-bold text-amber-400 bg-amber-950/60 px-1.5 py-0.2 rounded border border-amber-500/40">
                  MISMATCH
                </span>
              )}
            </div>
            <div className={`font-mono text-xs font-bold break-all ${hasReplyMismatch ? 'text-amber-300' : 'text-slate-100'}`}>
              {replyTo || '(Not Specified — Defaults to From)'}
            </div>
          </div>

          {/* Return-Path */}
          <div className={`p-3.5 rounded-lg bg-cyber-surface border space-y-1 ${
            hasReturnMismatch ? 'border-amber-500/50 bg-amber-950/20' : 'border-cyber-border'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                RETURN-PATH (ENVELOPE)
              </span>
              {hasReturnMismatch && (
                <span className="text-[9px] font-mono font-bold text-amber-400 bg-amber-950/60 px-1.5 py-0.2 rounded border border-amber-500/40">
                  MISMATCH
                </span>
              )}
            </div>
            <div className={`font-mono text-xs font-bold break-all ${hasReturnMismatch ? 'text-amber-300' : 'text-slate-100'}`}>
              {returnPath || 'UNAVAILABLE'}
            </div>
          </div>

        </div>

        {/* Mismatch Warning Box */}
        {(hasReplyMismatch || hasReturnMismatch) && (
          <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-500/30 flex items-start space-x-3 text-xs">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1 text-slate-300">
              <span className="font-mono font-bold text-amber-300 uppercase">
                IDENTITY ROUTING DISCREPANCY DETECTED
              </span>
              <p className="text-[11px] leading-relaxed">
                The envelope Return-Path or Reply-To header points to a different domain than the visible sender. 
                While legitimate mailing lists and automated systems frequently use separate reply domains, in unsolicited messages this is an established indicator of deception or bounce redirection.
              </p>
            </div>
          </div>
        )}

        {/* Message-ID & Recipients */}
        <div className="p-3 rounded-lg bg-slate-900/40 border border-cyber-border/70 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          <div>
            <span className="text-slate-500 text-[10px] uppercase block">RFC 5322 Message-ID:</span>
            <span className="text-slate-300 break-all text-[11px]">{messageId}</span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] uppercase block">Recipients (To):</span>
            <span className="text-slate-300 break-all text-[11px]">
              {email.to && email.to.length > 0 ? email.to.join(', ') : 'UNAVAILABLE'}
            </span>
          </div>
        </div>

      </div>
    </Card>
  );
};
