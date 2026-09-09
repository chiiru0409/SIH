import React, { useState } from 'react';
import { X, ExternalLink, ShieldCheck, ShieldAlert, FileCode, Paperclip, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';
import { EmailMetadata } from '../../types/email';
import { InvestigationCase } from '../../types/investigation';
import { Badge } from '../common/Badge';
import { RiskGauge } from '../common/RiskGauge';
import { HashViewer } from '../common/HashViewer';
import { Modal } from '../common/Modal';

interface EmailPreviewDrawerProps {
  email: EmailMetadata | null;
  investigationCase: InvestigationCase | undefined;
  onClose: () => void;
  onInvestigate: (caseId: string) => void;
}

export const EmailPreviewDrawer: React.FC<EmailPreviewDrawerProps> = ({
  email,
  investigationCase,
  onClose,
  onInvestigate
}) => {
  const [showRawHeaders, setShowRawHeaders] = useState(false);

  if (!email) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-cyber-panel border-l border-slate-700/80 shadow-2xl z-40 flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-cyber-slate/30 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-cyan-400">{email.id}</span>
            {investigationCase && (
              <Badge variant="severity" severity={investigationCase.verdict.severity}>
                {investigationCase.verdict.severity}
              </Badge>
            )}
          </div>
          <h3 className="text-sm font-semibold text-slate-100 mt-1 truncate max-w-md">
            {email.subject}
          </h3>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Body / Content */}
      <div className="flex-1 overflow-y-auto cyber-scrollbar p-5 space-y-4">
        {/* Quick Action Top Bar */}
        {investigationCase && (
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <RiskGauge score={investigationCase.verdict.overallRiskScore} size="sm" />
              <div>
                <div className="text-xs font-mono font-bold text-slate-200">
                  {investigationCase.verdict.primaryThreat}
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Confidence: {investigationCase.verdict.confidenceScore}%
                </div>
              </div>
            </div>
            <button
              onClick={() => onInvestigate(investigationCase.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500 text-slate-950 font-mono text-xs font-bold hover:bg-cyan-400 transition-colors shadow-glow-accent"
            >
              <span>Investigate Case</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Envelope & Metadata Details */}
        <div className="p-3.5 rounded-lg bg-cyber-dark/80 border border-slate-800 text-xs font-mono space-y-2">
          <div className="flex items-start justify-between">
            <span className="text-slate-400">From (Header):</span>
            <span className="text-slate-200 font-semibold">{email.headers.from}</span>
          </div>
          <div className="flex items-start justify-between">
            <span className="text-slate-400">Envelope-From:</span>
            <span className="text-amber-400/90">{email.headers.returnPath}</span>
          </div>
          <div className="flex items-start justify-between">
            <span className="text-slate-400">To:</span>
            <span className="text-slate-200">{email.headers.to}</span>
          </div>
          <div className="flex items-start justify-between">
            <span className="text-slate-400">Date:</span>
            <span className="text-slate-300">{new Date(email.headers.date).toUTCString()}</span>
          </div>
          <div className="flex items-start justify-between pt-1 border-t border-slate-800/80">
            <span className="text-slate-400">Originating IP:</span>
            <span className="text-cyan-400">{email.headers.originatingIp}</span>
          </div>
        </div>

        {/* Authentication Summary Badges */}
        <div className="grid grid-cols-3 gap-2">
          <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
            <div className="text-[10px] font-mono text-slate-400 uppercase">SPF</div>
            <Badge variant="protocol" protocolStatus={email.authenticationResults.spf.status} size="xs" className="mt-1">
              {email.authenticationResults.spf.status}
            </Badge>
          </div>
          <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
            <div className="text-[10px] font-mono text-slate-400 uppercase">DKIM</div>
            <Badge variant="protocol" protocolStatus={email.authenticationResults.dkim.status} size="xs" className="mt-1">
              {email.authenticationResults.dkim.status}
            </Badge>
          </div>
          <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
            <div className="text-[10px] font-mono text-slate-400 uppercase">DMARC</div>
            <Badge variant="protocol" protocolStatus={email.authenticationResults.dmarc.status} size="xs" className="mt-1">
              {email.authenticationResults.dmarc.status}
            </Badge>
          </div>
        </div>

        {/* Sanitized Message Body */}
        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 border-b border-slate-800 pb-2">
            <span>Sanitized Body Content (Defanged)</span>
            <span className="text-emerald-400 text-[10px] flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> Scripts Stripped
            </span>
          </div>
          <div className="text-xs text-slate-300 whitespace-pre-wrap font-sans leading-relaxed pt-1">
            {email.bodyText}
          </div>
        </div>

        {/* Extracted URLs */}
        {email.extractedUrls.length > 0 && (
          <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
            <div className="text-xs font-mono font-bold text-slate-300 flex items-center gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
              <span>Extracted Defanged URLs ({email.extractedUrls.length})</span>
            </div>
            {email.extractedUrls.map((u, idx) => (
              <div key={idx} className="p-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono">
                <div className="text-cyan-300 break-all">{u.defangedUrl}</div>
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1">
                  <span>Domain: {u.domain}</span>
                  <span className={u.riskScore > 50 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                    Risk: {u.riskScore}/100
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Attachments */}
        {email.attachments.length > 0 && (
          <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
            <div className="text-xs font-mono font-bold text-slate-300 flex items-center gap-1.5">
              <Paperclip className="w-3.5 h-3.5 text-cyan-400" />
              <span>Attachments ({email.attachments.length})</span>
            </div>
            {email.attachments.map((att, idx) => (
              <div key={idx} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">{att.filename}</span>
                  <span className="text-slate-400">{att.sizeBytes} bytes</span>
                </div>
                <HashViewer hash={att.sha256} label="SHA-256" truncateLength={24} />
              </div>
            ))}
          </div>
        )}

        {/* Raw Header Button */}
        <button
          onClick={() => setShowRawHeaders(true)}
          className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-xs font-mono text-cyan-400 transition-colors"
        >
          <FileCode className="w-4 h-4" />
          <span>View Full RFC-822 Headers</span>
        </button>
      </div>

      {/* Raw Header Modal */}
      <Modal
        isOpen={showRawHeaders}
        onClose={() => setShowRawHeaders(false)}
        title={`RFC-822 Raw Headers (${email.id})`}
        subtitle="Cryptographically verified email header structure"
        maxWidth="4xl"
      >
        <pre className="text-xs font-mono bg-slate-950 p-4 rounded text-cyan-300/90 overflow-x-auto cyber-scrollbar leading-relaxed">
          {email.rawHeaders}
        </pre>
      </Modal>
    </div>
  );
};
