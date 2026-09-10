import React, { useState } from 'react';
import { Mail, Shield, Eye, Lock, FileCode, Check } from 'lucide-react';
import { EmailMetadata } from '../../types/email';
import { safeStr } from '../../lib/utils';

interface EmailBodyPreviewProps {
  email: EmailMetadata;
}

export const EmailBodyPreview: React.FC<EmailBodyPreviewProps> = ({ email }) => {
  const [viewMode, setViewMode] = useState<'DEFANGED' | 'PLAIN' | 'HEADERS'>('DEFANGED');
  const [copied, setCopied] = useState(false);

  const rawHeaders = typeof email.headers === 'object'
    ? Object.entries(email.headers).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n')
    : String(email.headers || '');

  const bodyPlain = safeStr((email as any).body?.plain || (email as any).bodyPlain || (email as any).body || 'No plaintext payload available for this message.');
  const bodyHtml = safeStr((email as any).body?.html || (email as any).bodyHtml || bodyPlain);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Mail className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Sanitized Message Body & Payload Inspection
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-0.5 text-xs font-mono">
            <button
              onClick={() => setViewMode('DEFANGED')}
              className={`px-2.5 py-1 rounded transition-colors ${
                viewMode === 'DEFANGED' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Defanged Preview
            </button>
            <button
              onClick={() => setViewMode('PLAIN')}
              className={`px-2.5 py-1 rounded transition-colors ${
                viewMode === 'PLAIN' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Raw Plaintext
            </button>
            <button
              onClick={() => setViewMode('HEADERS')}
              className={`px-2.5 py-1 rounded transition-colors ${
                viewMode === 'HEADERS' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              RFC-822 Headers
            </button>
          </div>

          <button
            onClick={() => handleCopy(viewMode === 'HEADERS' ? rawHeaders : bodyPlain)}
            className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition-colors text-xs font-mono"
            title="Copy Content"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <FileCode className="w-4 h-4" />}
          </button>
        </div>
      </div>

      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/90 text-xs font-mono min-h-[140px] max-h-[320px] overflow-y-auto cyber-scrollbar">
        {viewMode === 'DEFANGED' && (
          <div className="space-y-3 font-sans text-slate-300 leading-relaxed whitespace-pre-wrap">
            <div className="p-2 rounded bg-cyan-950/30 border border-cyan-500/20 text-[11px] font-mono text-cyan-400 flex items-center gap-2 mb-2">
              <Shield className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>Zero-Execution Sandbox: All scripts stripped, links neutralized (hxxp://) and click triggers locked.</span>
            </div>
            {bodyPlain}
          </div>
        )}

        {viewMode === 'PLAIN' && (
          <pre className="text-slate-300 font-mono text-xs whitespace-pre-wrap leading-relaxed">
            {bodyPlain}
          </pre>
        )}

        {viewMode === 'HEADERS' && (
          <pre className="text-cyan-300/90 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
            {rawHeaders}
          </pre>
        )}
      </div>
    </div>
  );
};
