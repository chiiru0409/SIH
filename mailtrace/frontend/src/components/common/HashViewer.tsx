import React, { useState } from 'react';
import { Copy, Check, ShieldCheck } from 'lucide-react';

interface HashViewerProps {
  hash: string;
  algorithm?: string;
  truncateLength?: number;
  label?: string;
  verified?: boolean;
  className?: string;
}

export const HashViewer: React.FC<HashViewerProps> = ({
  hash,
  algorithm = 'SHA-256',
  truncateLength,
  label,
  verified = true,
  className = ''
}) => {
  const [copied, setCopied] = useState(false);

  const displayHash = truncateLength && hash.length > truncateLength
    ? `${hash.slice(0, truncateLength / 2)}...${hash.slice(-truncateLength / 2)}`
    : hash;

  const handleCopy = () => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`inline-flex flex-col gap-1 ${className}`}>
      {label && (
        <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
          <span>{label}</span>
          <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-cyan-400 border border-slate-700">
            {algorithm}
          </span>
          {verified && (
            <span className="inline-flex items-center gap-0.5 text-[10px] text-emerald-400">
              <ShieldCheck className="w-3 h-3" />
              <span>Verified</span>
            </span>
          )}
        </div>
      )}
      <div className="flex items-center gap-2 bg-cyber-dark/80 border border-cyber-slate px-2.5 py-1.5 rounded text-xs font-mono text-slate-300 group hover:border-cyan-500/40 transition-colors">
        <span className="text-cyan-400/90 select-all break-all">{displayHash}</span>
        <button
          onClick={handleCopy}
          title="Copy full hash to clipboard"
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition-colors ml-auto flex-shrink-0"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
    </div>
  );
};
