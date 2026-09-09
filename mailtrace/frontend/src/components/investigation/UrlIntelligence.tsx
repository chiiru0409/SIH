import React from 'react';
import { ExtractedUrl } from '../../types/email';
import { Link2, AlertTriangle, ShieldCheck, ExternalLink, Globe, Lock } from 'lucide-react';
import { Badge } from '../common/Badge';

interface UrlIntelligenceProps {
  urls: ExtractedUrl[];
}

export const UrlIntelligence: React.FC<UrlIntelligenceProps> = ({ urls }) => {
  if (urls.length === 0) {
    return (
      <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 text-xs font-mono text-slate-400 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Link2 className="w-4 h-4 text-slate-400" />
          <span>No external hyperlinks detected in this email message.</span>
        </div>
        <span className="text-emerald-400 font-bold">CLEAN</span>
      </div>
    );
  }

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Link2 className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            URL Intelligence & Deep Domain Forensics
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Extracted Links: <span className="text-cyan-400 font-bold">{urls.length}</span>
        </span>
      </div>

      <div className="space-y-3">
        {urls.map((u, idx) => {
          const isHighRisk = u.riskScore >= 70;

          return (
            <div
              key={idx}
              className={`p-4 rounded-lg border space-y-3 ${
                isHighRisk
                  ? 'bg-red-950/20 border-red-500/40 shadow-glow-critical'
                  : 'bg-slate-900 border-slate-800'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-bold text-cyan-300 break-all">
                    {u.defangedUrl}
                  </span>
                  <Badge
                    variant="severity"
                    severity={isHighRisk ? 'CRITICAL' : 'BENIGN'}
                    size="xs"
                  >
                    Risk: {u.riskScore}/100
                  </Badge>
                </div>
              </div>

              {/* URL Properties Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-2 border-t border-slate-800/80 text-xs font-mono">
                <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Domain Host</span>
                  <span className="text-slate-200 font-semibold">{u.domain}</span>
                </div>

                <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Domain Age</span>
                  <span
                    className={
                      u.domainAgeDays && u.domainAgeDays < 30
                        ? 'text-red-400 font-bold'
                        : 'text-slate-200'
                    }
                  >
                    {u.domainAgeDays ? `${u.domainAgeDays} days (New)` : 'Established'}
                  </span>
                </div>

                <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Punycode / Typosquat</span>
                  <span
                    className={
                      u.isPunycode || u.isLookalike
                        ? 'text-red-400 font-bold'
                        : 'text-emerald-400'
                    }
                  >
                    {u.isLookalike ? 'DETECTED (Spoof)' : 'NONE'}
                  </span>
                </div>

                <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Destination IP</span>
                  <span className="text-cyan-400 font-mono">
                    {u.resolvedIp || 'Unresolved'}
                  </span>
                </div>
              </div>

              {/* Redirect chain if present */}
              {u.redirectChain && u.redirectChain.length > 1 && (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono">
                  <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">
                    Redirect Chain Path
                  </span>
                  <div className="space-y-1">
                    {u.redirectChain.map((step, sIdx) => (
                      <div key={sIdx} className="text-slate-300 flex items-center gap-2">
                        <span className="text-cyan-400">{sIdx + 1}.</span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
