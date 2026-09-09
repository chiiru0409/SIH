import React from 'react';
import { ExplainableFinding } from '../../types/investigation';
import { ShieldAlert, AlertTriangle, CheckCircle, Info, Sparkles, Eye } from 'lucide-react';
import { Badge } from '../common/Badge';

interface WhySuspiciousProps {
  findings: ExplainableFinding[];
}

export const WhySuspicious: React.FC<WhySuspiciousProps> = ({ findings }) => {
  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Explainable Forensic Findings (Why Is This Email Suspicious?)
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          {findings.length} Evidence Vectors
        </span>
      </div>

      <div className="space-y-3">
        {findings.map(item => (
          <div
            key={item.id}
            className="p-4 rounded-lg bg-slate-900/90 border border-slate-800/90 hover:border-slate-700 transition-colors space-y-2"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono font-bold text-slate-200">
                  {item.title}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {item.category || item.type}
                </span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold ${
                    (item.severity === 'CRITICAL' || item.level === 'CRITICAL')
                      ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                      : (item.severity === 'HIGH' || item.level === 'HIGH')
                      ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                      : (item.severity === 'LOW' || item.severity === 'INFO')
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                  }`}
                >
                  {item.severity}
                </span>
              </div>

              <div className="flex items-center gap-1 text-xs font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/50">
                <span>Score Impact:</span>
                <span>+{item.scoreContribution || item.weight || 10} pts</span>
              </div>
            </div>

            {/* Observed Fact Box */}
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono flex items-start gap-2.5">
              <Eye className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="text-slate-400 text-[10px] font-bold uppercase tracking-wider block mb-0.5">
                  Observed Forensic Fact
                </span>
                <p className="text-slate-300">{item.observedText || item.observedEvidence}</p>
              </div>
            </div>

            {/* AI Inference / Threat Context Box */}
            <div className="p-2.5 rounded bg-cyan-950/20 border border-cyan-500/20 text-xs font-mono flex items-start gap-2.5">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="text-cyan-400 text-[10px] font-bold uppercase tracking-wider block mb-0.5">
                  AI Forensic Inference & Threat Context
                </span>
                <p className="text-slate-300">{item.inferenceText || item.aiInference}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
