import React from 'react';
import { ShieldAlert, ArrowRight, Clock, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { Badge } from '../common/Badge';

export const RecentIncidents: React.FC = () => {
  const { cases, selectAndInvestigate } = useInvestigation();

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Recent High-Priority Forensic Incidents
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">Showing {cases.length} Synthetic Cases</span>
      </div>

      <div className="mt-3 divide-y divide-slate-800/60">
        {cases.map(c => {
          const isCritical = c.verdict.severity === 'CRITICAL';
          const isHigh = c.verdict.severity === 'HIGH';
          const isBenign = c.verdict.severity === 'LOW' || c.verdict.primaryThreat === 'BENIGN';

          return (
            <div
              key={c.id}
              className="py-3 px-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/40 rounded transition-colors group"
            >
              <div className="flex items-start gap-3">
                <div
                  className={`mt-0.5 p-1.5 rounded ${
                    isCritical
                      ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                      : isHigh
                      ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30'
                      : isBenign
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                  }`}
                >
                  {isBenign ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                </div>

                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-cyan-400 group-hover:underline">
                      {c.id}
                    </span>
                    <Badge variant="severity" severity={c.verdict.severity}>
                      {c.verdict.severity}
                    </Badge>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      Score: {c.verdict.overallRiskScore}/100
                    </span>
                  </div>

                  <h4 className="text-xs font-medium text-slate-200 mt-1">{c.subject}</h4>

                  <div className="flex items-center gap-3 mt-1 text-[11px] font-mono text-slate-400">
                    <span>From: <span className="text-slate-300">{c.sender}</span></span>
                    <span>•</span>
                    <span>To: <span className="text-slate-300">{c.recipient}</span></span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 self-end sm:self-center">
                <div className="text-right hidden md:block">
                  <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1 justify-end">
                    <Clock className="w-3 h-3" />
                    <span>{new Date(c.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-400">{c.verdict.primaryThreat}</div>
                </div>

                <button
                  onClick={() => selectAndInvestigate(c.id)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 text-cyan-300 text-xs font-mono font-medium transition-all group-hover:border-cyan-400"
                >
                  <span>Investigate</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
