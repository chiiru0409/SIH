import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, RotateCcw, Ban, Trash2, Clock, AlertCircle } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { ResponseActionLog, ResponseActionType } from '../../types/response';

export const ResponseQueue: React.FC = () => {
  const { responses, addResponseAction } = useInvestigation();
  const [filterAction, setFilterAction] = useState<string>('ALL');

  const filteredResponses = filterAction === 'ALL'
    ? responses
    : responses.filter(r => r.actionType === filterAction);

  const getActionBadge = (type: ResponseActionType) => {
    switch (type) {
      case 'QUARANTINE':
        return 'bg-red-500/20 text-red-400 border border-red-500/40';
      case 'BLOCK_DOMAIN':
        return 'bg-orange-500/20 text-orange-400 border border-orange-500/40';
      case 'BLOCK_IP':
        return 'bg-purple-500/20 text-purple-400 border border-purple-500/40';
      case 'ADD_BANNER':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      case 'RELEASE':
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700';
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-4 bg-cyber-panel border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Automated Quarantine Vault & SOC Response Audit Trail</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time policy enforcement actions, domain blocks, and immutable containment audit logs
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Filter Action:</span>
          {['ALL', 'QUARANTINE', 'BLOCK_DOMAIN', 'BLOCK_IP', 'ADD_BANNER'].map(a => (
            <button
              key={a}
              onClick={() => setFilterAction(a)}
              className={`px-2 py-0.5 rounded ${
                filterAction === a
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                  : 'bg-slate-900 text-slate-400 border border-slate-800'
              }`}
            >
              {a}
            </button>
          ))}
        </div>
      </div>

      {/* Response Audit Log Table */}
      <div className="bg-cyber-panel border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto cyber-scrollbar">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-cyber-slate/40 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Action ID & Type</th>
                <th className="py-3 px-4">Case & Target</th>
                <th className="py-3 px-4">Actor / Engine</th>
                <th className="py-3 px-4">Policy Rationale</th>
                <th className="py-3 px-4">Status & Impact</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredResponses.map(res => (
                <tr key={res.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="font-bold text-slate-300">{res.id}</div>
                    <span className={`inline-block mt-1 text-[10px] px-1.5 py-0.2 rounded font-bold ${getActionBadge(res.actionType)}`}>
                      {res.actionType}
                    </span>
                  </td>

                  <td className="py-3.5 px-4">
                    <div className="font-bold text-cyan-400">{res.caseId}</div>
                    <div className="text-[11px] text-slate-300 truncate max-w-xs mt-0.5">
                      {res.target}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 whitespace-nowrap text-slate-300">
                    {res.executedBy}
                  </td>

                  <td className="py-3.5 px-4">
                    <div className="text-slate-300 max-w-sm truncate">{res.reason}</div>
                  </td>

                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <span className="text-emerald-400 font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{res.status}</span>
                      </span>
                      <span className="text-[10px] text-slate-400">
                        (Impact: {res.impactScore}/100)
                      </span>
                    </div>
                  </td>

                  <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-xs">
                    {new Date(res.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
