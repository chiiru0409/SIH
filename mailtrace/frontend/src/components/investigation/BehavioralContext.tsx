import React from 'react';
import { History, AlertTriangle, Users } from 'lucide-react';
import { BehavioralContext as BehavioralContextType } from '../../types/investigation';

interface BehavioralContextProps {
  context?: Partial<BehavioralContextType>;
}

export const BehavioralContext: React.FC<BehavioralContextProps> = ({ context = {} }) => {
  const c = context || {};
  const isFirstTime = c.isFirstTimeSender ?? c.firstTimeSender ?? true;
  const historyCount = c.historicalEmailCount ?? c.previousCommunicationCount ?? 0;
  const similarityScore = c.displayNameSimilarityScore ?? 0;
  const familiarity = c.senderFamiliarity || (isFirstTime ? 'NONE' : 'MEDIUM');

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Sender Behavioral Profile & Historical Baseline
          </h3>
        </div>
        <span
          className={`text-xs font-mono px-2 py-0.5 rounded font-bold ${
            isFirstTime
              ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
          }`}
        >
          {isFirstTime ? 'FIRST TIME SENDER TO TENANT' : 'KNOWN SENDER'}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Historical Volume */}
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400">
            <History className="w-3.5 h-3.5 text-cyan-400" />
            <span>Historical Volume</span>
          </div>
          <div className="text-base font-bold text-slate-100">
            {historyCount} Prior Emails
          </div>
          <div className="text-[11px] text-slate-400">
            Baseline Window: Last 180 Days
          </div>
        </div>

        {/* Executive Impersonation / Similarity */}
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>VIP / Executive Similarity</span>
          </div>
          <div
            className={`text-base font-bold ${
              similarityScore > 70
                ? 'text-red-400'
                : 'text-emerald-400'
            }`}
          >
            {similarityScore ? `${similarityScore}% Match` : '0% Match'}
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {similarityScore > 70 ? 'High Impersonation Risk' : 'Standard Baseline Match'}
          </div>
        </div>

        {/* Sender Familiarity */}
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400">
            <Users className="w-3.5 h-3.5 text-cyan-400" />
            <span>Familiarity Rating</span>
          </div>
          <div className="text-base font-bold text-cyan-300">
            {familiarity}
          </div>
          <div className="text-[11px] text-slate-400">
            Organization Graph Anomaly: {isFirstTime ? 'High' : 'Low'}
          </div>
        </div>
      </div>
    </div>
  );
};
