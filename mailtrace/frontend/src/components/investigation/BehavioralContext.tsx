import React from 'react';
import { UserCheck, AlertTriangle, History, ShieldAlert, Users } from 'lucide-react';
import { BehavioralContext as BehavioralContextType } from '../../types/investigation';

interface BehavioralContextProps {
  context: BehavioralContextType;
}

export const BehavioralContext: React.FC<BehavioralContextProps> = ({ context }) => {
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
            context.isFirstTimeSender
              ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
          }`}
        >
          {context.isFirstTimeSender ? 'FIRST TIME SENDER TO TENANT' : 'KNOWN SENDER'}
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
            {context.historicalEmailCount} Prior Emails
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
              context.displayNameSimilarityScore && context.displayNameSimilarityScore > 70
                ? 'text-red-400'
                : 'text-emerald-400'
            }`}
          >
            {context.displayNameSimilarityScore ? `${context.displayNameSimilarityScore}% Match` : '0% Match'}
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {context.impersonatedVip || 'No executive VIP impersonated'}
          </div>
        </div>

        {/* Relationship Tier */}
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400">
            <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span>Relationship Trust Tier</span>
          </div>
          <div className="text-base font-bold text-slate-100">
            {context.relationshipTier}
          </div>
          <div className="text-[11px] text-slate-400">
            Org-Wide Affinity Score
          </div>
        </div>
      </div>
    </div>
  );
};
