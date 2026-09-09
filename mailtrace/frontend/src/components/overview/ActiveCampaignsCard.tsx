import React from 'react';
import { Flame, Target, ArrowRight, ShieldCheck } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

export const ActiveCampaignsCard: React.FC = () => {
  const { campaigns, setActiveTab } = useInvestigation();

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Flame className="w-4 h-4 text-orange-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Active Multi-Target Threat Campaigns
          </h3>
        </div>
        <button
          onClick={() => setActiveTab('campaigns')}
          className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
        >
          <span>View All</span>
          <ArrowRight className="w-3 h-3" />
        </button>
      </div>

      <div className="space-y-3 mt-3">
        {campaigns.map(camp => (
          <div
            key={camp.id}
            className="p-3 rounded bg-slate-900/90 border border-slate-800 hover:border-orange-500/40 transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-orange-400">{camp.id}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-orange-500/10 text-orange-300 border border-orange-500/30">
                  {camp.status}
                </span>
              </div>
              <span className="text-xs font-mono font-bold text-slate-300">
                {camp.totalEmails} Ingested
              </span>
            </div>

            <h4 className="text-xs font-medium text-slate-200 mt-1">{camp.theme}</h4>

            <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-slate-400 border-t border-slate-800/60 pt-2">
              <span>Targets: {camp.targetedDepartments.join(', ')}</span>
              <span className="text-cyan-400">Confidence: {camp.confidenceScore}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
