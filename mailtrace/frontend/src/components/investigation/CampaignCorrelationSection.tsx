import React from 'react';
import { Flame, Network, ArrowRight, ShieldAlert, Link2, Server, Globe } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { InvestigationCase } from '../../types/investigation';
import { safeStr } from '../../lib/utils';

interface CampaignCorrelationSectionProps {
  investigationCase: InvestigationCase;
}

export const CampaignCorrelationSection: React.FC<CampaignCorrelationSectionProps> = ({ investigationCase }) => {
  const { campaigns, selectAndInvestigate, setActiveTab } = useInvestigation();
  const caseId = safeStr(investigationCase.id || 'CASE-2026-0842');

  // Find matching campaign
  const matchedCampaign = campaigns.find(c =>
    c.timeline.some(t => t.associatedCaseId === caseId) ||
    c.id === 'CAMP-0042'
  ) || campaigns[0];

  const relatedCases = (matchedCampaign?.timeline || [])
    .filter(t => t.associatedCaseId && t.associatedCaseId !== caseId)
    .map(t => ({
      caseId: t.associatedCaseId!,
      reason: `Shares originating Tor relay node (185.220.101.42) and typosquatted login portal`,
      target: t.target,
      timestamp: t.timestamp
    }));

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Flame className="w-4 h-4 text-orange-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Multi-Case Campaign Linkage & Graph Correlation
          </h3>
        </div>
        <button
          onClick={() => setActiveTab('campaigns')}
          className="flex items-center gap-1 text-xs font-mono text-orange-400 hover:text-orange-300 transition-colors"
        >
          <span>Open Campaign Dashboard</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Campaign Cluster Card */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-orange-400 px-2 py-0.5 rounded bg-orange-950/80 border border-orange-800/60">
              {matchedCampaign.id}
            </span>
            <span className="text-sm font-bold text-slate-100 font-sans">{matchedCampaign.name}</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Cluster Confidence:</span>
            <span className="text-emerald-400 font-bold">{matchedCampaign.confidenceScore}%</span>
          </div>
        </div>

        <p className="text-xs text-slate-300 font-sans leading-relaxed">
          {matchedCampaign.theme}
        </p>

        {/* Shared Infrastructure Highlights */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-2 border-t border-slate-800/80 text-xs font-mono">
          <div className="p-2 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px]">Shared Domains</span>
            <span className="text-slate-200 truncate block">{matchedCampaign.sharedInfrastructure.domains.join(', ')}</span>
          </div>
          <div className="p-2 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px]">Shared IPs</span>
            <span className="text-slate-200 truncate block">{matchedCampaign.sharedInfrastructure.ips.join(', ')}</span>
          </div>
          <div className="p-2 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px]">Shared ASNs</span>
            <span className="text-slate-200 truncate block">{matchedCampaign.sharedInfrastructure.asns.join(', ')}</span>
          </div>
        </div>
      </div>

      {/* Related Cases Inverted Index */}
      <div className="space-y-2">
        <div className="text-xs font-mono font-bold text-slate-300">
          Correlated Cases in Cluster ({relatedCases.length} Linked Peers)
        </div>

        {relatedCases.length === 0 ? (
          <div className="p-3 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-400 text-center">
            Zero related cases currently indexed for this isolated incident.
          </div>
        ) : (
          <div className="space-y-2">
            {relatedCases.map((rc, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition-colors"
              >
                <div className="space-y-1 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400">{rc.caseId}</span>
                    <span className="text-slate-500">•</span>
                    <span className="text-slate-400">Target: {rc.target}</span>
                  </div>
                  <p className="text-slate-300 text-[11px]">
                    <strong className="text-slate-400">Why Related:</strong> {rc.reason}
                  </p>
                </div>

                <button
                  onClick={() => selectAndInvestigate(rc.caseId)}
                  className="self-start sm:self-center px-3 py-1.5 rounded bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 text-cyan-300 text-xs font-mono font-medium transition-colors shrink-0 flex items-center gap-1"
                >
                  <span>Investigate Peer</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
