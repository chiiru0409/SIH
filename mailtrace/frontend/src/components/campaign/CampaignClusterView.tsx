import React from 'react';
import { Layers, Network, ArrowRight, ShieldAlert, Sparkles, Hash, Link as LinkIcon, Server, Globe } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { defangUrl, defangIp } from '../../lib/sanitize';
import type { CampaignCluster, CaseCorrelation } from '../../types/api';

export interface CampaignClusterViewProps {
  campaigns?: CampaignCluster[];
  correlations?: CaseCorrelation[];
  onSelectCase?: (caseId: string) => void;
  className?: string;
}

export const CampaignClusterView: React.FC<CampaignClusterViewProps> = ({
  campaigns = [],
  correlations = [],
  onSelectCase,
  className,
}) => {
  if (!campaigns || campaigns.length === 0) {
    return (
      <Card
        title="CAMPAIGN CLUSTER CORRELATION"
        subtitle="Cross-case infrastructure & threat pattern aggregation"
        icon={<Layers className="w-4 h-4 text-cyber-cyan" />}
        className={className}
      >
        <div className="py-12 text-center text-xs font-mono text-slate-500 space-y-2">
          <Layers className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="font-bold text-slate-300">NO CORRELATED CAMPAIGNS DETECTED</div>
          <p className="text-[11px] text-slate-500 max-w-md mx-auto">
            Ingested email cases do not share overlapping public IPs, registrable domains, or URL hashes above the correlation threshold.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <Card
      title="CORRELATED CAMPAIGN CLUSTERS"
      subtitle={`Autonomous identification of multi-case infrastructure overlaps (${campaigns.length} clusters)`}
      icon={<Layers className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-6">
        
        {/* Attribution Safeguard Notice */}
        <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-xs font-mono text-cyan-300">
          <strong>SAFEGUARD NOTICE: </strong>
          Clusters identify technical infrastructure commonalities across distinct email cases. They are classified as "Potentially Related Campaigns" based on observable network indicators.
        </div>

        {/* Campaign Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {campaigns.map((camp, idx) => {
            const strengthPct = Math.round(camp.correlation_strength || 80);

            return (
              <div
                key={camp.campaign_id || idx}
                className="p-5 rounded-xl bg-cyber-surface border border-cyber-border hover:border-cyber-cyan/40 transition-all space-y-4 shadow-lg"
              >
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-slate-100">
                        {camp.campaign_id}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-bold">
                        POTENTIAL CAMPAIGN
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400 block">
                      {camp.case_count} Correlated Cases Identified
                    </span>
                  </div>

                  <div className="text-right">
                    <span className="text-lg font-extrabold font-mono text-cyber-cyan">
                      {strengthPct}%
                    </span>
                    <span className="text-[9px] font-mono text-slate-500 block uppercase">
                      Correlation
                    </span>
                  </div>
                </div>

                {/* Explanation */}
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {camp.explanation || 'Cases within this cluster share common authoritative nameservers, sender envelope addresses, or URL hosting structures.'}
                </p>

                {/* Shared Indicators */}
                {camp.shared_indicators && camp.shared_indicators.length > 0 && (
                  <div className="space-y-1.5 pt-2 border-t border-cyber-border/40">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                      SHARED TECHNICAL INDICATORS
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {camp.shared_indicators.map((ind, i) => {
                        const val = ind.value || ind.indicator || String(ind);
                        const type = ind.type || 'indicator';

                        return (
                          <span
                            key={`ind-${i}`}
                            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-900 border border-cyber-border text-slate-300 font-mono text-[10px]"
                          >
                            <span className="text-slate-500 uppercase">{type}:</span>
                            <span className="text-cyan-300 font-bold">{val}</span>
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Linked Cases List */}
                {camp.case_ids && camp.case_ids.length > 0 && (
                  <div className="space-y-1.5 pt-2 border-t border-cyber-border/40">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                      ASSOCIATED CASES ({camp.case_ids.length})
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {camp.case_ids.map((cid) => (
                        <button
                          key={cid}
                          onClick={() => onSelectCase && onSelectCase(cid)}
                          className="px-2 py-1 rounded bg-cyber-bg hover:bg-slate-800 border border-cyber-border hover:border-cyber-cyan/50 text-slate-300 hover:text-white font-mono text-[10px] transition flex items-center space-x-1"
                        >
                          <Hash className="w-3 h-3 text-slate-500" />
                          <span>{cid.slice(0, 8)}…</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

              </div>
            );
          })}
        </div>

      </div>
    </Card>
  );
};
