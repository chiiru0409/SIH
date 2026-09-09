import React, { useState } from 'react';
import { Flame, Target, Users, Clock, Globe, ShieldAlert, ArrowRight, CheckCircle2, ChevronDown } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { CampaignCluster } from '../../types/campaign';
import { Badge } from '../common/Badge';

export const CampaignList: React.FC = () => {
  const { campaigns, selectAndInvestigate } = useInvestigation();
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignCluster>(campaigns[0]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-4 bg-cyber-panel border border-slate-800 rounded-lg flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-400" />
            <span>Correlated Attack Campaigns & Multi-Target Clusters</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Grouping cross-tenant threat emails by shared infrastructure, temporal bursts, and payload signatures
          </p>
        </div>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2.5 py-1 rounded border border-cyan-800 font-bold">
          {campaigns.length} Active Campaigns
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Campaign List (5 cols) */}
        <div className="lg:col-span-5 space-y-3">
          {campaigns.map(camp => {
            const isSelected = selectedCampaign.id === camp.id;

            return (
              <div
                key={camp.id}
                onClick={() => setSelectedCampaign(camp)}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-cyber-panel border-orange-500/50 shadow-glow-high'
                    : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-orange-400">{camp.id}</span>
                    <Badge variant="severity" severity={camp.severity} size="xs">
                      {camp.severity}
                    </Badge>
                  </div>
                  <span className="text-xs font-mono font-bold text-slate-300">
                    {camp.totalEmails} Ingested
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-slate-100 mt-1.5">{camp.name}</h3>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2">{camp.theme}</p>

                <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400 border-t border-slate-800/80 pt-2">
                  <span>Confidence: <strong className="text-cyan-400">{camp.confidenceScore}%</strong></span>
                  <span>Status: <strong className="text-orange-400">{camp.status}</strong></span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Campaign Detail Deep-Dive (7 cols) */}
        <div className="lg:col-span-7 p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-5">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800/80">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-orange-400">{selectedCampaign.id}</span>
                <span className="text-xs font-mono text-slate-400">•</span>
                <span className="text-xs font-mono text-slate-200 font-semibold">{selectedCampaign.name}</span>
              </div>
              <p className="text-xs text-slate-300 mt-1 font-sans">{selectedCampaign.theme}</p>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30 font-bold">
              {selectedCampaign.status}
            </span>
          </div>

          {/* Key Metrics */}
          <div className="grid grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Total Ingested</span>
              <span className="text-lg font-bold text-slate-100">{selectedCampaign.totalEmails} Emails</span>
            </div>
            <div className="p-3 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Targeted VIPs</span>
              <span className="text-lg font-bold text-cyan-400">{selectedCampaign.targetedRecipients} Users</span>
            </div>
            <div className="p-3 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400 text-[10px] block">AI Confidence</span>
              <span className="text-lg font-bold text-emerald-400">{selectedCampaign.confidenceScore}%</span>
            </div>
          </div>

          {/* Shared Infrastructure */}
          <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
            <div className="text-cyan-400 font-bold uppercase text-[11px]">
              Shared Threat Infrastructure
            </div>
            <div className="space-y-1 text-slate-300">
              <div>
                <strong className="text-slate-400">Domains:</strong> {selectedCampaign.sharedInfrastructure.domains.join(', ')}
              </div>
              <div>
                <strong className="text-slate-400">IPs:</strong> {selectedCampaign.sharedInfrastructure.ips.join(', ')}
              </div>
              <div>
                <strong className="text-slate-400">ASNs:</strong> {selectedCampaign.sharedInfrastructure.asns.join(', ')}
              </div>
            </div>
          </div>

          {/* Correlation Reasons */}
          <div className="space-y-2">
            <div className="text-xs font-mono font-bold text-slate-200">
              Multi-Point Correlation Rationale
            </div>
            <div className="space-y-2">
              {selectedCampaign.correlationReasons.map((reason, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-900 border border-slate-800 text-xs font-mono flex items-start justify-between gap-3">
                  <div>
                    <span className="font-bold text-slate-200 block">{reason.factor}</span>
                    <p className="text-slate-400 text-[11px] mt-0.5">{reason.description}</p>
                  </div>
                  <span className="text-cyan-400 font-bold whitespace-nowrap">+{reason.weight}%</span>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Timeline */}
          <div className="space-y-2">
            <div className="text-xs font-mono font-bold text-slate-200">
              Attack Progression Timeline
            </div>
            <div className="space-y-2">
              {selectedCampaign.timeline.map((event, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-900 border border-slate-800 text-xs font-mono flex items-center justify-between gap-3">
                  <div>
                    <div className="text-slate-300 font-medium">{event.event}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      Target: {event.target} • {new Date(event.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                  {event.associatedCaseId && (
                    <button
                      onClick={() => selectAndInvestigate(event.associatedCaseId)}
                      className="px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 text-[11px] font-bold"
                    >
                      {event.associatedCaseId}
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
