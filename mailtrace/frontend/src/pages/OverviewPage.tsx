import React from 'react';
import { KpiCards } from '../components/overview/KpiCards';
import { ThreatTimeline } from '../components/overview/ThreatTimeline';
import { ThreatDistribution } from '../components/overview/ThreatDistribution';
import { RecentIncidents } from '../components/overview/RecentIncidents';
import { ActiveCampaignsCard } from '../components/overview/ActiveCampaignsCard';
import { ShieldCheck, Activity } from 'lucide-react';

export const OverviewPage: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* SOC Operations Header */}
      <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <h2 className="text-base font-bold font-mono tracking-wider text-slate-100">
              MAILTRACE Security Operations Center
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
              SIH26106 SOC ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans max-w-3xl">
            Continuous email threat detection, reverse-hop routing forensics, passive infrastructure geolocation, and multi-case campaign correlation for institutional defense.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900/80 px-3 py-2 rounded border border-slate-800 shrink-0">
          <Activity className="w-4 h-4 text-cyan-400" />
          <span>Engine Status: <strong className="text-emerald-400">NOMINAL (100% ONLINE)</strong></span>
        </div>
      </div>

      {/* Top Metrics Row */}
      <KpiCards />

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <ThreatTimeline />
        </div>
        <div className="lg:col-span-4">
          <ThreatDistribution />
        </div>
      </div>

      {/* Recent Incidents & Campaigns Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <RecentIncidents />
        </div>
        <div className="lg:col-span-4">
          <ActiveCampaignsCard />
        </div>
      </div>
    </div>
  );
};
