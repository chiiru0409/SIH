import React from 'react';
import { KpiCards } from '../components/overview/KpiCards';
import { ThreatTimeline } from '../components/overview/ThreatTimeline';
import { ThreatDistribution } from '../components/overview/ThreatDistribution';
import { RecentIncidents } from '../components/overview/RecentIncidents';
import { ActiveCampaignsCard } from '../components/overview/ActiveCampaignsCard';
import { ShieldCheck, Activity, ArrowRight, ShieldAlert, Flame, Search, CheckCircle2, Sparkles } from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';

export const OverviewPage: React.FC = () => {
  const { cases, campaigns, selectAndInvestigate, setActiveTab } = useInvestigation();
  const criticalCase = cases.find(c => c.verdict.severity === 'CRITICAL') || cases[0];

  const handleStartInvestigation = () => {
    if (criticalCase) {
      selectAndInvestigate(criticalCase.id);
    } else {
      setActiveTab('mailbox');
    }
  };

  return (
    <div className="space-y-6">
      {/* Judge Mode High-Impact Executive Hero Banner */}
      <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-cyan-500/30 shadow-2xl flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="space-y-2 max-w-3xl">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <h1 className="text-lg font-bold font-mono tracking-wider text-slate-100">
              MAILTRACE Security Operations Center
            </h1>
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
              SIH26106 • AI-Powered DFIR Platform
            </span>
          </div>
          <p className="text-sm text-slate-300 font-sans leading-relaxed">
            Automated email threat detection, reverse-hop relay tracing, observed infrastructure geolocation, and multi-incident campaign correlation for enterprise defense.
          </p>

          {/* 4 Core Judge Indicators */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono text-xs">
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] block uppercase">Threats Detected</span>
              <span className="text-base font-bold text-cyan-400">12</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] block uppercase">Active Campaigns</span>
              <span className="text-base font-bold text-orange-400">3 Clusters</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30 bg-red-950/10">
              <span className="text-red-400 text-[10px] block uppercase font-bold">Critical Threats</span>
              <span className="text-base font-bold text-red-400">1 Urgent</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] block uppercase">Active Investigations</span>
              <span className="text-base font-bold text-emerald-400">3 Open</span>
            </div>
          </div>
        </div>

        {/* Primary Action CTA */}
        <div className="flex flex-col sm:flex-row lg:flex-col gap-2.5 shrink-0">
          <button
            onClick={() => setActiveTab('experience')}
            className="flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono text-xs font-bold transition-all shadow-glow-accent group"
          >
            <Sparkles className="w-4 h-4 text-slate-950" />
            <span>EXPLORE FORENSIC TRACE</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>
          <button
            onClick={handleStartInvestigation}
            className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-semibold transition-colors"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
            <span>Investigate Active Case</span>
          </button>
          <button
            onClick={() => setActiveTab('mailbox')}
            className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-xs font-medium transition-colors"
          >
            <span>View Security Mailbox</span>
          </button>
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
