import React from 'react';
import {
  LayoutDashboard,
  Inbox,
  UploadCloud,
  Crosshair,
  Network,
  Compass,
  Flame,
  Database,
  ShieldCheck,
  Sliders,
  Building2,
  Fingerprint,
  Award,
  FileText,
  Radio,
  Sparkles
} from 'lucide-react';
import { useInvestigation, ActiveTab } from '../../context/InvestigationContext';

export const Sidebar: React.FC = () => {
  const { activeTab, setActiveTab, activeCaseId, cases, campaigns } = useInvestigation();

  const primaryNavItems: { id: ActiveTab; label: string; icon: React.ComponentType<{ className?: string }>; badge?: string }[] = [
    { id: 'overview', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'mailbox', label: 'Security Mailbox', icon: Inbox, badge: `${cases.length}` },
    { id: 'investigation', label: 'Investigations', icon: Crosshair, badge: activeCaseId ? 'ACTIVE' : undefined },
    { id: 'campaigns', label: 'Threat Campaigns', icon: Flame, badge: `${campaigns.length}` },
    { id: 'intelligence', label: 'Threat Intelligence', icon: Database },
    { id: 'evidence', label: 'Evidence & Integrity', icon: Fingerprint },
    { id: 'reports', label: 'Forensic Reports', icon: FileText }
  ];

  return (
    <aside className="w-64 bg-cyber-darker border-r border-slate-800 flex flex-col flex-shrink-0 h-screen select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800/80 bg-cyber-panel/40">
        <div className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-glow-accent">
            <Radio className="w-5 h-5 animate-pulse text-cyan-400" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-500 ring-2 ring-cyber-darker animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h1 className="text-base font-bold font-mono tracking-wider text-slate-100">
                MAILTRACE
              </h1>
              <span className="text-[10px] px-1 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30 font-semibold">
                SOC
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
              <Sparkles className="w-2.5 h-2.5 text-amber-400" />
              <span>SIH26106 • Team EAGLE</span>
            </p>
          </div>
        </div>
      </div>

      {/* Quick Ingest Button */}
      <div className="px-3 pt-3">
        <button
          onClick={() => setActiveTab('mailbox')}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md bg-gradient-to-r from-cyan-500/20 to-blue-500/20 hover:from-cyan-500/30 hover:to-blue-500/30 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold transition-all shadow-sm group"
        >
          <UploadCloud className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
          <span>+ Ingest Suspicious .EML</span>
        </button>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-3 py-3 space-y-1.5 overflow-y-auto cyber-scrollbar">
        <div className="px-3 pb-1 text-[10px] font-mono font-semibold tracking-wider text-slate-500 uppercase">
          Threat Operations
        </div>
        {primaryNavItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-mono font-medium transition-all group ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 shadow-glow-accent'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                  }`}
                />
                <span className="truncate max-w-[130px] text-left">{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`px-1.5 py-0.2 text-[9px] font-mono rounded ${
                    isActive
                      ? 'bg-cyan-400 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 group-hover:text-slate-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Active Case Footer & Engine Status */}
      <div className="p-3 border-t border-slate-800 bg-cyber-panel/50 space-y-2">
        <div className="p-2 rounded border border-slate-800 bg-slate-900/80">
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>SELECTED CASE</span>
            <span className="text-threat-critical font-semibold">CRITICAL</span>
          </div>
          <div className="text-xs font-mono font-bold text-cyan-400 truncate mt-0.5">
            {activeCaseId}
          </div>
        </div>

        <div className="flex items-center justify-between px-1 text-[10px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>AI Forensics: ONLINE</span>
          </div>
          <span className="text-slate-400">v3.4.0</span>
        </div>
      </div>
    </aside>
  );
};
