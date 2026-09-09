import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Search, 
  Compass, 
  Network, 
  Layers, 
  FolderLock, 
  Upload, 
  CheckCircle2, 
  AlertCircle,
  Cloud,
  Lock,
  Award
} from 'lucide-react';
import { Button } from '../ui/Button';

import type { DatabaseStatus } from '../../types/api';

export interface HeaderProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
  apiConnected: boolean;
  dbStatus?: DatabaseStatus | null;
  activeCaseId: string | null;
  onResetCase: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  apiConnected,
  dbStatus,
  activeCaseId,
  onResetCase,
}) => {
  const navItems = [
    { id: 'overview', label: 'Analysis & Ingest', icon: <Upload className="w-3.5 h-3.5" /> },
    { id: 'forensics', label: 'Forensics', icon: <Search className="w-3.5 h-3.5" /> },
    { id: 'tenants', label: 'Cloud Tenants', icon: <Cloud className="w-3.5 h-3.5" /> },
    { id: 'quarantine', label: 'Quarantine & Policy', icon: <Lock className="w-3.5 h-3.5" /> },
    { id: 'compliance', label: 'Compliance', icon: <Award className="w-3.5 h-3.5" /> },
    { id: 'infrastructure', label: 'Infrastructure & Geo', icon: <Compass className="w-3.5 h-3.5" /> },
    { id: 'graph', label: 'Investigation Graph', icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'cases', label: 'Case Repository', icon: <FolderLock className="w-3.5 h-3.5" /> },
  ];

  const isDbReady = dbStatus ? dbStatus.connected && dbStatus.status === 'ready' : apiConnected;
  const dbLabel = dbStatus
    ? dbStatus.provider === 'neon'
      ? 'NEON DB'
      : dbStatus.engine === 'postgresql'
      ? 'POSTGRES'
      : 'SQLITE'
    : 'DB';

  return (
    <header className="sticky top-0 z-40 w-full border-b border-cyber-border/80 bg-cyber-bg/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Platform Title */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => onTabChange('overview')}>
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_15px_rgba(0,240,255,0.25)]">
              <ShieldAlert className="w-5 h-5 text-cyber-cyan animate-pulse-subtle" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-base font-extrabold tracking-widest text-slate-100">
                  MAIL<span className="text-cyber-cyan">TRACE</span>
                </span>
                <span className="px-1.5 py-0.2 rounded bg-cyan-950/60 border border-cyan-500/30 text-[9px] font-mono font-semibold text-cyan-400">
                  SOC-FORENSICS v1.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono tracking-tight">
                AI Threat Detection & Forensic Intelligence
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden lg:flex items-center space-x-1">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-md font-mono text-xs uppercase tracking-wider transition-all duration-150 ${
                    isActive
                      ? 'bg-cyber-card text-cyber-cyan border border-cyber-cyan/40 shadow-[0_0_10px_rgba(0,240,255,0.15)] font-bold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                  }`}
                >
                  <span className={isActive ? 'text-cyber-cyan' : 'text-slate-500'}>{item.icon}</span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Status Indicators & Quick Actions */}
          <div className="flex items-center space-x-3">
            {/* Backend Health Status */}
            <div
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full border text-[11px] font-mono ${
                apiConnected
                  ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
                  : 'bg-red-950/40 border-red-500/30 text-red-400 animate-pulse'
              }`}
              title={apiConnected ? 'Connected to MailTrace API' : 'Backend API is unreachable'}
            >
              <span className={`w-2 h-2 rounded-full ${apiConnected ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 'bg-red-500'}`} />
              <span className="hidden sm:inline">{apiConnected ? 'API ONLINE' : 'API OFFLINE'}</span>
            </div>

            {/* Database Readiness Status */}
            <div
              className={`hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded-full border text-[11px] font-mono ${
                isDbReady
                  ? 'bg-cyan-950/40 border-cyan-500/30 text-cyan-400'
                  : 'bg-amber-950/40 border-amber-500/30 text-amber-400 animate-pulse'
              }`}
              title={isDbReady ? `Database connected (${dbLabel})` : 'Database is unreachable or initializing'}
            >
              <span className={`w-2 h-2 rounded-full ${isDbReady ? 'bg-cyan-400 shadow-[0_0_8px_rgba(0,240,255,0.8)]' : 'bg-amber-500'}`} />
              <span>{isDbReady ? `${dbLabel} READY` : 'DB OFFLINE'}</span>
            </div>

            {/* Active Case Context */}
            {activeCaseId && (
              <div className="hidden sm:flex items-center space-x-2 pl-2 border-l border-cyber-border">
                <span className="text-[11px] font-mono text-slate-400">CASE:</span>
                <span className="font-mono text-xs text-cyan-300 font-semibold bg-cyber-surface px-2 py-0.5 rounded border border-cyber-border">
                  {activeCaseId.slice(0, 8)}…
                </span>
                <button
                  onClick={onResetCase}
                  className="text-xs text-slate-400 hover:text-red-400 font-mono transition"
                  title="Unload current case & analyze new email"
                >
                  [NEW]
                </button>
              </div>
            )}

            {/* New Analysis Button */}
            <Button
              variant="primary"
              size="sm"
              icon={<Upload className="w-3.5 h-3.5" />}
              onClick={() => {
                onResetCase();
                onTabChange('overview');
              }}
            >
              Analyze
            </Button>
          </div>

        </div>
      </div>

      {/* Mobile Navigation Sub-bar */}
      <div className="lg:hidden flex items-center space-x-1 px-4 py-2 overflow-x-auto border-t border-cyber-border/40 bg-cyber-surface/60">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`flex items-center space-x-1 px-2.5 py-1 rounded text-[11px] font-mono whitespace-nowrap ${
                isActive
                  ? 'bg-cyber-card text-cyber-cyan border border-cyber-cyan/40 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
