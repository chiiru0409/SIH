import React, { useState, useEffect } from 'react';
import { Search, Bell, Shield, Clock, ChevronDown, CheckCircle2 } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

export const Header: React.FC = () => {
  const {
    activeCaseId,
    setActiveCaseId,
    cases,
    searchQuery,
    setSearchQuery,
    setActiveTab
  } = useInvestigation();

  const [time, setTime] = useState<string>('');
  const [caseDropdownOpen, setCaseDropdownOpen] = useState<boolean>(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 bg-cyber-panel border-b border-slate-800 px-6 flex items-center justify-between flex-shrink-0 z-30">
      {/* Left: Quick Case Study Selector & Search */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <button
            onClick={() => setCaseDropdownOpen(!caseDropdownOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 text-xs font-mono text-slate-200 transition-colors"
          >
            <span className="text-slate-400">Case Study:</span>
            <span className="font-bold text-cyan-400">{activeCaseId}</span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {caseDropdownOpen && (
            <div className="absolute top-full mt-1.5 left-0 w-80 bg-cyber-darker border border-slate-700 rounded-lg shadow-2xl py-1.5 z-50 animate-in fade-in zoom-in-95">
              <div className="px-3 py-1 text-[10px] font-mono text-slate-400 uppercase tracking-wider border-b border-slate-800">
                Switch Investigation Target
              </div>
              {cases.map(c => (
                <button
                  key={c.id}
                  onClick={() => {
                    setActiveCaseId(c.id);
                    setCaseDropdownOpen(false);
                    setActiveTab('investigation');
                  }}
                  className={`w-full text-left px-3 py-2 text-xs font-mono flex items-center justify-between hover:bg-slate-800/80 transition-colors ${
                    c.id === activeCaseId ? 'bg-cyan-500/10 text-cyan-400' : 'text-slate-300'
                  }`}
                >
                  <div>
                    <div className="font-bold flex items-center gap-1.5">
                      <span>{c.id}</span>
                      <span
                        className={`text-[9px] px-1 rounded ${
                          c.verdict.severity === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-400'
                            : c.verdict.severity === 'HIGH'
                            ? 'bg-orange-500/20 text-orange-400'
                            : c.verdict.severity === 'LOW' || c.verdict.primaryThreat === 'BENIGN'
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : 'bg-yellow-500/20 text-yellow-400'
                        }`}
                      >
                        {c.verdict.severity}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate max-w-[220px]">
                      {c.subject}
                    </div>
                  </div>
                  {c.id === activeCaseId && (
                    <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Global Filter / Search */}
        <div className="relative w-72">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IOC, IP, domain, hash..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs font-mono bg-slate-900 border border-slate-700/80 rounded focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-200 placeholder-slate-400 outline-none"
          />
        </div>
      </div>

      {/* Right: SOC Status, UTC Clock, Analyst */}
      <div className="flex items-center gap-5">
        <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900/60 px-3 py-1 rounded border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{time || '2026-09-09 08:42:15 UTC'}</span>
        </div>

        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono font-medium">
          <Shield className="w-3.5 h-3.5" />
          <span>SIH SOC ACTIVE</span>
        </div>

        <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
          <button className="relative p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors">
            <Bell className="w-4 h-4" />
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-cyan-400" />
          </button>

          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-cyan-600/30 border border-cyan-400/50 flex items-center justify-center text-cyan-300 font-mono text-xs font-bold">
              E
            </div>
            <div className="hidden sm:block text-left font-mono">
              <div className="text-xs font-semibold text-slate-200">Team EAGLE</div>
              <div className="text-[10px] text-slate-400">SIH26106 Lead</div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
