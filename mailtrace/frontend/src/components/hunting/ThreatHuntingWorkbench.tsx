import React, { useState, useEffect } from 'react';
import {
  Crosshair,
  Search,
  ShieldAlert,
  Layers,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  Globe,
  Database,
  FileSpreadsheet,
  CheckCircle,
  HelpCircle,
  TrendingUp,
  Cpu,
} from 'lucide-react';
import { executeThreatHunt } from '../../lib/api';
import type { ThreatHuntResponse, ThreatHuntResultItem } from '../../types/api';

interface ThreatHuntingWorkbenchProps {
  onSelectCase?: (caseId: string) => void;
}

const HYPOTHESES = [
  {
    id: 'ALL',
    label: 'All Hypotheses (Comprehensive)',
    icon: Layers,
    badge: 'Hunt Suite',
    desc: 'Evaluate all empirical threat hunting hypotheses across all ingested email telemetry.',
  },
  {
    id: 'SHARED_INFRASTRUCTURE',
    label: 'Shared Infrastructure Reuse',
    icon: Globe,
    badge: 'T1583.001',
    desc: 'Identify malicious campaigns sharing public sending IPs, ASNs, or bulletproof host domains.',
  },
  {
    id: 'EXECUTIVE_SPOOFING',
    label: 'VIP / Executive Spoofing',
    icon: ShieldAlert,
    badge: 'T1036.005',
    desc: 'Detect high-risk display name impersonation of executives originating from external freemail.',
  },
  {
    id: 'SAAS_CLOUD_ABUSE',
    label: 'Living off Legitimate Services (LOLServices)',
    icon: Cpu,
    badge: 'T1566.003',
    desc: 'Uncover phishing lures and payload redirectors hosted on Google Forms, Canva, Notion, SharePoint.',
  },
  {
    id: 'CREDENTIAL_CAMPAIGNS',
    label: 'Credential Harvesting Campaigns',
    icon: Crosshair,
    badge: 'T1056.001',
    desc: 'Correlate credential solicitation lures combined with urgent psychological pressure.',
  },
  {
    id: 'DMARC_BYPASS_ATTEMPTS',
    label: 'DMARC & Authentication Failures',
    icon: AlertTriangle,
    badge: 'T1534',
    desc: 'Pinpoint external unauthenticated emails attempting wire transfers or sensitive account changes.',
  },
];

export const ThreatHuntingWorkbench: React.FC<ThreatHuntingWorkbenchProps> = ({ onSelectCase }) => {
  const [activeHypothesis, setActiveHypothesis] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [huntData, setHuntData] = useState<ThreatHuntResponse | null>(null);
  const [selectedResult, setSelectedResult] = useState<ThreatHuntResultItem | null>(null);

  const runHunt = async (hyp: string = activeHypothesis, query: string = searchQuery) => {
    setLoading(true);
    setError(null);
    try {
      const data = await executeThreatHunt(hyp, query);
      setHuntData(data);
      if (data.results && data.results.length > 0) {
        setSelectedResult(data.results[0]);
      } else {
        setSelectedResult(null);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to execute threat hunt query.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runHunt(activeHypothesis, searchQuery);
  }, [activeHypothesis]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runHunt(activeHypothesis, searchQuery);
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Methodology Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden shadow-xl">
        <div className="absolute -right-10 -top-10 w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded-lg">
                <Crosshair className="w-5 h-5" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Threat Hunting Workbench</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Huntpedia / SpecterOps Framework
              </span>
            </div>
            <p className="text-slate-400 text-sm max-w-2xl">
              Hypothesis-driven email threat hunting engine. Execute proactive queries, detect multi-signal indicator overlap, and pivot across sender infrastructure without alert dependency.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => runHunt(activeHypothesis, searchQuery)}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg border border-slate-700 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Re-run Hunt
            </button>
          </div>
        </div>
      </div>

      {/* Hypothesis Selector & Indicator Search Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Sidebar: Hypotheses */}
        <div className="lg:col-span-1 space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 px-1">
            Hunting Hypotheses
          </div>
          <div className="space-y-2">
            {HYPOTHESES.map((hyp) => {
              const Icon = hyp.icon;
              const isActive = activeHypothesis === hyp.id;
              return (
                <button
                  key={hyp.id}
                  onClick={() => {
                    setActiveHypothesis(hyp.id);
                  }}
                  className={`w-full text-left p-3 rounded-xl border transition flex flex-col gap-1.5 ${
                    isActive
                      ? 'bg-indigo-950/50 border-indigo-500/50 shadow-md shadow-indigo-950/30'
                      : 'bg-slate-900/60 hover:bg-slate-900 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-indigo-400' : 'text-slate-400'}`} />
                      <span className={`text-sm font-semibold ${isActive ? 'text-white' : 'text-slate-200'}`}>
                        {hyp.label}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-xs mt-1">
                    <span className="text-slate-500 line-clamp-1">{hyp.desc}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700 shrink-0 ml-2">
                      {hyp.badge}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Main Area: Search, Findings & Pivots */}
        <div className="lg:col-span-3 space-y-6">
          {/* Search / Indicator Pivot Input */}
          <form onSubmit={handleSearchSubmit} className="flex gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Pivot on indicator (IP: 185.220.101.5, Domain, Sender, or URL substring)..."
                className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-xl transition shadow-md shadow-indigo-600/20 disabled:opacity-50"
            >
              Pivot
            </button>
          </form>

          {/* Error Message */}
          {error && (
            <div className="p-4 bg-rose-950/40 border border-rose-800/50 rounded-xl text-rose-300 text-sm flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Hunt Metrics Bar */}
          {huntData && (
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
                <div className="text-xs text-slate-400 font-medium">Cases Evaluated</div>
                <div className="text-xl font-bold text-white mt-1">{huntData.total_cases_analyzed}</div>
              </div>
              <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
                <div className="text-xs text-slate-400 font-medium">Hypotheses Run</div>
                <div className="text-xl font-bold text-indigo-400 mt-1">{huntData.hypotheses_evaluated}</div>
              </div>
              <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
                <div className="text-xs text-slate-400 font-medium">Total Matches Detected</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {huntData.results.reduce((acc, r) => acc + r.total_matches, 0)}
                </div>
              </div>
            </div>
          )}

          {/* Results List / Details */}
          {huntData && huntData.results && huntData.results.length > 0 ? (
            <div className="space-y-4">
              {huntData.results.map((res) => (
                <div
                  key={res.hypothesis_id}
                  className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                    <div>
                      <div className="flex items-center gap-2.5">
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                          {res.hypothesis_id}
                        </span>
                        <h3 className="text-base font-semibold text-white">{res.title}</h3>
                        <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                          {res.mitre_technique}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">{res.description}</p>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">Matches:</span>
                      <span className="px-2.5 py-1 rounded-lg text-sm font-bold bg-slate-800 text-white border border-slate-700">
                        {res.total_matches}
                      </span>
                    </div>
                  </div>

                  {/* Rationale & Analytics */}
                  <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800/60 text-xs text-slate-300 space-y-1">
                    <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                      Detection Engineering Rationale:
                    </span>
                    <p>{res.rationale}</p>
                  </div>

                  {/* Matched Indicators */}
                  {res.matched_indicators && res.matched_indicators.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                        Correlated Indicators of Interest ({res.matched_indicators.length})
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {res.matched_indicators.map((ind, idx) => (
                          <div
                            key={idx}
                            className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800/80 rounded-lg border border-slate-700/70 text-xs font-mono text-slate-200"
                          >
                            <span className="text-indigo-400 uppercase font-semibold">{ind.type}:</span>
                            <span className="truncate max-w-[200px]">{ind.value}</span>
                            {ind.cases_affected && (
                              <span className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 text-[10px]">
                                {ind.cases_affected} cases
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Matched Cases Grid */}
                  {res.matched_cases && res.matched_cases.length > 0 && (
                    <div className="space-y-2">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        Matching Cases ({res.matched_cases.length})
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                        {res.matched_cases.map((mc) => (
                          <div
                            key={mc.case_id}
                            className="p-3 bg-slate-950/40 rounded-lg border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between gap-2"
                          >
                            <div>
                              <div className="flex items-center justify-between">
                                <span className="font-mono text-xs font-semibold text-indigo-400">
                                  {mc.filename || `Case ${mc.case_id.slice(0, 8)}`}
                                </span>
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                    mc.risk_label === 'CRITICAL'
                                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                      : mc.risk_label === 'HIGH'
                                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                      : 'bg-slate-800 text-slate-300'
                                  }`}
                                >
                                  {mc.risk_label || 'RISK'} ({mc.risk_score || 0})
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 mt-1 line-clamp-2">{mc.matching_rationale}</p>
                            </div>

                            <div className="flex items-center justify-between pt-1 border-t border-slate-800/60">
                              <span className="text-[11px] text-slate-500 truncate max-w-[150px]">
                                {mc.sender || 'Unknown Sender'}
                              </span>
                              {onSelectCase && (
                                <button
                                  onClick={() => onSelectCase(mc.case_id)}
                                  className="text-xs font-medium text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition"
                                >
                                  Investigate <ArrowRight className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Pivot Recommendations */}
                  {res.pivot_recommendations && res.pivot_recommendations.length > 0 && (
                    <div className="bg-indigo-950/30 rounded-lg p-3 border border-indigo-900/40 space-y-1.5">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                        <TrendingUp className="w-3.5 h-3.5" />
                        Recommended SOC Analyst Pivots
                      </div>
                      <ul className="space-y-1">
                        {res.pivot_recommendations.map((piv, pIdx) => (
                          <li key={pIdx} className="text-xs text-slate-300 flex items-start gap-2">
                            <span className="text-indigo-400 mt-0.5">•</span>
                            <span>{piv}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            !loading && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400 space-y-2">
                <CheckCircle className="w-10 h-10 text-emerald-500 mx-auto" />
                <h4 className="text-base font-semibold text-white">No Indicators Match Current Hypothesis</h4>
                <p className="text-xs max-w-md mx-auto text-slate-500">
                  The evaluated hypothesis returned zero anomalies across analyzed mailboxes. Try switching hypotheses or entering an indicator pivot query.
                </p>
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
};
