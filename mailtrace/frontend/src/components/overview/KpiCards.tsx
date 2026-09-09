import React from 'react';
import { Mail, ShieldAlert, AlertTriangle, Flame, Lock, ArrowUpRight } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

export const KpiCards: React.FC = () => {
  const { cases, campaigns } = useInvestigation();

  const totalAnalyzed = 1420;
  const criticalThreats = cases.filter(c => c.verdict.severity === 'CRITICAL').length;
  const activeCampaignsCount = campaigns.filter(c => c.status === 'ACTIVE').length;
  const autoContained = 99.4;

  const cards = [
    {
      label: 'Total Emails Ingested (24h)',
      value: totalAnalyzed.toLocaleString(),
      change: '+14.2% vs baseline',
      icon: Mail,
      accent: 'text-cyan-400',
      border: 'border-cyan-500/30',
      bg: 'bg-cyan-500/5'
    },
    {
      label: 'Critical Threats Flagged',
      value: `${criticalThreats} Active`,
      change: 'Requiring immediate action',
      icon: ShieldAlert,
      accent: 'text-threat-critical',
      border: 'border-threat-critical/30',
      bg: 'bg-threat-critical/5'
    },
    {
      label: 'Active Threat Campaigns',
      value: `${activeCampaignsCount} Clusters`,
      change: '142 correlated incidents',
      icon: Flame,
      accent: 'text-threat-high',
      border: 'border-threat-high/30',
      bg: 'bg-threat-high/5'
    },
    {
      label: 'Automated Containment Rate',
      value: `${autoContained}%`,
      change: '0 false-positive lockouts',
      icon: Lock,
      accent: 'text-threat-benign',
      border: 'border-threat-benign/30',
      bg: 'bg-threat-benign/5'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className={`p-4 rounded-lg bg-cyber-panel border ${card.border} ${card.bg} shadow-lg transition-transform hover:-translate-y-0.5 duration-200`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 font-medium uppercase tracking-wider">
                {card.label}
              </span>
              <div className={`p-2 rounded-md bg-slate-900/80 ${card.accent}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className={`text-2xl font-bold font-mono tracking-tight ${card.accent}`}>
                {card.value}
              </span>
            </div>
            <div className="mt-1 flex items-center gap-1 text-[11px] font-mono text-slate-400">
              <ArrowUpRight className="w-3 h-3 text-cyan-400" />
              <span>{card.change}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
