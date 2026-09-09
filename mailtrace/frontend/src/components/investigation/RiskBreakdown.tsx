import React from 'react';
import { RiskScoreBreakdown } from '../../types/investigation';
import { Calculator, Shield, Activity, Globe, MessageSquare, AlertCircle } from 'lucide-react';

interface RiskBreakdownProps {
  breakdown?: Partial<RiskScoreBreakdown>;
}

export const RiskBreakdown: React.FC<RiskBreakdownProps> = ({ breakdown = {} }) => {
  const b = breakdown || {};
  const authPoints = b.authentication ?? 20;
  const identityPoints = b.identitySpoofing ?? b.identity ?? 15;
  const urlPoints = b.urlAndPayload ?? b.urlIntelligence ?? 20;
  const linguisticPoints = b.linguisticIntent ?? b.linguisticSignals ?? 15;
  const infraPoints = b.infrastructureGeo ?? b.infrastructure ?? 10;
  const behaviorPoints = b.behavioralAnomaly ?? b.behavior ?? 5;
  const totalCalculated = authPoints + identityPoints + urlPoints + linguisticPoints + infraPoints + behaviorPoints;
  const totalScore = b.totalScore ?? Math.min(100, totalCalculated);

  const layers = [
    {
      name: 'Authentication Layer',
      subtext: 'SPF / DKIM / DMARC Header Alignment',
      points: authPoints,
      maxPoints: 25,
      icon: Shield
    },
    {
      name: 'Identity & Spoofing Layer',
      subtext: 'Display Name Mismatch & Lookalike Domains',
      points: identityPoints,
      maxPoints: 25,
      icon: AlertCircle
    },
    {
      name: 'URL & Payload Intelligence',
      subtext: 'Punycode, Typosquat, Live Harvesting Pages',
      points: urlPoints,
      maxPoints: 25,
      icon: Activity
    },
    {
      name: 'Linguistic & Social Engineering',
      subtext: 'Urgency, Coercion, Authority NLP Signals',
      points: linguisticPoints,
      maxPoints: 15,
      icon: MessageSquare
    },
    {
      name: 'Infrastructure & Geolocation',
      subtext: 'Tor Exit, Bulletproof ASN, Relay Anomaly',
      points: infraPoints,
      maxPoints: 15,
      icon: Globe
    },
    {
      name: 'Behavioral Relationship Baseline',
      subtext: 'First-time Sender, Communication History',
      points: behaviorPoints,
      maxPoints: 10,
      icon: Calculator
    }
  ];

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Calculator className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Unified Multi-Layer Risk Score Composition
          </h3>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <span className="text-slate-400">Total Risk:</span>
          <span className="text-cyan-400 font-bold">{totalScore}/100</span>
        </div>
      </div>

      <div className="space-y-3">
        {layers.map((layer, idx) => {
          const Icon = layer.icon;
          const percentage = Math.min(100, Math.round((layer.points / layer.maxPoints) * 100));

          return (
            <div key={idx} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2">
                  <Icon className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-slate-200 font-medium">{layer.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 text-[11px] hidden sm:inline">{layer.subtext}</span>
                  <span className="text-cyan-300 font-bold">
                    {layer.points}/{layer.maxPoints} pts
                  </span>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="h-1.5 w-full bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-500 rounded-full ${
                    percentage >= 70
                      ? 'bg-gradient-to-r from-orange-500 to-red-500'
                      : percentage >= 40
                      ? 'bg-gradient-to-r from-cyan-500 to-amber-500'
                      : 'bg-gradient-to-r from-emerald-500 to-cyan-500'
                  }`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
