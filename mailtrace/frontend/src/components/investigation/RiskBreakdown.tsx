import React from 'react';
import { RiskScoreBreakdown } from '../../types/investigation';
import { Calculator, Shield, Activity, Globe, MessageSquare, AlertCircle } from 'lucide-react';

interface RiskBreakdownProps {
  breakdown: RiskScoreBreakdown;
}

export const RiskBreakdown: React.FC<RiskBreakdownProps> = ({ breakdown }) => {
  const layers = [
    {
      name: 'Authentication Layer',
      subtext: 'SPF / DKIM / DMARC Header Alignment',
      points: breakdown.authentication,
      maxPoints: 25,
      icon: Shield
    },
    {
      name: 'Identity & Spoofing Layer',
      subtext: 'Display Name Mismatch & Lookalike Domains',
      points: breakdown.identitySpoofing,
      maxPoints: 25,
      icon: AlertCircle
    },
    {
      name: 'URL & Payload Intelligence',
      subtext: 'Punycode, Typosquat, Live Harvesting Pages',
      points: breakdown.urlAndPayload,
      maxPoints: 25,
      icon: Activity
    },
    {
      name: 'Linguistic & Social Engineering',
      subtext: 'Urgency, Coercion, Authority NLP Signals',
      points: breakdown.linguisticIntent,
      maxPoints: 15,
      icon: MessageSquare
    },
    {
      name: 'Infrastructure & Geolocation',
      subtext: 'Tor Exit, Bulletproof ASN, Relay Anomaly',
      points: breakdown.infrastructureGeo,
      maxPoints: 15,
      icon: Globe
    },
    {
      name: 'Behavioral Relationship Baseline',
      subtext: 'First-time Sender, Communication History',
      points: breakdown.behavioralAnomaly,
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
            Multi-Layer Additive Risk Scoring Engine
          </h3>
        </div>
        <div className="text-xs font-mono font-bold text-cyan-400">
          Calculated Total: {breakdown.totalScore}/100
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {layers.map((layer, idx) => {
          const Icon = layer.icon;
          const percentage = (layer.points / layer.maxPoints) * 100;
          const isHigh = percentage >= 70;

          return (
            <div
              key={idx}
              className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex flex-col justify-between space-y-3"
            >
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className={`w-4 h-4 ${isHigh ? 'text-threat-critical' : 'text-cyan-400'}`} />
                    <span className="text-xs font-mono font-bold text-slate-200">
                      {layer.name}
                    </span>
                  </div>
                  <span
                    className={`text-xs font-mono font-bold ${
                      isHigh ? 'text-threat-critical' : 'text-cyan-400'
                    }`}
                  >
                    +{layer.points} pts
                  </span>
                </div>
                <p className="text-[11px] font-mono text-slate-400 mt-1">{layer.subtext}</p>
              </div>

              <div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      isHigh ? 'bg-threat-critical' : 'bg-cyan-500'
                    }`}
                    style={{ width: `${Math.min(100, percentage)}%` }}
                  />
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-slate-400 mt-1">
                  <span>Base Weight</span>
                  <span>Max: {layer.maxPoints} pts</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Transparent Calculation Summary formula bar */}
      <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 text-slate-400">
          <span className="font-bold text-cyan-400">Formula:</span>
          <span>Score = Auth({breakdown.authentication}) + Spoof({breakdown.identitySpoofing}) + URL({breakdown.urlAndPayload}) + NLP({breakdown.linguisticIntent}) + Geo({breakdown.infrastructureGeo}) + Behavior({breakdown.behavioralAnomaly})</span>
        </div>
        <div className="text-cyan-400 font-bold">= {breakdown.totalScore} / 100</div>
      </div>
    </div>
  );
};
