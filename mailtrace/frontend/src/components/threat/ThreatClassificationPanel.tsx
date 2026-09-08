import React from 'react';
import { 
  Zap, 
  BrainCircuit, 
  ShieldAlert, 
  Flame, 
  FileCheck2, 
  AlertTriangle, 
  Tag 
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import type { ThreatAnalysisResult } from '../../types/api';

export interface ThreatClassificationPanelProps {
  threatAnalysis?: ThreatAnalysisResult | null;
  className?: string;
}

export const ThreatClassificationPanel: React.FC<ThreatClassificationPanelProps> = ({
  threatAnalysis,
  className,
}) => {
  if (!threatAnalysis) {
    return (
      <Card title="AI Threat Classification" className={className}>
        <div className="py-8 text-center text-xs font-mono text-slate-500">
          THREAT ANALYSIS NOT AVAILABLE
        </div>
      </Card>
    );
  }

  const primaryThreat = threatAnalysis.primary_threat || 'SUSPICIOUS';
  const confidencePct = Math.round((threatAnalysis.confidence || 0.5) * 100);
  const secondaryThreats = threatAnalysis.secondary_threats || [];
  const signals = threatAnalysis.signals || {};

  const getSignalLevelBadge = (level: string = 'NONE') => {
    const l = level.toUpperCase();
    switch (l) {
      case 'HIGH':
        return 'bg-red-950/60 text-red-400 border-red-500/40 glow-red-sm';
      case 'MEDIUM':
        return 'bg-amber-950/60 text-amber-400 border-amber-500/40 glow-amber-sm';
      case 'LOW':
        return 'bg-cyan-950/60 text-cyan-400 border-cyan-500/30';
      case 'NONE':
      default:
        return 'bg-slate-900/40 text-slate-500 border-slate-800';
    }
  };

  const signalItems = [
    { key: 'urgency', label: 'Urgency & Deadlines', val: (signals as any).urgency || 'NONE' },
    { key: 'credential_request', label: 'Credential Harvesting', val: (signals as any).credential_request || 'NONE' },
    { key: 'financial_request', label: 'Financial / Payment Request', val: (signals as any).financial_request || 'NONE' },
    { key: 'impersonation', label: 'VIP / Brand Impersonation', val: (signals as any).impersonation || 'NONE' },
    { key: 'suspicious_link', label: 'Suspicious / Obfuscated Link', val: (signals as any).suspicious_link || 'NONE' },
    { key: 'attachment_threat', label: 'Dangerous Attachment Indicator', val: (signals as any).attachment_threat || 'NONE' },
    { key: 'fear_manipulation', label: 'Fear & Coercion Tactic', val: (signals as any).fear_manipulation || 'NONE' },
    { key: 'authority_pressure', label: 'Authority / Executive Pressure', val: (signals as any).authority_pressure || 'NONE' },
  ];

  return (
    <Card
      title="AI THREAT CLASSIFICATION"
      subtitle="Behavioral intent & linguistic NLP signals"
      icon={<BrainCircuit className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-6">
        
        {/* Primary Classification Hero Banner */}
        <div className="p-4 rounded-xl bg-gradient-to-r from-cyber-surface via-cyber-card to-cyber-surface border border-cyber-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
              PRIMARY THREAT CLASS
            </span>
            <div className="flex items-center space-x-3">
              <span className="text-xl sm:text-2xl font-mono font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-red-400 via-orange-300 to-amber-300 tracking-wider">
                {primaryThreat}
              </span>
              <span className="font-mono text-xs font-bold text-cyber-cyan bg-cyan-950/60 border border-cyan-500/40 px-2 py-0.5 rounded shadow-[0_0_10px_rgba(0,240,255,0.2)]">
                {confidencePct}% CONFIDENCE
              </span>
            </div>
          </div>

          {/* Secondary Threats */}
          {secondaryThreats.length > 0 && (
            <div className="space-y-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                SECONDARY THREATS
              </span>
              <div className="flex flex-wrap gap-1.5">
                {secondaryThreats.map((threat) => (
                  <span
                    key={threat}
                    className="px-2.5 py-1 rounded bg-purple-950/40 border border-purple-500/40 font-mono text-[11px] font-semibold text-purple-300 shadow-[0_0_8px_rgba(168,85,247,0.2)]"
                  >
                    {threat}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Explainable NLP Analysis Text */}
        <div className="p-4 rounded-lg bg-cyber-surface/50 border border-cyber-border space-y-1.5">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-300 font-bold uppercase">
            <Zap className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>EXPLAINABLE THREAT RATIONALE</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            {threatAnalysis.explanation || 'Rule and NLP engines evaluated email body, linguistic structures, and forensic indicators.'}
          </p>
        </div>

        {/* 8-Signal Behavioral Matrix */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
              BEHAVIORAL & SOCIAL ENGINEERING SIGNALS
            </span>
            <span className="text-[10px] font-mono text-slate-500">
              8 SIGNALS EVALUATED
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {signalItems.map((sig) => (
              <div
                key={sig.key}
                className="p-2.5 rounded-lg bg-cyber-surface border border-cyber-border/70 flex items-center justify-between"
              >
                <span className="text-[11px] text-slate-300 font-medium truncate pr-2">
                  {sig.label}
                </span>
                <span
                  className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded border uppercase shrink-0 ${getSignalLevelBadge(
                    sig.val
                  )}`}
                >
                  {sig.val}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Extracted Threat Indicators Sub-list */}
        {threatAnalysis.indicators && threatAnalysis.indicators.length > 0 && (
          <div className="space-y-2 pt-2 border-t border-cyber-border/40">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
              SPECIFIC THREAT INDICATORS ({threatAnalysis.indicators.length})
            </span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {threatAnalysis.indicators.map((ind, i) => (
                <div
                  key={`${ind.indicator}-${i}`}
                  className="p-2.5 rounded bg-slate-900/50 border border-cyber-border text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-slate-200 truncate">
                      {ind.indicator}
                    </span>
                    <Badge variant="severity" severity={ind.severity} size="sm" />
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    {ind.description}
                  </p>
                  {ind.evidence && (
                    <div className="font-mono text-[10px] text-cyan-300 bg-cyber-bg px-2 py-0.5 rounded border border-cyber-border truncate">
                      MATCH: "{ind.evidence}"
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </Card>
  );
};
