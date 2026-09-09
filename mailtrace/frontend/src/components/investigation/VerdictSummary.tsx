import React from 'react';
import { InvestigationCase } from '../../types/investigation';
import { RiskGauge } from '../common/RiskGauge';
import { Badge } from '../common/Badge';
import { safeStr } from '../../lib/utils';

interface VerdictSummaryProps {
  verdict?: Partial<InvestigationCase['verdict']>;
}

export const VerdictSummary: React.FC<VerdictSummaryProps> = ({ verdict = {} }) => {
  const severity = safeStr(verdict?.severity || 'HIGH').toUpperCase();
  const primaryThreat = safeStr(verdict?.primaryThreat || 'SUSPICIOUS');
  const riskScore = Number(verdict?.overallRiskScore ?? verdict?.riskScore ?? 75);
  const confidenceScore = Number(verdict?.confidenceScore ?? verdict?.confidence ?? 94);
  const summaryText = safeStr(verdict?.summary || verdict?.summaryExplanation || 'Automated forensic inspection completed.');
  const secondaryThreats = Array.isArray(verdict?.secondaryThreats) ? verdict.secondaryThreats.map(t => safeStr(t)) : [];

  const isBenign = severity === 'LOW' || severity === 'INFO' || primaryThreat === 'BENIGN';
  const isCritical = severity === 'CRITICAL';

  return (
    <div
      className={`p-5 rounded-lg border relative overflow-hidden ${
        isCritical
          ? 'bg-red-950/20 border-red-500/40'
          : isBenign
          ? 'bg-emerald-950/20 border-emerald-500/40'
          : 'bg-amber-950/20 border-amber-500/40'
      }`}
    >
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-start gap-4">
          <RiskGauge score={riskScore} size="lg" />

          <div className="space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant="severity" severity={severity as any} size="md">
                {severity} THREAT
              </Badge>
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60 font-semibold">
                AI Confidence: {confidenceScore}%
              </span>
            </div>

            <h3 className="text-lg font-bold font-mono text-slate-100 mt-1">
              {primaryThreat}
            </h3>

            <p className="text-xs text-slate-300 max-w-2xl font-sans leading-relaxed">
              {summaryText}
            </p>

            {secondaryThreats.length > 0 && (
              <div className="flex items-center gap-1.5 pt-1 flex-wrap">
                <span className="text-[11px] font-mono text-slate-400">Co-Occurring Vectors:</span>
                {secondaryThreats.map((tag, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="hidden lg:flex flex-col items-end justify-center p-3.5 rounded bg-slate-950/80 border border-slate-800 text-right font-mono min-w-[200px]">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider">
            Automated Policy
          </span>
          <span
            className={`text-sm font-bold mt-0.5 ${
              isCritical
                ? 'text-red-400'
                : isBenign
                ? 'text-emerald-400'
                : 'text-amber-400'
            }`}
          >
            {isCritical
              ? 'MANDATORY QUARANTINE'
              : isBenign
              ? 'PASS TO INBOX'
              : 'SECURITY BANNER'}
          </span>
          <span className="text-[10px] text-slate-400 mt-1">
            Engine Rule #SIH-{(severity || 'SEC').slice(0, 3)}-99
          </span>
        </div>
      </div>
    </div>
  );
};
