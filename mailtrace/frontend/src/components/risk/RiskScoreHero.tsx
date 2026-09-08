import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Flame } from 'lucide-react';
import { Badge } from '../ui/Badge';
import { Card } from '../ui/Card';
import type { RiskAssessmentResult } from '../../types/api';

export interface RiskScoreHeroProps {
  riskAssessment?: RiskAssessmentResult | null;
  className?: string;
}

export const RiskScoreHero: React.FC<RiskScoreHeroProps> = ({ riskAssessment, className }) => {
  if (!riskAssessment) {
    return (
      <Card title="Unified Forensic Risk Assessment" className={className}>
        <div className="py-8 text-center text-xs font-mono text-slate-500">
          RISK DATA UNAVAILABLE FOR THIS CASE
        </div>
      </Card>
    );
  }

  const score = Math.min(100, Math.max(0, Math.round(riskAssessment.risk_score ?? 0)));
  const severity = (riskAssessment.severity || 'LOW').toUpperCase();
  const confidence = Math.round((riskAssessment.confidence ?? 0.8) * 100);
  const riskFactors = Array.isArray(riskAssessment.risk_factors) ? riskAssessment.risk_factors : [];
  const categoryScores = riskAssessment.category_scores && typeof riskAssessment.category_scores === 'object'
    ? riskAssessment.category_scores
    : {};

  // SVG Gauge calculations
  const radius = 70;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  // Use a 270 degree arc (from 135deg to 405deg)
  const arcPercentage = 0.75;
  const totalLength = circumference * arcPercentage;
  const strokeDashoffset = totalLength - (totalLength * score) / 100;

  // Severity color mapping
  const getSeverityConfig = () => {
    switch (severity) {
      case 'CRITICAL':
        return {
          stroke: '#ef4444',
          glow: 'drop-shadow(0 0 16px rgba(239, 68, 68, 0.6))',
          badgeVariant: 'danger',
          icon: <Flame className="w-5 h-5 text-red-400 animate-pulse" />,
          accentBg: 'bg-red-950/30 border-red-500/30',
        };
      case 'HIGH':
        return {
          stroke: '#f97316',
          glow: 'drop-shadow(0 0 16px rgba(249, 115, 22, 0.5))',
          badgeVariant: 'warning',
          icon: <ShieldAlert className="w-5 h-5 text-orange-400" />,
          accentBg: 'bg-orange-950/30 border-orange-500/30',
        };
      case 'MEDIUM':
        return {
          stroke: '#f59e0b',
          glow: 'drop-shadow(0 0 16px rgba(245, 158, 11, 0.4))',
          badgeVariant: 'warning',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
          accentBg: 'bg-amber-950/30 border-amber-500/30',
        };
      case 'LOW':
      default:
        return {
          stroke: '#10b981',
          glow: 'drop-shadow(0 0 16px rgba(16, 185, 129, 0.4))',
          badgeVariant: 'success',
          icon: <CheckCircle className="w-5 h-5 text-emerald-400" />,
          accentBg: 'bg-emerald-950/30 border-emerald-500/30',
        };
    }
  };

  const config = getSeverityConfig();

  return (
    <Card 
      title="UNIFIED RISK ASSESSMENT" 
      subtitle="Deterministic multi-vector scoring (0–100)"
      icon={<ShieldAlert className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="flex flex-col lg:flex-row items-center justify-between gap-6 py-2">
        
        {/* Animated Radial Gauge */}
        <div className="relative flex flex-col items-center justify-center shrink-0">
          <div className="relative w-44 h-44 flex items-center justify-center">
            <svg
              className="w-full h-full transform -rotate-90"
              viewBox="0 0 180 180"
            >
              {/* Background Track Arc */}
              <circle
                cx="90"
                cy="90"
                r={radius}
                fill="none"
                stroke="#1e293b"
                strokeWidth={strokeWidth}
                strokeDasharray={`${totalLength} ${circumference}`}
                strokeLinecap="round"
                className="transform rotate-[135deg] origin-center"
              />

              {/* Dynamic Value Arc */}
              <circle
                cx="90"
                cy="90"
                r={radius}
                fill="none"
                stroke={config.stroke}
                strokeWidth={strokeWidth}
                strokeDasharray={`${totalLength} ${circumference}`}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                style={{
                  filter: config.glow,
                  transition: 'stroke-dashoffset 1s ease-out',
                }}
                className="transform rotate-[135deg] origin-center"
              />
            </svg>

            {/* Center Content */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-extrabold font-mono tracking-tighter text-slate-100">
                {score}
              </span>
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                / 100 RISK
              </span>
              <div className="mt-1">
                <Badge variant="severity" severity={severity} size="sm" />
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-[11px] font-mono text-slate-400 mt-[-10px]">
            <span>CONFIDENCE: <strong className="text-slate-200">{confidence}%</strong></span>
            <span>•</span>
            <span>METHOD: <strong className="text-slate-200">{riskAssessment.method || 'WEIGHTED'}</strong></span>
          </div>
        </div>

        {/* Narrative & Category Breakdown */}
        <div className="flex-1 space-y-4">
          <div className={`p-4 rounded-lg border ${config.accentBg} space-y-2`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {config.icon}
                <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-200">
                  {severity} SEVERITY LEVEL
                </span>
              </div>
              <span className="font-mono text-xs text-slate-400">
                {riskFactors.length} Risk Factors Detected
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {riskAssessment.explanation || 'Comprehensive analysis of authentication headers, sender identity, threat intent signals, and infrastructure enrichment.'}
            </p>
          </div>

          {/* Category Scores Sub-Grid */}
          {Object.keys(categoryScores).length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                Category Contribution Vector
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(categoryScores).map(([cat, pts]) => (
                  <div
                    key={cat}
                    className="p-2 rounded bg-cyber-surface border border-cyber-border/70 text-center"
                  >
                    <div className="text-[10px] font-mono text-slate-400 uppercase truncate">
                      {cat.replace(/_/g, ' ')}
                    </div>
                    <div className="font-mono text-xs font-bold text-cyber-cyan mt-0.5">
                      +{pts} pts
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

      </div>
    </Card>
  );
};
