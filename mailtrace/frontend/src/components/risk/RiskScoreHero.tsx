import React, { useId, useMemo } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Flame, 
  Radio, 
  Cpu, 
  Activity, 
  Crosshair,
  ShieldCheck,
  Zap,
  Layers,
  Terminal,
  Gauge
} from 'lucide-react';
import type { RiskAssessmentResult } from '../../types/api';

export interface RiskScoreHeroProps {
  riskAssessment?: RiskAssessmentResult | null;
  className?: string;
}

export const RiskScoreHero: React.FC<RiskScoreHeroProps> = ({ riskAssessment, className = '' }) => {
  const gradientId = useId();
  const filterId = useId();
  const glowFilterId = useId();

  if (!riskAssessment) {
    return (
      <div className={`relative overflow-hidden rounded-xl border border-slate-800 bg-slate-950/80 p-6 backdrop-blur-md shadow-2xl ${className}`}>
        <div className="flex items-center space-x-2 border-b border-slate-800/80 pb-3 font-mono text-xs text-slate-400">
          <Crosshair className="h-4 w-4 text-cyan-400" />
          <span className="font-bold tracking-wider text-slate-200 uppercase">UNIFIED RISK ASSESSMENT</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-500">Tactical forensic scoring engine (0–100)</span>
        </div>
        <div className="py-12 text-center font-mono text-xs tracking-widest text-slate-500 uppercase">
          [ TELEMETRY STREAM INACTIVE • NO RISK DATA LOADED ]
        </div>
      </div>
    );
  }

  const score = Math.min(100, Math.max(0, Math.round(riskAssessment.risk_score ?? 0)));
  const severity = (riskAssessment.severity || 'LOW').toUpperCase();
  const confidence = Math.round((riskAssessment.confidence ?? 0.85) * 100);
  const riskFactors = Array.isArray(riskAssessment.risk_factors) 
    ? riskAssessment.risk_factors 
    : (Array.isArray((riskAssessment as any).top_factors) ? (riskAssessment as any).top_factors : []);
  const categoryScores = riskAssessment.category_scores && typeof riskAssessment.category_scores === 'object'
    ? riskAssessment.category_scores
    : {};

  // Gauge Geometry: 240-degree tactical arc (150° to 390°)
  const radius = 80;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const arcFraction = 0.72; // 259.2 degrees
  const arcLength = circumference * arcFraction;
  const strokeDashoffset = arcLength - (arcLength * score) / 100;

  // Dynamic SOC Color Mapping & Laser Glow Intensity based on bounded score
  const severityTheme = useMemo(() => {
    if (score >= 80 || severity === 'CRITICAL') {
      return {
        level: 'CRITICAL',
        primaryHex: '#f43f5e', // rose-500
        secondaryHex: '#e11d48', // rose-600
        accentHex: '#fda4af', // rose-300
        textClass: 'text-rose-500',
        glowStyle: 'drop-shadow(0 0 16px rgba(244, 63, 94, 0.85)) drop-shadow(0 0 32px rgba(244, 63, 94, 0.4))',
        bgGlow: 'from-rose-500/10 via-rose-950/20 to-transparent',
        borderClass: 'border-rose-500/40',
        badgeBg: 'bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-[0_0_12px_rgba(244,63,94,0.3)]',
        icon: <Flame className="h-4 w-4 text-rose-500 animate-pulse" />,
        statusText: 'CRITICAL THREAT DETECTED',
        radarPulse: 'bg-rose-500 animate-ping',
        gaugeFilterDeviation: '6',
      };
    }
    if (score >= 60 || severity === 'HIGH') {
      return {
        level: 'HIGH',
        primaryHex: '#fb923c', // orange-400
        secondaryHex: '#ea580c', // orange-600
        accentHex: '#fed7aa', // orange-200
        textClass: 'text-orange-400',
        glowStyle: 'drop-shadow(0 0 12px rgba(251, 146, 60, 0.75)) drop-shadow(0 0 24px rgba(251, 146, 60, 0.3))',
        bgGlow: 'from-orange-500/10 via-orange-950/20 to-transparent',
        borderClass: 'border-orange-500/40',
        badgeBg: 'bg-orange-500/10 text-orange-400 border-orange-500/30 shadow-[0_0_10px_rgba(251,146,60,0.25)]',
        icon: <ShieldAlert className="h-4 w-4 text-orange-400 animate-pulse" />,
        statusText: 'HIGH RISK ANOMALIES DETECTED',
        radarPulse: 'bg-orange-400 animate-ping',
        gaugeFilterDeviation: '5',
      };
    }
    if (score >= 30 || severity === 'MEDIUM') {
      return {
        level: 'MEDIUM',
        primaryHex: '#fbbf24', // amber-400
        secondaryHex: '#d97706', // amber-600
        accentHex: '#fef3c7', // amber-100
        textClass: 'text-amber-400',
        glowStyle: 'drop-shadow(0 0 10px rgba(251, 191, 36, 0.65)) drop-shadow(0 0 18px rgba(251, 191, 36, 0.2))',
        bgGlow: 'from-amber-500/10 via-amber-950/20 to-transparent',
        borderClass: 'border-amber-500/40',
        badgeBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-[0_0_8px_rgba(251,191,36,0.2)]',
        icon: <AlertTriangle className="h-4 w-4 text-amber-400" />,
        statusText: 'ELEVATED SUSPICIOUS INDICATORS',
        radarPulse: 'bg-amber-400 animate-ping',
        gaugeFilterDeviation: '4',
      };
    }
    return {
      level: 'LOW',
      primaryHex: '#34d399', // emerald-400 (toxic green safe)
      secondaryHex: '#059669', // emerald-600
      accentHex: '#a7f3d0', // emerald-200
      textClass: 'text-emerald-400',
      glowStyle: 'drop-shadow(0 0 8px rgba(52, 211, 153, 0.6)) drop-shadow(0 0 16px rgba(52, 211, 153, 0.2))',
      bgGlow: 'from-emerald-500/10 via-emerald-950/20 to-transparent',
      borderClass: 'border-emerald-500/40',
      badgeBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-[0_0_8px_rgba(52,211,153,0.2)]',
      icon: <ShieldCheck className="h-4 w-4 text-emerald-400" />,
      statusText: 'NOMINAL COMM PATTERNS',
      radarPulse: 'bg-emerald-400 animate-pulse',
      gaugeFilterDeviation: '3',
    };
  }, [score, severity]);

  // Generate 25 precision tick markers around the gauge
  const ticks = useMemo(() => {
    return Array.from({ length: 25 }, (_, i) => {
      const angle = 140 + i * (260 / 24); // 140deg to 400deg
      const rad = (angle * Math.PI) / 180;
      const isMajor = i % 6 === 0;
      const tickLen = isMajor ? 8 : 4;
      const innerR = radius - strokeWidth / 2 - 4;
      const outerR = innerR - tickLen;
      const x1 = 100 + innerR * Math.cos(rad);
      const y1 = 100 + innerR * Math.sin(rad);
      const x2 = 100 + outerR * Math.cos(rad);
      const y2 = 100 + outerR * Math.sin(rad);
      const active = (i / 24) * 100 <= score;
      return { x1, y1, x2, y2, active, isMajor };
    });
  }, [score, radius, strokeWidth]);

  return (
    <div className={`relative overflow-hidden rounded-xl border border-slate-800 bg-slate-950/90 shadow-2xl backdrop-blur-md transition-all ${className}`}>
      
      {/* Dynamic Background Glow Layer */}
      <div 
        className={`pointer-events-none absolute -left-20 -top-20 h-72 w-72 rounded-full bg-gradient-to-br ${severityTheme.bgGlow} opacity-50 blur-3xl`} 
      />

      {/* Top Tactical Status Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 bg-slate-900/60 px-5 py-3 font-mono text-xs">
        <div className="flex items-center space-x-2.5">
          <Activity className="h-4 w-4 text-cyan-400 animate-pulse" />
          <span className="font-bold tracking-wider text-slate-100 uppercase">UNIFIED FORENSIC RISK ENGINE</span>
          <span className="text-slate-600">|</span>
          <span className="text-[11px] text-slate-400">Deterministic Multi-Vector Threat Intelligence</span>
        </div>
        <div className="flex items-center space-x-3 text-[11px]">
          <div className="flex items-center space-x-1.5 text-slate-400">
            <Radio className="h-3 w-3 text-cyan-400 animate-pulse" />
            <span className="text-cyan-400 font-semibold">SYS.SOC // ONLINE</span>
          </div>
          <span className="rounded border border-slate-700 bg-slate-900/90 px-2 py-0.5 font-bold text-slate-300">
            {riskAssessment.method || 'RULE_ENGINE_V1'}
          </span>
        </div>
      </div>

      {/* Bento Grid Body */}
      <div className="p-5">
        <div className="flex flex-col xl:flex-row items-stretch gap-6">
          
          {/* ========================================================= */}
          {/* BENTO BOX 1: HUD Radial Gauge & Threat Score Center       */}
          {/* ========================================================= */}
          <div className="relative flex flex-col items-center justify-between rounded-xl border border-slate-800 bg-slate-950/80 p-5 shadow-inner backdrop-blur-md shrink-0 xl:w-[320px] overflow-hidden group">
            
            {/* Subtle Grid Pattern Overlay */}
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:16px_16px] opacity-40" />

            {/* Dial Telemetry Status */}
            <div className="relative z-10 w-full flex items-center justify-between text-[10px] font-mono">
              <span className="flex items-center space-x-1.5 text-slate-400">
                <span className={`h-1.5 w-1.5 rounded-full ${severityTheme.radarPulse}`} />
                <span className="tracking-wider text-slate-300">RADIAL GAUGING</span>
              </span>
              <span className="text-slate-500 uppercase tracking-widest font-semibold">SCALE 0–100</span>
            </div>

            {/* Glowing SVG Radial Gauge */}
            <div className="relative my-2 flex h-52 w-52 items-center justify-center z-10">
              <svg 
                className="h-full w-full transform -rotate-90"
                viewBox="0 0 200 200"
              >
                <defs>
                  {/* Dynamic Color Gradient */}
                  <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor={severityTheme.secondaryHex} />
                    <stop offset="100%" stopColor={severityTheme.primaryHex} />
                  </linearGradient>

                  {/* Multi-tier Neon Glow Filter */}
                  <filter id={glowFilterId} x="-30%" y="-30%" width="160%" height="160%">
                    <feGaussianBlur stdDeviation={severityTheme.gaugeFilterDeviation} result="coloredBlur" />
                    <feMerge>
                      <feMergeNode in="coloredBlur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                </defs>

                {/* Outer Tactical Radar Perimeter Ring */}
                <circle
                  cx="100"
                  cy="100"
                  r={radius + 12}
                  fill="none"
                  stroke="#1e293b"
                  strokeWidth="1"
                  strokeDasharray="4 4"
                  className="opacity-60"
                />

                {/* Perimeter Calibrated Ticks */}
                {ticks.map((t, idx) => (
                  <line
                    key={idx}
                    x1={t.x1}
                    y1={t.y1}
                    x2={t.x2}
                    y2={t.y2}
                    stroke={t.active ? severityTheme.primaryHex : '#334155'}
                    strokeWidth={t.isMajor ? 2 : 1}
                    className="transition-colors duration-500"
                    style={{
                      filter: t.active ? `drop-shadow(0 0 2px ${severityTheme.primaryHex})` : undefined
                    }}
                  />
                ))}

                {/* Inactive Background Gauge Track */}
                <circle
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="none"
                  stroke="#0f172a"
                  strokeWidth={strokeWidth}
                  strokeDasharray={`${arcLength} ${circumference}`}
                  strokeLinecap="round"
                  className="transform rotate-[126deg] origin-center"
                />

                {/* Inactive Subtle Inner Border */}
                <circle
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="none"
                  stroke="#1e293b"
                  strokeWidth="2"
                  strokeDasharray={`${arcLength} ${circumference}`}
                  strokeLinecap="round"
                  className="transform rotate-[126deg] origin-center opacity-30"
                />

                {/* Active Dynamic Glowing Arc */}
                <circle
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="none"
                  stroke={`url(#${gradientId})`}
                  strokeWidth={strokeWidth}
                  strokeDasharray={`${arcLength} ${circumference}`}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  filter={`url(#${glowFilterId})`}
                  style={{
                    transition: 'stroke-dashoffset 1.4s cubic-bezier(0.16, 1, 0.3, 1)',
                  }}
                  className="transform rotate-[126deg] origin-center"
                />
              </svg>

              {/* Central Numerical Telemetry Display */}
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none">
                <div className="flex items-baseline">
                  <span 
                    className="font-mono text-5xl font-black tracking-tight text-white transition-all duration-700"
                    style={{ filter: severityTheme.glowStyle }}
                  >
                    {score}
                  </span>
                  <span className="font-mono text-sm font-bold text-slate-500">.0</span>
                </div>
                <span className="mt-0.5 font-mono text-[9px] tracking-widest text-slate-400 uppercase">
                  / 100 RISK
                </span>
                <div className="mt-2">
                  <span className={`rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold tracking-wider uppercase transition-all ${severityTheme.badgeBg}`}>
                    {severity}
                  </span>
                </div>
              </div>
            </div>

            {/* Bottom Dial Telemetry Footer */}
            <div className="relative z-10 w-full border-t border-slate-800/80 pt-2 flex items-center justify-between font-mono text-[11px] text-slate-400">
              <div className="flex items-center space-x-1.5">
                <span className="text-slate-500">CONFIDENCE:</span>
                <span className="font-bold text-cyan-400">{confidence}%</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <span className="text-slate-500">FACTORS:</span>
                <span className="font-bold text-slate-200">{riskFactors.length}</span>
              </div>
            </div>
          </div>

          {/* ========================================================= */}
          {/* BENTO BOX 2: Executive Rationale & Category Vector Matrix */}
          {/* ========================================================= */}
          <div className="flex-1 flex flex-col justify-between space-y-4">
            
            {/* Executive SOC Verdict Console */}
            <div className={`relative overflow-hidden rounded-xl border bg-slate-950/70 p-4.5 backdrop-blur-md transition-all ${severityTheme.borderClass}`}>
              
              {/* Verdict Header */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
                <div className="flex items-center space-x-2.5">
                  <div className="rounded-lg border border-slate-700 bg-slate-900/90 p-1.5 shadow-sm">
                    {severityTheme.icon}
                  </div>
                  <div>
                    <span className="font-mono text-xs font-bold tracking-wider text-slate-100 uppercase">
                      {severity} SEVERITY LEVEL
                    </span>
                    <span className="block sm:inline sm:ml-2 font-mono text-[10px] text-slate-400">
                      [{severityTheme.statusText}]
                    </span>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2 font-mono text-[10px] text-slate-400">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
                  <span className="text-cyan-400 font-semibold">SOC VERDICT // CONFIRMED</span>
                </div>
              </div>

              {/* Grounded Narrative Explanation */}
              <p className="pt-3 font-sans text-xs leading-relaxed text-slate-300">
                {riskAssessment.explanation || 
                  'Comprehensive deterministic evaluation across authentication protocol alignment, identity anomalies, linguistic coercive vectors, and infrastructure enrichment.'}
              </p>
            </div>

            {/* Category Vector Matrix */}
            {Object.keys(categoryScores).length > 0 && (
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 shadow-inner">
                
                <div className="flex items-center justify-between pb-3">
                  <span className="flex items-center space-x-1.5 font-mono text-[10px] font-semibold tracking-widest text-slate-400 uppercase">
                    <Layers className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Bounded Category Subscore Vectors</span>
                  </span>
                  <span className="font-mono text-[10px] text-slate-500">
                    Strict Anti-Double-Counting Ceilings
                  </span>
                </div>

                {/* Subscores Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  {Object.entries(categoryScores).map(([category, pts]) => {
                    const numPts = Number(pts) || 0;
                    const hasPoints = numPts > 0;
                    
                    let vectorColor = 'text-cyan-400';
                    let vectorBarBg = 'bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.5)]';
                    if (numPts >= 15) {
                      vectorColor = 'text-rose-400';
                      vectorBarBg = 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]';
                    } else if (numPts >= 8) {
                      vectorColor = 'text-amber-400';
                      vectorBarBg = 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]';
                    }

                    return (
                      <div
                        key={category}
                        className={`rounded-lg border p-2.5 transition-all ${
                          hasPoints
                            ? 'border-slate-700/80 bg-slate-900/90 shadow-sm'
                            : 'border-slate-900/60 bg-slate-950/40 opacity-50'
                        }`}
                      >
                        <div className="truncate font-mono text-[10px] text-slate-400 uppercase">
                          {category.replace(/_/g, ' ')}
                        </div>
                        
                        <div className="mt-1 flex items-baseline justify-between">
                          <span className={`font-mono text-xs font-bold ${hasPoints ? vectorColor : 'text-slate-500'}`}>
                            {hasPoints ? `+${numPts.toFixed(1)}` : '0.0'}{' '}
                            <span className="text-[9px] font-normal text-slate-500">pts</span>
                          </span>
                        </div>

                        {/* Mini Metric Meter */}
                        <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-slate-900">
                          <div
                            className={`h-full rounded-full transition-all duration-700 ${vectorBarBg}`}
                            style={{ width: `${Math.min(100, (numPts / 30) * 100)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

          </div>

        </div>
      </div>

    </div>
  );
};

