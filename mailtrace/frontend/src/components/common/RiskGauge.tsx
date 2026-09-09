import React from 'react';

interface RiskGaugeProps {
  score: number; // 0 - 100
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  type?: 'circular' | 'bar';
  className?: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 'md',
  showLabel = true,
  type = 'circular',
  className = ''
}) => {
  const normalizedScore = Math.min(100, Math.max(0, score));

  const getColor = (s: number) => {
    if (s >= 80) return { stroke: '#ef4444', text: 'text-threat-critical', glow: 'shadow-glow-critical' };
    if (s >= 60) return { stroke: '#f97316', text: 'text-threat-high', glow: 'shadow-glow-high' };
    if (s >= 40) return { stroke: '#eab308', text: 'text-threat-medium', glow: '' };
    if (s >= 20) return { stroke: '#3b82f6', text: 'text-threat-low', glow: '' };
    return { stroke: '#10b981', text: 'text-threat-benign', glow: 'shadow-glow-benign' };
  };

  const { stroke, text } = getColor(normalizedScore);

  if (type === 'bar') {
    return (
      <div className={`w-full ${className}`}>
        {showLabel && (
          <div className="flex justify-between items-center mb-1 text-xs font-mono">
            <span className="text-slate-400">Risk Score</span>
            <span className={`font-bold ${text}`}>{normalizedScore}/100</span>
          </div>
        )}
        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
          <div
            className="h-full transition-all duration-700 ease-out rounded-full"
            style={{
              width: `${normalizedScore}%`,
              backgroundColor: stroke
            }}
          />
        </div>
      </div>
    );
  }

  const dimensions = {
    sm: { radius: 24, strokeWidth: 4, width: 64, height: 64, fontSize: 'text-sm' },
    md: { radius: 36, strokeWidth: 6, width: 92, height: 92, fontSize: 'text-xl' },
    lg: { radius: 52, strokeWidth: 8, width: 128, height: 128, fontSize: 'text-3xl' }
  }[size];

  const circumference = 2 * Math.PI * dimensions.radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className={`relative inline-flex flex-col items-center justify-center ${className}`}>
      <svg width={dimensions.width} height={dimensions.height} className="-rotate-90">
        <circle
          cx={dimensions.width / 2}
          cy={dimensions.height / 2}
          r={dimensions.radius}
          fill="transparent"
          stroke="#1e293b"
          strokeWidth={dimensions.strokeWidth}
        />
        <circle
          cx={dimensions.width / 2}
          cy={dimensions.height / 2}
          r={dimensions.radius}
          fill="transparent"
          stroke={stroke}
          strokeWidth={dimensions.strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className={`font-mono font-bold tracking-tight ${dimensions.fontSize} ${text}`}>
          {normalizedScore}
        </span>
        {size !== 'sm' && <span className="text-[10px] font-mono text-slate-400 uppercase -mt-1">/ 100</span>}
      </div>
    </div>
  );
};
