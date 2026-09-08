import React from 'react';
import { AlertCircle, FileSearch } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import type { RiskFactor } from '../../types/api';

export interface RiskFactorsListProps {
  factors: RiskFactor[];
  className?: string;
}

export const RiskFactorsList: React.FC<RiskFactorsListProps> = ({ factors = [], className }) => {
  if (!factors || factors.length === 0) {
    return (
      <Card title="RANKED RISK FACTORS" subtitle="No elevated risk triggers identified in this email" className={className}>
        <div className="p-6 text-center text-xs font-mono text-emerald-400 bg-emerald-950/20 rounded-lg border border-emerald-500/20">
          ✓ All deterministic authentication checks and threat heuristics within baseline tolerances.
        </div>
      </Card>
    );
  }

  // Sort descending by points
  const sortedFactors = [...factors].sort((a, b) => (b.points || 0) - (a.points || 0));

  return (
    <Card
      title="TOP RISK FACTORS"
      subtitle="Ranked contributing triggers from forensic, threat & infrastructure engines"
      icon={<AlertCircle className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-3">
        {sortedFactors.map((item, index) => {
          const rank = String(index + 1).padStart(2, '0');
          const pts = item.points || 0;

          return (
            <div
              key={`${item.factor}-${index}`}
              className="p-3.5 rounded-lg bg-cyber-surface/70 border border-cyber-border hover:border-cyber-borderLight transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
            >
              {/* Rank & Title */}
              <div className="flex items-start space-x-3 flex-1 overflow-hidden">
                <span className="font-mono text-sm font-extrabold text-cyber-cyan/80 shrink-0 mt-0.5">
                  {rank}
                </span>
                <div className="overflow-hidden">
                  <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {item.factor}
                    </span>
                    <Badge variant="severity" severity={item.severity} size="sm" />
                    <span className="text-[10px] font-mono uppercase bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
                      {item.category}
                    </span>
                  </div>
                  {item.evidence && (
                    <div className="mt-1 flex items-start space-x-1.5 text-slate-400 text-xs">
                      <FileSearch className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" />
                      <span className="font-mono text-[11px] text-slate-300 break-all leading-tight">
                        {item.evidence}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Point Contribution & Source Tag */}
              <div className="flex sm:flex-col items-center sm:items-end justify-between w-full sm:w-auto shrink-0 pl-7 sm:pl-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-cyber-border/40">
                <span className="font-mono text-sm font-extrabold text-red-400 bg-red-950/40 border border-red-500/30 px-2 py-0.5 rounded shadow-[0_0_8px_rgba(239,68,68,0.2)]">
                  +{pts} pts
                </span>
                <span className="text-[9px] font-mono text-slate-500 uppercase mt-1">
                  SRC: {item.source || 'RULE'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
};
