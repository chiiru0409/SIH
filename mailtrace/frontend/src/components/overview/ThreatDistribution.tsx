import React from 'react';
import { PieChart, ShieldAlert } from 'lucide-react';

export const ThreatDistribution: React.FC = () => {
  const distribution = [
    { label: 'Credential Harvesting', count: 68, percentage: 48, color: 'bg-red-500', text: 'text-red-400' },
    { label: 'BEC / Wire Fraud', count: 32, percentage: 22, color: 'bg-orange-500', text: 'text-orange-400' },
    { label: 'Malware Dropper / Trojans', count: 24, percentage: 17, color: 'bg-amber-500', text: 'text-amber-400' },
    { label: 'QR Code (Quishing)', count: 12, percentage: 8, color: 'bg-purple-500', text: 'text-purple-400' },
    { label: 'Executive Impersonation', count: 6, percentage: 5, color: 'bg-cyan-500', text: 'text-cyan-400' }
  ];

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <PieChart className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Threat Category Breakdown
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">142 Flagged Incidents</span>
      </div>

      {/* Multi-segmented distribution bar */}
      <div className="my-4">
        <div className="h-3.5 w-full bg-slate-900 rounded-full overflow-hidden flex border border-slate-700/60 p-0.5 gap-0.5">
          {distribution.map((item, idx) => (
            <div
              key={idx}
              className={`${item.color} h-full rounded-sm transition-all duration-500`}
              style={{ width: `${item.percentage}%` }}
              title={`${item.label}: ${item.count} (${item.percentage}%)`}
            />
          ))}
        </div>
      </div>

      {/* Distribution list */}
      <div className="space-y-2.5">
        {distribution.map((item, idx) => (
          <div key={idx} className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-sm ${item.color}`} />
              <span className="text-slate-300">{item.label}</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-slate-400">{item.count} cases</span>
              <span className={`font-bold w-10 text-right ${item.text}`}>{item.percentage}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
