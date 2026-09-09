import React, { useState } from 'react';
import { Activity, ShieldCheck, AlertCircle } from 'lucide-react';

export const ThreatTimeline: React.FC = () => {
  const [timeRange, setTimeRange] = useState<'24h' | '7d'>('24h');

  // Synthetic 24h threat bucket data
  const data24h = [
    { time: '00:00', total: 45, threat: 2 },
    { time: '02:00', total: 32, threat: 1 },
    { time: '04:00', total: 28, threat: 3 },
    { time: '06:00', total: 60, threat: 9 },
    { time: '08:00', total: 180, threat: 42 }, // Campaign surge
    { time: '10:00', total: 165, threat: 28 },
    { time: '12:00', total: 140, threat: 14 },
    { time: '14:00', total: 120, threat: 18 },
    { time: '16:00', total: 110, threat: 11 },
    { time: '18:00', total: 85, threat: 6 },
    { time: '20:00', total: 65, threat: 4 },
    { time: '22:00', total: 50, threat: 3 }
  ];

  const maxTotal = Math.max(...data24h.map(d => d.total));

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Threat Velocity & Ingestion Volume
          </h3>
        </div>
        <div className="flex items-center gap-1 bg-slate-900 p-0.5 rounded border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setTimeRange('24h')}
            className={`px-2 py-0.5 rounded ${timeRange === '24h' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400'}`}
          >
            24h
          </button>
          <button
            onClick={() => setTimeRange('7d')}
            className={`px-2 py-0.5 rounded ${timeRange === '7d' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400'}`}
          >
            7d
          </button>
        </div>
      </div>

      {/* Bar Chart Representation */}
      <div className="mt-4 pt-2">
        <div className="flex items-end justify-between gap-2 h-44 px-2">
          {data24h.map((point, idx) => {
            const totalHeight = (point.total / maxTotal) * 100;
            const threatHeight = (point.threat / point.total) * 100;
            return (
              <div key={idx} className="flex-1 flex flex-col items-center gap-1 group relative">
                {/* Tooltip on hover */}
                <div className="opacity-0 group-hover:opacity-100 transition-opacity absolute -top-12 z-20 pointer-events-none bg-slate-900 border border-slate-700 px-2 py-1 rounded text-[10px] font-mono shadow-xl whitespace-nowrap">
                  <div className="text-slate-200 font-bold">{point.time} UTC</div>
                  <div className="text-slate-400">Total: {point.total} | <span className="text-red-400 font-bold">{point.threat} Threats</span></div>
                </div>

                <div className="w-full bg-slate-800/80 rounded-t-sm flex flex-col justify-end overflow-hidden h-36 border-t border-slate-700/50">
                  <div
                    className="w-full bg-slate-700/40 relative flex flex-col justify-end"
                    style={{ height: `${totalHeight}%` }}
                  >
                    <div
                      className="w-full bg-threat-critical/80 shadow-glow-critical rounded-t-sm"
                      style={{ height: `${threatHeight}%` }}
                    />
                  </div>
                </div>
                <span className="text-[10px] font-mono text-slate-400 group-hover:text-slate-200 transition-colors">
                  {point.time}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono text-slate-400">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-slate-700" />
            <span>Benign Traffic</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-threat-critical" />
            <span>Malicious / Phishing Spikes</span>
          </div>
        </div>
        <div className="text-cyan-400 flex items-center gap-1">
          <AlertCircle className="w-3.5 h-3.5" />
          <span>Campaign Surge Detected @ 08:00 UTC</span>
        </div>
      </div>
    </div>
  );
};
