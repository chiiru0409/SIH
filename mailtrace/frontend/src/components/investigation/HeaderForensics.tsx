import React from 'react';
import { RelayHop } from '../../types/email';
import { Route } from 'lucide-react';

interface HeaderForensicsProps {
  relayHops?: RelayHop[];
  originatingIp?: string;
}

export const HeaderForensics: React.FC<HeaderForensicsProps> = ({
  relayHops = [],
  originatingIp = '185.220.101.42'
}) => {
  const safeHops = Array.isArray(relayHops) ? relayHops : [];

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Route className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            SMTP Relay Hop & Header Forensics Path
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Total Hops: <span className="text-cyan-400 font-bold">{safeHops.length}</span> | Origin IP: <span className="text-slate-200">{originatingIp}</span>
        </span>
      </div>

      {/* Hop Trace Timeline */}
      <div className="space-y-3">
        {safeHops.length === 0 ? (
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400 text-center">
            No Received hops extracted from header. Direct origin IP: {originatingIp}
          </div>
        ) : (
          safeHops.map((hop, idx) => {
            const isLast = idx === safeHops.length - 1;
            const isOrigin = hop.hopNumber === 1 || idx === 0;

            return (
              <div key={idx} className="relative">
                {!isLast && (
                  <div className="absolute left-4 top-10 bottom-0 w-0.5 bg-slate-800" />
                )}

                <div
                  className={`p-4 rounded-lg border transition-colors ${
                    hop.isSuspicious
                      ? 'bg-red-950/20 border-red-500/40 shadow-glow-critical'
                      : isOrigin
                      ? 'bg-cyan-950/20 border-cyan-500/40'
                      : 'bg-slate-900 border-slate-800'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-8 h-8 rounded-full flex items-center justify-center font-mono text-xs font-bold ${
                          hop.isSuspicious
                            ? 'bg-red-500/20 text-red-400 border border-red-500/50'
                            : isOrigin
                            ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}
                      >
                        #{hop.hopNumber || (idx + 1)}
                      </div>

                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-slate-200">
                            {hop.fromHost || 'unknown-from-host'}
                          </span>
                          <span className="text-slate-500 font-mono text-xs">→</span>
                          <span className="font-mono text-xs text-slate-300">
                            {hop.byHost || 'destination-mx'}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400 mt-0.5">
                          IP: <span className="text-cyan-300">{hop.fromIp || '0.0.0.0'}</span>
                          {hop.asn && <span className="ml-2 text-slate-500">({hop.asn})</span>}
                          {hop.city && <span className="ml-2 text-slate-500">[{hop.city}, {hop.country}]</span>}
                        </div>
                      </div>
                    </div>

                    <div className="text-right font-mono text-[11px]">
                      <div className="text-slate-300">{hop.timestamp || 'Timestamp recorded'}</div>
                      {hop.isSuspicious && (
                        <span className="text-red-400 text-[10px] font-bold">
                          {hop.suspiciousReason || hop.anomalyReason || 'ANOMALOUS HOP'}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
