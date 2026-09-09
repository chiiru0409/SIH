import React from 'react';
import { RelayHop } from '../../types/email';
import { Route, Server, AlertTriangle, ArrowRight, Clock, Globe } from 'lucide-react';
import { Badge } from '../common/Badge';

interface HeaderForensicsProps {
  relayHops: RelayHop[];
  originatingIp: string;
}

export const HeaderForensics: React.FC<HeaderForensicsProps> = ({
  relayHops,
  originatingIp
}) => {
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
          Total Hops: <span className="text-cyan-400 font-bold">{relayHops.length}</span> | Origin IP: <span className="text-slate-200">{originatingIp}</span>
        </span>
      </div>

      {/* Hop Trace Timeline */}
      <div className="space-y-3">
        {relayHops.map((hop, idx) => {
          const isLast = idx === relayHops.length - 1;
          const isOrigin = hop.hopNumber === 1;

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
                      {hop.hopNumber}
                    </div>

                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-bold text-slate-200">
                          {hop.fromHost}
                        </span>
                        <ArrowRight className="w-3 h-3 text-slate-400" />
                        <span className="text-xs font-mono text-slate-300">
                          {hop.byHost}
                        </span>

                        {hop.isSuspicious && (
                          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.2 rounded bg-red-500/20 text-red-400 border border-red-500/40 font-bold">
                            <AlertTriangle className="w-2.5 h-2.5" />
                            <span>ANOMALOUS RELAY</span>
                          </span>
                        )}

                        {isOrigin && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold">
                            ORIGIN HOP
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-3 mt-1 text-[11px] font-mono text-slate-400">
                        <span>IP: <span className="text-cyan-400">{hop.fromIp}</span></span>
                        <span>•</span>
                        <span>Delay: <span className="text-slate-200">{hop.delaySeconds}s</span></span>
                        <span>•</span>
                        <span>Time: {new Date(hop.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  </div>

                  {hop.anomalyReason && (
                    <div className="text-[11px] font-mono text-red-400 bg-red-950/40 px-2.5 py-1 rounded border border-red-900/50 max-w-xs self-start sm:self-center">
                      {hop.anomalyReason}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
