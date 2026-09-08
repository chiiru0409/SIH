import React from 'react';
import { GitCommit, Server, ArrowDown, Shield, Globe, Clock, Network } from 'lucide-react';
import { Card } from '../ui/Card';
import { formatDate } from '../../lib/utils';
import type { SMTPTrace, ReceivedHop } from '../../types/api';

export interface RelayTimelineProps {
  smtpTrace?: SMTPTrace | null;
  className?: string;
}

export const RelayTimeline: React.FC<RelayTimelineProps> = ({ smtpTrace, className }) => {
  if (!smtpTrace || !smtpTrace.received_chain || smtpTrace.received_chain.length === 0) {
    return (
      <Card title="SMTP RELAY & RECEIVED HEADER TIMELINE" className={className}>
        <div className="py-6 text-center text-xs font-mono text-slate-500">
          NO RECEIVED HEADERS DETECTED (SINGLE HOP OR DIRECT INGEST)
        </div>
      </Card>
    );
  }

  const hops = smtpTrace.received_chain;
  const earliestNode = smtpTrace.earliest_node;

  return (
    <Card
      title="SMTP RELAY & RECEIVED HEADER TIMELINE"
      subtitle={`Chronological hop-by-hop message routing trace (${hops.length} hops)`}
      icon={<Network className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-6">
        
        {/* Hop Count & Summary Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-cyber-surface rounded-lg border border-cyber-border text-xs font-mono">
          <div className="flex items-center space-x-3">
            <span className="text-slate-400">TOTAL HOPS:</span>
            <span className="font-bold text-cyber-cyan">{smtpTrace.hop_count}</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">PUBLIC RELAY IPS:</span>
            <span className="font-bold text-slate-200">
              {smtpTrace.public_ips && smtpTrace.public_ips.length > 0
                ? smtpTrace.public_ips.join(', ')
                : 'None detected'}
            </span>
          </div>

          <div className="text-[10px] text-slate-500 italic">
            Chronological order (Earliest Ingress → Final Destination)
          </div>
        </div>

        {/* Timeline Hops List */}
        <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-cyber-border">
          {hops.map((hop, index) => {
            const isEarliest = earliestNode && (earliestNode.ip === hop.ip || index === hops.length - 1);
            const hopNumber = index + 1;

            return (
              <div key={`hop-${index}`} className="relative group">
                
                {/* Timeline node icon */}
                <div
                  className={`absolute -left-6 top-1.5 w-5 h-5 rounded-full border-2 flex items-center justify-center transition-all ${
                    isEarliest
                      ? 'bg-amber-950 border-amber-400 text-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.5)]'
                      : hop.is_private
                      ? 'bg-slate-900 border-slate-600 text-slate-400'
                      : 'bg-cyan-950 border-cyan-400 text-cyan-400'
                  }`}
                >
                  <span className="text-[9px] font-mono font-extrabold">{hopNumber}</span>
                </div>

                {/* Hop Details Box */}
                <div
                  className={`p-4 rounded-lg border transition-all ${
                    isEarliest
                      ? 'bg-amber-950/20 border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.08)]'
                      : 'bg-cyber-surface/70 border-cyber-border hover:border-cyber-borderLight'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-cyber-border/40">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-slate-200">
                        HOP {String(hopNumber).padStart(2, '0')}
                      </span>
                      {isEarliest ? (
                        <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-500/40 text-amber-400 font-mono text-[10px] font-bold">
                          EARLIEST OBSERVED SENDING INFRASTRUCTURE
                        </span>
                      ) : (
                        <span
                          className={`px-2 py-0.2 rounded font-mono text-[10px] ${
                            hop.is_private
                              ? 'bg-slate-800 text-slate-400'
                              : 'bg-cyan-950/50 text-cyan-400 border border-cyan-500/30'
                          }`}
                        >
                          {hop.is_private ? 'PRIVATE RFC1918' : 'PUBLIC INTERNET'}
                        </span>
                      )}
                    </div>

                    {hop.timestamp && (
                      <div className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-400">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{formatDate(hop.timestamp)}</span>
                      </div>
                    )}
                  </div>

                  {/* Hop Content */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-3 text-xs font-mono">
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Transmitting Host (From):</span>
                      <span className="text-slate-200 break-all">{hop.from || 'UNSPECIFIED'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Receiving MTA (By):</span>
                      <span className="text-slate-200 break-all">{hop.by || 'UNSPECIFIED'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Originating IP:</span>
                      <span className="font-bold text-cyber-cyan break-all">
                        {hop.ip || 'NOT EXTRACTABLE'}
                      </span>
                    </div>
                  </div>

                  {/* Raw header preview toggle on hover/collapsible */}
                  {hop.raw && (
                    <div className="mt-2.5 pt-2 border-t border-cyber-border/30 text-[10px] font-mono text-slate-500 truncate">
                      <span className="text-slate-400">RAW: </span>
                      {hop.raw}
                    </div>
                  )}

                </div>
              </div>
            );
          })}
        </div>

      </div>
    </Card>
  );
};
