import React, { useState } from 'react';
import { 
  Compass, 
  Globe, 
  Server, 
  Link as LinkIcon, 
  FileCode, 
  Clock, 
  ShieldCheck, 
  AlertCircle 
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Tabs } from '../ui/Tabs';
import { defangUrl, defangIp } from '../../lib/sanitize';
import { formatDate } from '../../lib/utils';
import type { InfrastructureIntelligenceResult } from '../../types/api';

export interface InfrastructurePanelProps {
  infrastructure?: InfrastructureIntelligenceResult | null;
  className?: string;
}

export const InfrastructurePanel: React.FC<InfrastructurePanelProps> = ({
  infrastructure,
  className,
}) => {
  const [activeTab, setActiveTab] = useState<'ips' | 'domains' | 'urls'>('ips');

  if (!infrastructure) {
    return (
      <Card title="INFRASTRUCTURE INTELLIGENCE" className={className}>
        <div className="py-8 text-center text-xs font-mono text-slate-500">
          INFRASTRUCTURE INTELLIGENCE NOT AVAILABLE
        </div>
      </Card>
    );
  }

  const ips = infrastructure.ips || [];
  const domains = infrastructure.domains || [];
  const urls = infrastructure.urls || [];

  const tabs = [
    { id: 'ips', label: 'IP Intelligence', count: ips.length, icon: <Server className="w-3.5 h-3.5" /> },
    { id: 'domains', label: 'Domain & RDAP', count: domains.length, icon: <Globe className="w-3.5 h-3.5" /> },
    { id: 'urls', label: 'URL Structure & Hashes', count: urls.length, icon: <LinkIcon className="w-3.5 h-3.5" /> },
  ];

  return (
    <Card
      title="INFRASTRUCTURE INTELLIGENCE ENRICHMENT"
      subtitle="Autonomous GeoIP, ASN BGP routing, RDAP domain registration, and URL structure analysis"
      icon={<Compass className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-6">
        
        {/* Navigation Tabs */}
        <Tabs
          tabs={tabs}
          activeTab={activeTab}
          onChange={(tab) => setActiveTab(tab as any)}
          variant="pills"
        />

        {/* 1. IP INTELLIGENCE TAB */}
        {activeTab === 'ips' && (
          <div className="space-y-3">
            {ips.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                No IP indicators extracted from this email.
              </div>
            ) : (
              ips.map((ipRec, idx) => (
                <div
                  key={`ip-${ipRec.ip}-${idx}`}
                  className="p-4 rounded-lg bg-cyber-surface border border-cyber-border space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-cyber-border/40">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-sm font-bold text-cyber-cyan">
                        {defangIp(ipRec.ip)}
                      </span>
                      <span className="px-2 py-0.2 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                        IPv{ipRec.version} • {ipRec.classification || 'PUBLIC'}
                      </span>
                    </div>

                    <div className="text-[11px] font-mono text-slate-400">
                      SRC: {ipRec.source || 'LOCAL_DB'}
                    </div>
                  </div>

                  {/* IP Fields Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Location:</span>
                      <span className="text-slate-200">
                        {ipRec.geo?.city ? `${ipRec.geo.city}, ` : ''}
                        {ipRec.geo?.country || 'UNAVAILABLE'}
                      </span>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Autonomous System (ASN):</span>
                      <span className="text-slate-200 font-bold">
                        {ipRec.asn?.asn || 'UNAVAILABLE'}
                      </span>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Organization:</span>
                      <span className="text-slate-200 truncate block" title={ipRec.asn?.organization || ''}>
                        {ipRec.asn?.organization || 'UNAVAILABLE'}
                      </span>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">BGP Network CIDR:</span>
                      <span className="text-slate-200">
                        {ipRec.asn?.network || 'UNAVAILABLE'}
                      </span>
                    </div>
                  </div>

                </div>
              ))
            )}
          </div>
        )}

        {/* 2. DOMAIN & RDAP TAB */}
        {activeTab === 'domains' && (
          <div className="space-y-3">
            {domains.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                No domain indicators extracted from this email.
              </div>
            ) : (
              domains.map((dom, idx) => {
                const rdap = dom.rdap || {};
                return (
                  <div
                    key={`dom-${dom.domain}-${idx}`}
                    className="p-4 rounded-lg bg-cyber-surface border border-cyber-border space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-cyber-border/40">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-sm font-bold text-slate-100">
                          {dom.domain}
                        </span>
                        {dom.registrable_domain !== dom.domain && (
                          <span className="px-2 py-0.2 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
                            Parent: {dom.registrable_domain}
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] font-mono text-slate-400">
                        TLD: {dom.tld || 'UNAVAILABLE'}
                      </div>
                    </div>

                    {/* RDAP Fields */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                      <div>
                        <span className="text-slate-500 text-[10px] uppercase block">Registrar:</span>
                        <span className="text-slate-200 truncate block">
                          {rdap.registrar || 'UNAVAILABLE'}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-500 text-[10px] uppercase block">Created Date:</span>
                        <span className="text-slate-200">
                          {formatDate(rdap.creation_date)}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-500 text-[10px] uppercase block">Updated Date:</span>
                        <span className="text-slate-200">
                          {formatDate(rdap.updated_date)}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-500 text-[10px] uppercase block">Expiration Date:</span>
                        <span className="text-slate-200">
                          {formatDate(rdap.expiration_date)}
                        </span>
                      </div>
                    </div>

                    {rdap.nameservers && rdap.nameservers.length > 0 && (
                      <div className="pt-2 border-t border-cyber-border/30 text-[10px] font-mono text-slate-400">
                        <span className="text-slate-500">Nameservers: </span>
                        {rdap.nameservers.join(', ')}
                      </div>
                    )}

                  </div>
                );
              })
            )}
          </div>
        )}

        {/* 3. URL STRUCTURE & HASHES TAB */}
        {activeTab === 'urls' && (
          <div className="space-y-3">
            {urls.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                No URLs identified in email body or HTML payload.
              </div>
            ) : (
              urls.map((u, idx) => (
                <div
                  key={`url-${u.url_hash || idx}`}
                  className="p-4 rounded-lg bg-cyber-surface border border-cyber-border space-y-2.5"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1 overflow-hidden">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                        DEFANGED URL
                      </span>
                      <div className="font-mono text-xs font-bold text-cyan-300 break-all select-all">
                        {defangUrl(u.url)}
                      </div>
                    </div>
                    <span className="font-mono text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded shrink-0">
                      {u.scheme ? u.scheme.toUpperCase() : 'HTTP'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-cyber-border/40 text-[11px] font-mono">
                    <div>
                      <span className="text-slate-500 text-[10px] block">Hostname:</span>
                      <span className="text-slate-200 break-all">{u.hostname || 'UNAVAILABLE'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">Path:</span>
                      <span className="text-slate-200 break-all">{u.path || '/'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">URL SHA-256 Hash:</span>
                      <span className="text-slate-400 text-[10px] break-all">{u.url_hash || 'UNAVAILABLE'}</span>
                    </div>
                  </div>

                  {u.indicators && u.indicators.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {u.indicators.map((ind, i) => (
                        <span
                          key={`ind-${i}`}
                          className="px-2 py-0.2 rounded bg-amber-950/40 border border-amber-500/30 text-amber-400 font-mono text-[10px]"
                        >
                          {ind}
                        </span>
                      ))}
                    </div>
                  )}

                </div>
              ))
            )}
          </div>
        )}

      </div>
    </Card>
  );
};
