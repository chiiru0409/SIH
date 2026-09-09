import React, { useState } from 'react';
import { Database, Search, ShieldAlert, Globe, Server, Link2, FileCode, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { ThreatIoc, IocType } from '../../types/intelligence';
import { Badge } from '../common/Badge';
import { RiskGauge } from '../common/RiskGauge';
import { Modal } from '../common/Modal';

export const IocDatabase: React.FC = () => {
  const { intelligence, selectAndInvestigate } = useInvestigation();
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');
  const [activeIoc, setActiveIoc] = useState<ThreatIoc | null>(null);

  const filteredIocs = intelligence.filter(ioc => {
    const matchesType = selectedType === 'ALL' || ioc.type === selectedType;
    const matchesSearch =
      search === '' ||
      ioc.value.toLowerCase().includes(search.toLowerCase()) ||
      ioc.threatCategory.toLowerCase().includes(search.toLowerCase());
    return matchesType && matchesSearch;
  });

  const getIocIcon = (type: IocType) => {
    switch (type) {
      case 'IP':
        return Server;
      case 'DOMAIN':
        return Globe;
      case 'URL':
        return Link2;
      case 'FILE_HASH_SHA256':
        return FileCode;
      default:
        return Database;
    }
  };

  return (
    <div className="space-y-4">
      {/* Search & Filter Header */}
      <div className="p-4 bg-cyber-panel border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Threat Intelligence Indicators of Compromise (IOC)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time reputation feeds, multi-engine consensus, and ASN/WHOIS intelligence
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IOC value or type..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs font-mono bg-slate-900 border border-slate-700 rounded focus:border-cyan-500 text-slate-200 outline-none"
            />
          </div>
        </div>
      </div>

      {/* Type Filter Buttons */}
      <div className="flex items-center gap-2 text-xs font-mono">
        <span className="text-slate-400">Filter Type:</span>
        {['ALL', 'IP', 'DOMAIN', 'URL', 'FILE_HASH_SHA256'].map(t => (
          <button
            key={t}
            onClick={() => setSelectedType(t)}
            className={`px-2.5 py-1 rounded transition-colors ${
              selectedType === t
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            {t === 'FILE_HASH_SHA256' ? 'SHA-256 HASH' : t}
          </button>
        ))}
      </div>

      {/* IOC Table */}
      <div className="bg-cyber-panel border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto cyber-scrollbar">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-cyber-slate/40 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Risk & Status</th>
                <th className="py-3 px-4">Indicator (Defanged)</th>
                <th className="py-3 px-4">Type & Category</th>
                <th className="py-3 px-4">Engine Consensus</th>
                <th className="py-3 px-4">Associated Cases</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredIocs.map(ioc => {
                const Icon = getIocIcon(ioc.type);
                const isMalicious = ioc.status === 'KNOWN_MALICIOUS';

                return (
                  <tr
                    key={ioc.id}
                    onClick={() => setActiveIoc(ioc)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <RiskGauge score={ioc.riskScore} size="sm" />
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            isMalicious
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : ioc.status === 'SUSPICIOUS'
                              ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                          }`}
                        >
                          {ioc.status}
                        </span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="font-bold text-cyan-300 break-all max-w-sm">
                        {ioc.defangedValue}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <Icon className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="font-semibold">{ioc.type}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{ioc.threatCategory}</div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="text-slate-300">
                        {ioc.detectionEngines[0]?.verdict || 'Feed Validated'}
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {ioc.detectionEngines.length} Feeds Synced
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1 flex-wrap">
                        {ioc.associatedCases.map(cId => (
                          <span
                            key={cId}
                            onClick={e => {
                              e.stopPropagation();
                              selectAndInvestigate(cId);
                            }}
                            className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-700 text-cyan-400 hover:border-cyan-400 font-bold"
                          >
                            {cId}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          setActiveIoc(ioc);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 text-slate-200 hover:bg-slate-700 hover:text-cyan-400 font-semibold transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {activeIoc && (
        <Modal
          isOpen={!!activeIoc}
          onClose={() => setActiveIoc(null)}
          title={`IOC Forensic Deep-Dive: ${activeIoc.defangedValue}`}
          subtitle={`Threat Type: ${activeIoc.type} • Calculated Risk: ${activeIoc.riskScore}/100`}
          maxWidth="4xl"
        >
          <div className="space-y-4 font-mono text-xs">
            {/* Detection Engines List */}
            <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-2">
              <div className="text-cyan-400 font-bold uppercase text-[11px]">
                Multi-Vendor Detection Engine Consensus
              </div>
              <div className="space-y-1.5">
                {activeIoc.detectionEngines.map((eng, idx) => (
                  <div key={idx} className="flex justify-between items-center py-1 border-b border-slate-800/60 last:border-0">
                    <span className="text-slate-300 font-semibold">{eng.engineName}</span>
                    <span className="text-red-400 font-bold">{eng.verdict}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* WHOIS or ASN details if available */}
            {activeIoc.whois && (
              <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="text-cyan-400 font-bold uppercase text-[11px]">WHOIS Registration Telemetry</div>
                <div className="flex justify-between"><span className="text-slate-400">Registrar:</span><span className="text-slate-200">{activeIoc.whois.registrar}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Created:</span><span className="text-red-400 font-bold">{activeIoc.whois.creationDate}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Registrant Org:</span><span className="text-slate-200">{activeIoc.whois.registrantOrg}</span></div>
              </div>
            )}

            {activeIoc.asnDetails && (
              <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="text-cyan-400 font-bold uppercase text-[11px]">BGP Routing & ASN Network</div>
                <div className="flex justify-between"><span className="text-slate-400">ASN:</span><span className="text-cyan-300 font-bold">{activeIoc.asnDetails.asn}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Organization:</span><span className="text-slate-200">{activeIoc.asnDetails.org}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Subnet CIDR:</span><span className="text-slate-300">{activeIoc.asnDetails.cidr}</span></div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
