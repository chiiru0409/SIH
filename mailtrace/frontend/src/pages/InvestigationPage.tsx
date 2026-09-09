import React, { useState } from 'react';
import { useInvestigation } from '../context/InvestigationContext';
import { CaseHeader } from '../components/investigation/CaseHeader';
import { VerdictSummary } from '../components/investigation/VerdictSummary';
import { WhySuspicious } from '../components/investigation/WhySuspicious';
import { RiskBreakdown } from '../components/investigation/RiskBreakdown';
import { AuthIntelligence } from '../components/investigation/AuthIntelligence';
import { HeaderForensics } from '../components/investigation/HeaderForensics';
import { UrlIntelligence } from '../components/investigation/UrlIntelligence';
import { InfrastructureGeo } from '../components/investigation/InfrastructureGeo';
import { BehavioralContext } from '../components/investigation/BehavioralContext';
import { ShieldCheck, Route, Link2, Globe, Users } from 'lucide-react';

export const InvestigationPage: React.FC = () => {
  const { activeCase, activeEmail, setActiveTab } = useInvestigation();
  const [activeForensicTab, setActiveForensicTab] = useState<'auth' | 'relay' | 'urls' | 'geo' | 'behavior'>('auth');

  if (!activeCase || !activeEmail) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono">
        No case currently selected.
      </div>
    );
  }

  const forensicTabs = [
    { id: 'auth', label: 'Auth & Alignment', icon: ShieldCheck },
    { id: 'relay', label: 'SMTP Relay Trace', icon: Route },
    { id: 'urls', label: `URL Intel (${activeEmail.extractedUrls.length})`, icon: Link2 },
    { id: 'geo', label: 'Infrastructure & GeoIP', icon: Globe },
    { id: 'behavior', label: 'Behavior Baseline', icon: Users }
  ];

  return (
    <div className="space-y-6">
      {/* 1. Case Header with Quick Actions */}
      <CaseHeader
        investigationCase={activeCase}
        onOpenReport={() => setActiveTab('reports')}
        onOpenEvidence={() => setActiveTab('evidence')}
      />

      {/* 2. Primary Verdict Banner */}
      <VerdictSummary verdict={activeCase.verdict} />

      {/* 3. Explainable Findings & Mathematical Risk Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7">
          <WhySuspicious findings={activeCase.explainableFindings} />
        </div>
        <div className="lg:col-span-5">
          <RiskBreakdown breakdown={activeCase.verdict.riskScoreBreakdown} />
        </div>
      </div>

      {/* 4. Forensic Deep-Dive Tabs Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto cyber-scrollbar">
          {forensicTabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeForensicTab === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveForensicTab(tab.id as any)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-md font-mono text-xs font-medium whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-glow-accent'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Content Display */}
        {activeForensicTab === 'auth' && (
          <AuthIntelligence auth={activeEmail.authenticationResults} />
        )}

        {activeForensicTab === 'relay' && (
          <HeaderForensics
            relayHops={activeEmail.relayHops}
            originatingIp={activeEmail.headers.originatingIp}
          />
        )}

        {activeForensicTab === 'urls' && (
          <UrlIntelligence urls={activeEmail.extractedUrls} />
        )}

        {activeForensicTab === 'geo' && (
          <InfrastructureGeo
            ip={activeEmail.headers.originatingIp}
            asn={activeEmail.infrastructure.originatingAsn}
            org={activeEmail.infrastructure.originatingOrg}
            country={activeEmail.infrastructure.originatingCountry}
            city={activeEmail.infrastructure.originatingCity}
            latitude={activeEmail.infrastructure.originatingLatitude}
            longitude={activeEmail.infrastructure.originatingLongitude}
            isProxyOrTor={activeEmail.infrastructure.isProxyOrTor}
          />
        )}

        {activeForensicTab === 'behavior' && (
          <BehavioralContext context={activeCase.behavioralContext} />
        )}
      </div>
    </div>
  );
};
