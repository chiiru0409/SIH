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

  const extractedUrlsList = activeEmail.extractedUrls || activeEmail.urls || [];
  const relayHopsList = activeEmail.relayHops || (activeEmail.headers?.receivedHops as any) || [];
  const findingsList = activeCase.explainableFindings || activeCase.findings || [];
  const authResults = activeEmail.authenticationResults || activeEmail.auth || {
    overallAlignment: false,
    spf: { status: 'NONE' as any, domain: 'unknown', aligned: false, details: 'No SPF' },
    dkim: { status: 'NONE' as any, domain: 'unknown', selector: 's1', aligned: false, details: 'No DKIM' },
    dmarc: { status: 'NONE' as any, policy: 'none' as any, aligned: false, details: 'No DMARC' }
  };
  const infraData = activeEmail.infrastructure || {
    originatingIp: activeEmail.headers?.originatingIp || '185.220.101.42',
    originatingAsn: 'AS49505',
    originatingOrg: 'Hosting Infrastructure',
    originatingCountry: 'Netherlands',
    originatingCity: 'Amsterdam',
    originatingLatitude: 52.3702,
    originatingLongitude: 4.8952,
    isProxyOrTor: true
  };
  const behavioralData = activeCase.behavioralContext || activeCase.behavioral || {
    senderFamiliarity: 'NONE',
    firstTimeSender: true,
    isFirstTimeSender: true,
    previousCommunicationCount: 0,
    historicalEmailCount: 0,
    firstSeenTimestamp: new Date().toISOString(),
    relationshipTier: 'NEW',
    displayNameSimilarityScore: 0,
    executiveTarget: false
  };

  const riskBreakdownData = activeCase.verdict?.riskScoreBreakdown || activeCase.riskBreakdown || {
    authentication: 20,
    identity: 15,
    identitySpoofing: 15,
    urlIntelligence: 20,
    urlAndPayload: 20,
    linguisticSignals: 15,
    linguisticIntent: 15,
    infrastructure: 10,
    infrastructureGeo: 10,
    behavior: 5,
    behavioralAnomaly: 5,
    correlation: 5,
    totalScore: activeCase.verdict?.riskScore || 75,
    topContributors: ['Authentication Alignment', 'External Links']
  };

  const forensicTabs = [
    { id: 'auth', label: 'Auth & Alignment', icon: ShieldCheck },
    { id: 'relay', label: 'SMTP Relay Trace', icon: Route },
    { id: 'urls', label: `URL Intel (${extractedUrlsList.length})`, icon: Link2 },
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
          <WhySuspicious findings={findingsList} />
        </div>
        <div className="lg:col-span-5">
          <RiskBreakdown breakdown={riskBreakdownData} />
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
          <AuthIntelligence auth={authResults} />
        )}

        {activeForensicTab === 'relay' && (
          <HeaderForensics
            relayHops={relayHopsList}
            originatingIp={activeEmail.headers?.originatingIp || infraData.originatingIp || '185.220.101.42'}
          />
        )}

        {activeForensicTab === 'urls' && (
          <UrlIntelligence urls={extractedUrlsList} />
        )}

        {activeForensicTab === 'geo' && (
          <InfrastructureGeo
            ip={infraData.originatingIp || activeEmail.headers?.originatingIp || '185.220.101.42'}
            asn={infraData.originatingAsn}
            org={infraData.originatingOrg}
            country={infraData.originatingCountry}
            city={infraData.originatingCity}
            latitude={infraData.originatingLatitude}
            longitude={infraData.originatingLongitude}
            isProxyOrTor={infraData.isProxyOrTor}
          />
        )}

        {activeForensicTab === 'behavior' && (
          <BehavioralContext context={behavioralData} />
        )}
      </div>
    </div>
  );
};
