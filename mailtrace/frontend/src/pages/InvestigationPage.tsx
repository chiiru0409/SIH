import React, { useState } from 'react';
import { useInvestigation } from '../context/InvestigationContext';
import { CaseHeader } from '../components/investigation/CaseHeader';
import { VerdictSummary } from '../components/investigation/VerdictSummary';
import { WhySuspicious } from '../components/investigation/WhySuspicious';
import { RiskBreakdown } from '../components/investigation/RiskBreakdown';
import { EmailBodyPreview } from '../components/investigation/EmailBodyPreview';
import { AuthIntelligence } from '../components/investigation/AuthIntelligence';
import { IdentityAnalysis } from '../components/investigation/IdentityAnalysis';
import { HeaderForensics } from '../components/investigation/HeaderForensics';
import { UrlIntelligence } from '../components/investigation/UrlIntelligence';
import { InfrastructureGeo } from '../components/investigation/InfrastructureGeo';
import { BehavioralContext } from '../components/investigation/BehavioralContext';
import { CampaignCorrelationSection } from '../components/investigation/CampaignCorrelationSection';
import { InvestigationGraph } from '../components/graph/InvestigationGraph';
import { ResponsePlaybook } from '../components/investigation/ResponsePlaybook';
import { InvestigationEvidenceSnippet } from '../components/investigation/InvestigationEvidenceSnippet';
import { ShieldAlert, Route, Crosshair, Layers } from 'lucide-react';

export const InvestigationPage: React.FC = () => {
  const { activeCase, activeEmail, setActiveTab } = useInvestigation();
  const [activeStage, setActiveStage] = useState<'DETECT' | 'TRACE' | 'INVESTIGATE' | 'ALL'>('ALL');

  if (!activeCase || !activeEmail) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono">
        No case currently selected for forensic investigation.
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

  return (
    <div className="space-y-6">
      {/* 1. Case Header with Quick Actions */}
      <CaseHeader
        investigationCase={activeCase}
        onOpenReport={() => setActiveTab('reports')}
        onOpenEvidence={() => setActiveTab('evidence')}
      />

      {/* 2. Core Triad Navigation Tabs (DETECT -> TRACE -> INVESTIGATE) */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveStage('DETECT')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md font-mono text-xs font-bold transition-all ${
              activeStage === 'DETECT'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-glow-accent'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 bg-slate-900/80 border border-slate-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
            <span>🔵 1. DETECT (AI Threat & Intent)</span>
          </button>

          <button
            onClick={() => setActiveStage('TRACE')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md font-mono text-xs font-bold transition-all ${
              activeStage === 'TRACE'
                ? 'bg-orange-500/20 text-orange-300 border border-orange-500/50 shadow-glow-high'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 bg-slate-900/80 border border-slate-800'
            }`}
          >
            <Route className="w-3.5 h-3.5 text-orange-400" />
            <span>🟠 2. TRACE (Routing & GeoIP)</span>
          </button>

          <button
            onClick={() => setActiveStage('INVESTIGATE')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md font-mono text-xs font-bold transition-all ${
              activeStage === 'INVESTIGATE'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-glow-critical'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 bg-slate-900/80 border border-slate-800'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5 text-purple-400" />
            <span>🟣 3. INVESTIGATE (Graph & Evidence)</span>
          </button>
        </div>

        <button
          onClick={() => setActiveStage('ALL')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-mono text-xs transition-colors ${
            activeStage === 'ALL'
              ? 'bg-slate-800 text-slate-100 font-bold border border-slate-700'
              : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Complete Dossier (All Stages)</span>
        </button>
      </div>

      {/* ========================================================= */}
      {/* 🔵 STAGE 1: DETECT (Threat Intent & Risk Findings)        */}
      {/* ========================================================= */}
      {(activeStage === 'DETECT' || activeStage === 'ALL') && (
        <section className="space-y-6">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Stage 01: AI Threat Detection & Mathematical Risk Scoring</span>
          </div>

          <VerdictSummary verdict={activeCase.verdict} />

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7">
              <WhySuspicious findings={findingsList} />
            </div>
            <div className="lg:col-span-5">
              <RiskBreakdown breakdown={riskBreakdownData} />
            </div>
          </div>

          <EmailBodyPreview email={activeEmail} />
        </section>
      )}

      {/* ========================================================= */}
      {/* 🟠 STAGE 2: TRACE (Infrastructure & Routing Forensics)    */}
      {/* ========================================================= */}
      {(activeStage === 'TRACE' || activeStage === 'ALL') && (
        <section className="space-y-6">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-orange-400 uppercase tracking-wider pt-4 border-t border-slate-800/80">
            <span className="w-2 h-2 rounded-full bg-orange-400 animate-pulse" />
            <span>Stage 02: Reverse-Hop SMTP Routing, Authentication & Infrastructure Geolocation</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-6">
              <AuthIntelligence auth={authResults} />
            </div>
            <div className="lg:col-span-6">
              <IdentityAnalysis email={activeEmail} investigationCase={activeCase} />
            </div>
          </div>

          <HeaderForensics
            relayHops={relayHopsList}
            originatingIp={activeEmail.headers?.originatingIp || infraData.originatingIp || '185.220.101.42'}
          />

          <UrlIntelligence urls={extractedUrlsList} />

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
        </section>
      )}

      {/* ========================================================= */}
      {/* 🟣 STAGE 3: INVESTIGATE (Correlation, Response & Evidence) */}
      {/* ========================================================= */}
      {(activeStage === 'INVESTIGATE' || activeStage === 'ALL') && (
        <section className="space-y-6">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-400 uppercase tracking-wider pt-4 border-t border-slate-800/80">
            <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
            <span>Stage 03: Multi-Case Correlation Graph, Behavioral Baseline, Mitigation & Evidence Proof</span>
          </div>

          <BehavioralContext context={behavioralData} />

          <CampaignCorrelationSection investigationCase={activeCase} />

          {/* Embedded Interactive Correlation Subgraph */}
          <div className="space-y-2">
            <div className="text-xs font-mono font-bold text-slate-300">
              Interactive Infrastructure Correlation Subgraph
            </div>
            <InvestigationGraph />
          </div>

          <ResponsePlaybook investigationCase={activeCase} />

          <InvestigationEvidenceSnippet investigationCase={activeCase} />
        </section>
      )}
    </div>
  );
};
