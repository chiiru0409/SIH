import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/layout/Header';
import { Footer } from './components/layout/Footer';
import { UploadZone } from './components/upload/UploadZone';
import { RiskScoreHero } from './components/risk/RiskScoreHero';
import { RiskFactorsList } from './components/risk/RiskFactorsList';
import { ThreatClassificationPanel } from './components/threat/ThreatClassificationPanel';
import { AuthenticationMatrix } from './components/forensic/AuthenticationMatrix';
import { IdentityInspector } from './components/forensic/IdentityInspector';
import { RelayTimeline } from './components/forensic/RelayTimeline';
import { ForensicEvidencePanel } from './components/forensic/ForensicEvidencePanel';
import { InfrastructurePanel } from './components/infrastructure/InfrastructurePanel';
import { GeoMap } from './components/infrastructure/GeoMap';
import { InvestigationGraphView } from './components/graph/InvestigationGraphView';
import { CampaignClusterView } from './components/campaign/CampaignClusterView';
import { CaseListView } from './components/cases/CaseListView';
import { CaseDetailWorkspace } from './components/cases/CaseDetailWorkspace';
import { ErrorBoundary } from './components/ui/ErrorBoundary';
import { Alert } from './components/ui/Alert';
import { 
  checkHealth, 
  checkReadiness,
  fetchCases, 
  fetchCase, 
  fetchGlobalCorrelation, 
  fetchCaseCorrelation 
} from './lib/api';
import type { 
  CaseSummary, 
  CaseDetail, 
  UploadResponse, 
  CorrelationOverviewResponse, 
  CaseCorrelationDetailResponse,
  DatabaseStatus,
} from './types/api';

export const App: React.FC = () => {
  // Navigation & View State
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [apiConnected, setApiConnected] = useState<boolean>(true);
  const [dbStatus, setDbStatus] = useState<DatabaseStatus | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Active Case Workspace State
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [activeCaseDetail, setActiveCaseDetail] = useState<CaseDetail | null>(null);
  const [activeCaseCorrelation, setActiveCaseCorrelation] = useState<CaseCorrelationDetailResponse | null>(null);

  // Data Cache State
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [globalCorrelation, setGlobalCorrelation] = useState<CorrelationOverviewResponse | null>(null);
  const [latestUpload, setLatestUpload] = useState<UploadResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Initial Health & Data Polling
  const verifyBackend = useCallback(async () => {
    try {
      const readyRes = await checkReadiness();
      setApiConnected(true);
      if (readyRes.db_info) {
        setDbStatus(readyRes.db_info);
      }
    } catch {
      try {
        const healthRes = await checkHealth();
        setApiConnected(true);
        if (healthRes.db_info) {
          setDbStatus({
            ...healthRes.db_info,
            status: 'unreachable',
            connected: false,
          });
        }
      } catch {
        setApiConnected(false);
        setDbStatus(null);
      }
    }
  }, []);

  const loadCaseList = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await fetchCases(1, 100);
      setCases(data);
      setErrorMessage(null);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to retrieve cases.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loadGlobalCorrelation = useCallback(async () => {
    try {
      const data = await fetchGlobalCorrelation();
      setGlobalCorrelation(data);
    } catch (err: any) {
      console.warn('Global correlation load warning:', err.message);
    }
  }, []);

  useEffect(() => {
    verifyBackend();
    loadCaseList();
    loadGlobalCorrelation();

    // Heartbeat every 15s
    const timer = setInterval(verifyBackend, 15000);
    return () => clearInterval(timer);
  }, [verifyBackend, loadCaseList, loadGlobalCorrelation]);

  // Load a single case for deep forensic workspace
  const handleSelectCase = async (caseId: string) => {
    try {
      setIsLoading(true);
      setActiveCaseId(caseId);
      const detail = await fetchCase(caseId);
      setActiveCaseDetail(detail);

      try {
        const corr = await fetchCaseCorrelation(caseId);
        setActiveCaseCorrelation(corr);
      } catch {
        setActiveCaseCorrelation(null);
      }

      setErrorMessage(null);
    } catch (err: any) {
      setErrorMessage(`Failed to load case ${caseId}: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetCase = () => {
    setActiveCaseId(null);
    setActiveCaseDetail(null);
    setActiveCaseCorrelation(null);
    setLatestUpload(null);
  };

  // Called when upload succeeds (background refresh of lists)
  const handleUploadSuccess = async (_uploadRes: UploadResponse) => {
    await loadCaseList();
    await loadGlobalCorrelation();
  };

  // Called when user clicks "Inspect Full Investigation"
  const handleUploadComplete = async (uploadRes: UploadResponse) => {
    setLatestUpload(uploadRes);
    await loadCaseList();
    await loadGlobalCorrelation();
    await handleSelectCase(uploadRes.case_id);
  };

  return (
    <div className="min-h-screen flex flex-col bg-cyber-bg text-cyber-text">
      
      {/* Top Cyber Navigation Bar */}
      <Header
        activeTab={activeTab}
        onTabChange={(tab) => {
          setActiveTab(tab);
          if (tab === 'cases') {
            loadCaseList();
          } else if (tab === 'graph' || tab === 'campaigns') {
            loadGlobalCorrelation();
          }
        }}
        apiConnected={apiConnected}
        dbStatus={dbStatus}
        activeCaseId={activeCaseId}
        onResetCase={handleResetCase}
      />

      {/* Main Investigation Workspace Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Global Error Banner */}
        {errorMessage && (
          <div className="mb-6">
            <Alert variant="error" title="Investigation Engine Error">
              {errorMessage}
            </Alert>
          </div>
        )}

        {/* API Offline Warning */}
        {!apiConnected && (
          <div className="mb-6">
            <Alert variant="warning" title="Backend Connection Offline">
              <span>The MailTrace backend API service is unreachable. Ensure the backend service is running and properly connected.</span>
            </Alert>
          </div>
        )}

        {/* VIEW 1: ACTIVE CASE DETAIL DEEP-DIVE (If a case is loaded) */}
        {activeCaseDetail ? (
          <ErrorBoundary
            fallbackTitle="INVESTIGATION WORKSPACE ERROR"
            onReset={handleResetCase}
          >
            <CaseDetailWorkspace
              caseData={activeCaseDetail}
              correlationData={activeCaseCorrelation}
              onBack={() => handleResetCase()}
              onSelectRelatedCase={(relatedId) => handleSelectCase(relatedId)}
            />
          </ErrorBoundary>
        ) : (
          /* TAB ROUTING (When no specific case is locked in focus) */
          <ErrorBoundary
            fallbackTitle="INVESTIGATION VIEW ERROR"
            onReset={handleResetCase}
          >
            {/* OVERVIEW & INGEST TAB */}
            {activeTab === 'overview' && (
              <div className="space-y-12">
                <UploadZone
                  onUploadSuccess={handleUploadSuccess}
                  onAnalysisComplete={handleUploadComplete}
                  onViewInvestigations={() => {
                    setActiveTab('cases');
                    loadCaseList();
                  }}
                />

                {/* Recent Cases Quick Grid */}
                {cases.length > 0 && (
                  <div className="pt-4 border-t border-cyber-border/60">
                    <CaseListView
                      cases={cases.slice(0, 5)}
                      isLoading={isLoading}
                      onRefresh={loadCaseList}
                      onSelectCase={handleSelectCase}
                    />
                  </div>
                )}
              </div>
            )}

            {/* FORENSICS TAB */}
            {activeTab === 'forensics' && (
              <div className="space-y-6">
                <div className="p-4 rounded-xl bg-cyber-surface border border-cyber-border text-center space-y-2">
                  <h2 className="font-mono text-base font-bold text-slate-100 uppercase tracking-wide">
                    FORENSIC EVIDENCE REPOSITORY
                  </h2>
                  <p className="text-xs text-slate-400 max-w-xl mx-auto">
                    Select a recorded case below or ingest a new .eml file to audit SPF/DKIM/DMARC alignments, Received relay timelines, and identity discrepancies.
                  </p>
                </div>
                <CaseListView
                  cases={cases}
                  isLoading={isLoading}
                  onRefresh={loadCaseList}
                  onSelectCase={handleSelectCase}
                />
              </div>
            )}

            {/* INFRASTRUCTURE & GEO TAB */}
            {activeTab === 'infrastructure' && (
              <div className="space-y-6">
                <GeoMap
                  ips={
                    globalCorrelation?.graph?.nodes
                      ?.filter((n) => n.type === 'IP')
                      ?.map((n) => ({
                        ip: n.label,
                        version: 4,
                        classification: 'PUBLIC',
                        geo: {
                          country: n.metadata?.country || null,
                          country_code: n.metadata?.country_code || null,
                          region: n.metadata?.region || null,
                          city: n.metadata?.city || null,
                          latitude: n.metadata?.latitude || null,
                          longitude: n.metadata?.longitude || null,
                          timezone: null,
                          source: 'local_db',
                          status: 'resolved',
                        },
                        asn: {
                          asn: n.metadata?.asn || null,
                          organization: n.metadata?.organization || null,
                          network: null,
                          registry: null,
                          source: 'local_db',
                          status: 'resolved',
                        },
                        source: 'local_db',
                        status: 'resolved',
                      })) || []
                  }
                />
                <CaseListView
                  cases={cases}
                  isLoading={isLoading}
                  onRefresh={loadCaseList}
                  onSelectCase={handleSelectCase}
                />
              </div>
            )}

            {/* INVESTIGATION GRAPH TAB */}
            {activeTab === 'graph' && (
              <div className="space-y-6">
                <InvestigationGraphView
                  graph={globalCorrelation?.graph}
                  onSelectCase={handleSelectCase}
                />
              </div>
            )}

            {/* CAMPAIGN CLUSTERS TAB */}
            {activeTab === 'campaigns' && (
              <div className="space-y-6">
                <CampaignClusterView
                  campaigns={globalCorrelation?.campaigns}
                  correlations={globalCorrelation?.correlations}
                  onSelectCase={handleSelectCase}
                />
              </div>
            )}

            {/* CASE REPOSITORY TAB */}
            {activeTab === 'cases' && (
              <div className="space-y-6">
                <CaseListView
                  cases={cases}
                  isLoading={isLoading}
                  onRefresh={loadCaseList}
                  onSelectCase={handleSelectCase}
                />
              </div>
            )}
          </ErrorBoundary>
        )}

      </main>

      {/* Forensic Engine Footer */}
      <Footer dbStatus={dbStatus} />

    </div>
  );
};

export default App;
