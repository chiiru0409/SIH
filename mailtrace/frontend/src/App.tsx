import React from 'react';
import { InvestigationProvider, useInvestigation } from './context/InvestigationContext';
import { Shell } from './components/layout/Shell';
import { ErrorBoundary } from './components/common/ErrorBoundary';

import { OverviewPage } from './pages/OverviewPage';
import { MailboxPage } from './pages/MailboxPage';
import { UploadPage } from './pages/UploadPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { GraphPage } from './pages/GraphPage';
import { HuntingPage } from './pages/HuntingPage';
import { CampaignsPage } from './pages/CampaignsPage';
import { IntelligencePage } from './pages/IntelligencePage';
import { ResponsePage } from './pages/ResponsePage';
import { PolicyPage } from './pages/PolicyPage';
import { TenantPage } from './pages/TenantPage';
import { EvidencePage } from './pages/EvidencePage';
import { CompliancePage } from './pages/CompliancePage';
import { ReportsPage } from './pages/ReportsPage';
import { Scene } from './components/landing/KageScene';

const AppContent: React.FC = () => {
  const { activeTab, setActiveTab } = useInvestigation();

  if (activeTab === 'landing') {
    return (
      <div className="relative w-screen h-screen overflow-hidden bg-black">
        <button
          onClick={() => setActiveTab('overview')}
          className="fixed top-4 right-4 z-50 px-4 py-2 bg-slate-900/90 hover:bg-slate-800 text-cyan-400 font-mono text-xs rounded-lg border border-cyan-500/40 shadow-lg backdrop-blur-md flex items-center gap-2 transition-all hover:scale-105"
        >
          <span>← Back to SOC Portal</span>
        </button>
        <ErrorBoundary fallbackTitle="Landing Experience Recovered">
          <Scene />
        </ErrorBoundary>
      </div>
    );
  }

  const renderActivePage = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewPage />;
      case 'mailbox':
        return <MailboxPage />;
      case 'upload':
        return <UploadPage />;
      case 'investigation':
        return <InvestigationPage />;
      case 'graph':
        return <GraphPage />;
      case 'hunting':
        return <HuntingPage />;
      case 'campaigns':
        return <CampaignsPage />;
      case 'intelligence':
        return <IntelligencePage />;
      case 'response':
        return <ResponsePage />;
      case 'policy':
        return <PolicyPage />;
      case 'tenant':
        return <TenantPage />;
      case 'evidence':
        return <EvidencePage />;
      case 'compliance':
        return <CompliancePage />;
      case 'reports':
        return <ReportsPage />;
      default:
        return <OverviewPage />;
    }
  };

  return (
    <Shell>
      <ErrorBoundary fallbackTitle="Tab View Recovered">
        {renderActivePage()}
      </ErrorBoundary>
    </Shell>
  );
};

export const App: React.FC = () => {
  return (
    <ErrorBoundary fallbackTitle="Application Recovered">
      <InvestigationProvider>
        <AppContent />
      </InvestigationProvider>
    </ErrorBoundary>
  );
};

export default App;
