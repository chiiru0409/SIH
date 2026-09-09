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

const AppContent: React.FC = () => {
  const { activeTab } = useInvestigation();

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
