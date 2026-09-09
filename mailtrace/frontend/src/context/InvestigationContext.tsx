import React, { createContext, useContext, useState, useMemo } from 'react';
import { InvestigationCase } from '../types/investigation';
import { EmailMetadata } from '../types/email';
import { CampaignCluster } from '../types/campaign';
import { ThreatIoc } from '../types/intelligence';
import { CryptographicEvidence } from '../types/evidence';
import { ResponseActionLog } from '../types/response';

import { mockInvestigations } from '../data/mockInvestigations';
import { mockEmails } from '../data/mockEmails';
import { mockCampaigns } from '../data/mockCampaigns';
import { mockIntelligence } from '../data/mockIntelligence';
import { mockEvidence } from '../data/mockEvidence';
import { mockResponses } from '../data/mockResponses';

export type ActiveTab = 
  | 'overview' 
  | 'mailbox' 
  | 'upload'
  | 'investigation' 
  | 'graph' 
  | 'hunting'
  | 'campaigns' 
  | 'intelligence' 
  | 'response' 
  | 'policy'
  | 'tenant'
  | 'evidence' 
  | 'compliance'
  | 'reports';

interface InvestigationContextType {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  activeCaseId: string;
  setActiveCaseId: (id: string) => void;
  activeCase: InvestigationCase | undefined;
  activeEmail: EmailMetadata | undefined;
  cases: InvestigationCase[];
  emails: EmailMetadata[];
  campaigns: CampaignCluster[];
  intelligence: ThreatIoc[];
  evidenceRecords: Record<string, CryptographicEvidence>;
  responses: ResponseActionLog[];
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  selectAndInvestigate: (caseId: string) => void;
  addResponseAction: (action: Omit<ResponseActionLog, 'id' | 'timestamp'>) => void;
  updateCaseStatus: (caseId: string, status: InvestigationCase['status']) => void;
  simulateTamper: (caseId: string) => void;
  restoreTamper: (caseId: string) => void;
}

const InvestigationContext = createContext<InvestigationContextType | undefined>(undefined);

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [activeCaseId, setActiveCaseId] = useState<string>('CASE-2026-0842');
  const [cases, setCases] = useState<InvestigationCase[]>(mockInvestigations);
  const [emails] = useState<EmailMetadata[]>(mockEmails);
  const [campaigns] = useState<CampaignCluster[]>(mockCampaigns);
  const [intelligence] = useState<ThreatIoc[]>(mockIntelligence);
  const [evidenceRecords, setEvidenceRecords] = useState<Record<string, CryptographicEvidence>>(mockEvidence);
  const [responses, setResponses] = useState<ResponseActionLog[]>(mockResponses);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const activeCase = useMemo(() => {
    return cases.find(c => c.id === activeCaseId) || cases[0];
  }, [cases, activeCaseId]);

  const activeEmail = useMemo(() => {
    return emails.find(e => e.caseId === activeCase?.id || e.id === activeCase?.emailId);
  }, [emails, activeCase]);

  const selectAndInvestigate = (caseId: string) => {
    setActiveCaseId(caseId);
    setActiveTab('investigation');
  };

  const addResponseAction = (action: Omit<ResponseActionLog, 'id' | 'timestamp'>) => {
    const newAction: ResponseActionLog = {
      ...action,
      id: `ACT-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString()
    };
    setResponses(prev => [newAction, ...prev]);
  };

  const updateCaseStatus = (caseId: string, status: InvestigationCase['status']) => {
    setCases(prev => prev.map(c => (c.id === caseId ? { ...c, status } : c)));
  };

  const simulateTamper = (caseId: string) => {
    setEvidenceRecords(prev => {
      const record = prev[caseId];
      if (!record) return prev;
      return {
        ...prev,
        [caseId]: {
          ...record,
          tamperStatus: 'TAMPER_DETECTED',
          isTamperEvident: true,
          auditTrail: [
            ...record.auditTrail,
            {
              step: record.auditTrail.length + 1,
              action: 'UNAUTHORIZED HEADER MODIFICATION AT REST (CORRUPTION DETECTED)',
              actor: 'Tamper Simulation Utility',
              timestamp: new Date().toISOString(),
              hashBefore: record.rawEmailSha256,
              hashAfter: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
              status: 'ANOMALOUS'
            }
          ]
        }
      };
    });
  };

  const restoreTamper = (caseId: string) => {
    if (mockEvidence[caseId]) {
      setEvidenceRecords(prev => ({
        ...prev,
        [caseId]: { ...mockEvidence[caseId] }
      }));
    }
  };

  return (
    <InvestigationContext.Provider
      value={{
        activeTab,
        setActiveTab,
        activeCaseId,
        setActiveCaseId,
        activeCase,
        activeEmail,
        cases,
        emails,
        campaigns,
        intelligence,
        evidenceRecords,
        responses,
        searchQuery,
        setSearchQuery,
        selectAndInvestigate,
        addResponseAction,
        updateCaseStatus,
        simulateTamper,
        restoreTamper
      }}
    >
      {children}
    </InvestigationContext.Provider>
  );
};

export const useInvestigation = () => {
  const context = useContext(InvestigationContext);
  if (!context) {
    throw new Error('useInvestigation must be used within an InvestigationProvider');
  }
  return context;
};
