import React, { createContext, useContext, useState, useMemo, useEffect } from 'react';
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
import { adaptUploadResponseToModels } from '../lib/adapters';
import { fetchCases, fetchCase } from '../lib/api';

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
  ingestUploadedCase: (data: any) => InvestigationCase;
  addResponseAction: (action: Omit<ResponseActionLog, 'id' | 'timestamp'>) => void;
  updateCaseStatus: (caseId: string, status: InvestigationCase['status']) => void;
  simulateTamper: (caseId: string) => void;
  restoreTamper: (caseId: string) => void;
  reloadCasesFromBackend: () => Promise<void>;
}

const STORAGE_CASES_KEY = 'mailtrace_custom_cases';
const STORAGE_EMAILS_KEY = 'mailtrace_custom_emails';
const STORAGE_EVIDENCE_KEY = 'mailtrace_custom_evidence';

const InvestigationContext = createContext<InvestigationContextType | undefined>(undefined);

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [activeCaseId, setActiveCaseId] = useState<string>('CASE-2026-0842');

  // Load custom stored records from local storage if available
  const [customCases, setCustomCases] = useState<InvestigationCase[]>(() => {
    try {
      const item = localStorage.getItem(STORAGE_CASES_KEY);
      return item ? JSON.parse(item) : [];
    } catch {
      return [];
    }
  });

  const [customEmails, setCustomEmails] = useState<EmailMetadata[]>(() => {
    try {
      const item = localStorage.getItem(STORAGE_EMAILS_KEY);
      return item ? JSON.parse(item) : [];
    } catch {
      return [];
    }
  });

  const [customEvidence, setCustomEvidence] = useState<Record<string, CryptographicEvidence>>(() => {
    try {
      const item = localStorage.getItem(STORAGE_EVIDENCE_KEY);
      return item ? JSON.parse(item) : {};
    } catch {
      return {};
    }
  });

  const [campaigns] = useState<CampaignCluster[]>(mockCampaigns);
  const [intelligence] = useState<ThreatIoc[]>(mockIntelligence);
  const [responses, setResponses] = useState<ResponseActionLog[]>(mockResponses);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Merged cases: custom uploaded first, followed by default mock baseline
  const cases = useMemo(() => {
    const defaultIds = new Set(customCases.map(c => c.id));
    const filteredMock = mockInvestigations.filter(m => !defaultIds.has(m.id));
    return [...customCases, ...filteredMock];
  }, [customCases]);

  const emails = useMemo(() => {
    const defaultIds = new Set(customEmails.map(e => e.caseId || e.id));
    const filteredMock = mockEmails.filter(m => !defaultIds.has(m.caseId) && !defaultIds.has(m.id));
    return [...customEmails, ...filteredMock];
  }, [customEmails]);

  const evidenceRecords = useMemo(() => {
    return {
      ...mockEvidence,
      ...customEvidence,
    };
  }, [customEvidence]);

  const activeCase = useMemo(() => {
    return cases.find(c => c.id === activeCaseId) || cases[0];
  }, [cases, activeCaseId]);

  const activeEmail = useMemo(() => {
    return emails.find(e => e.caseId === activeCase?.id || e.id === activeCase?.emailId) || emails[0];
  }, [emails, activeCase]);

  // Sync to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_CASES_KEY, JSON.stringify(customCases));
      localStorage.setItem(STORAGE_EMAILS_KEY, JSON.stringify(customEmails));
      localStorage.setItem(STORAGE_EVIDENCE_KEY, JSON.stringify(customEvidence));
    } catch (e) {
      console.warn('Could not persist MailTrace cases to localStorage:', e);
    }
  }, [customCases, customEmails, customEvidence]);

  // Try to load any existing cases from backend (e.g. Neon PostgreSQL)
  const reloadCasesFromBackend = async () => {
    try {
      const backendSummaries = await fetchCases(1, 50);
      if (backendSummaries && backendSummaries.length > 0) {
        // Fetch detailed record for each case that isn't already loaded
        for (const summary of backendSummaries) {
          const exists = cases.some(c => c.id === summary.case_id);
          if (!exists) {
            try {
              const fullDetail = await fetchCase(summary.case_id);
              if (fullDetail && fullDetail.case_id) {
                const { investigationCase, emailMetadata, evidenceRecord } = adaptUploadResponseToModels(fullDetail);
                setCustomCases(prev => [investigationCase, ...prev.filter(c => c.id !== investigationCase.id)]);
                setCustomEmails(prev => [emailMetadata, ...prev.filter(e => e.id !== emailMetadata.id)]);
                setCustomEvidence(prev => ({ ...prev, [evidenceRecord.caseId]: evidenceRecord }));
              }
            } catch (err) {
              console.debug('Case detail fetch skipped:', summary.case_id, err);
            }
          }
        }
      }
    } catch (err) {
      console.debug('Backend cases sync skipped:', err);
    }
  };

  useEffect(() => {
    reloadCasesFromBackend();
  }, []);

  const selectAndInvestigate = (caseId: string) => {
    setActiveCaseId(caseId);
    setActiveTab('investigation');
  };

  const ingestUploadedCase = (data: any): InvestigationCase => {
    const { investigationCase, emailMetadata, evidenceRecord } = adaptUploadResponseToModels(data);

    setCustomCases(prev => [investigationCase, ...prev.filter(c => c.id !== investigationCase.id)]);
    setCustomEmails(prev => [emailMetadata, ...prev.filter(e => e.id !== emailMetadata.id)]);
    setCustomEvidence(prev => ({
      ...prev,
      [evidenceRecord.caseId]: evidenceRecord
    }));

    setActiveCaseId(investigationCase.id);
    return investigationCase;
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
    setCustomCases(prev => prev.map(c => (c.id === caseId ? { ...c, status } : c)));
  };

  const simulateTamper = (caseId: string) => {
    setCustomEvidence(prev => {
      const record = prev[caseId] || evidenceRecords[caseId];
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
      setCustomEvidence(prev => {
        const next = { ...prev };
        delete next[caseId];
        return next;
      });
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
        ingestUploadedCase,
        addResponseAction,
        updateCaseStatus,
        simulateTamper,
        restoreTamper,
        reloadCasesFromBackend,
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
