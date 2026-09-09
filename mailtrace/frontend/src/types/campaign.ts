import { ThreatCategory, ThreatSeverity } from './email';

export interface CampaignCluster {
  id: string; // e.g. "CAMPAIGN-0042"
  name: string; // e.g. "O365-CRED-HARVEST-BLITZ"
  theme: string;
  threatCategory: ThreatCategory;
  severity: ThreatSeverity;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  confidenceScore: number;
  status: 'ACTIVE' | 'CONTAINED' | 'MONITORING';
  firstObserved: string;
  lastObserved: string;
  totalEmails: number;
  targetedRecipients: number;
  targetedDepartments: string[];
  sharedInfrastructure: {
    domains: string[];
    ips: string[];
    asns: string[];
    urls: string[];
    attachmentHashes: string[];
  };
  correlationReasons: {
    factor: string;
    description: string;
    weight: number;
  }[];
  timeline: {
    timestamp: string;
    event: string;
    target: string;
    associatedCaseId: string;
  }[];
  associatedCaseIds: string[];
}
