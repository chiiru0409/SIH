import { ResponseActionLog } from '../types/response';

export const mockResponses: ResponseActionLog[] = [
  {
    id: 'ACT-001',
    caseId: 'CASE-2026-0842',
    actionType: 'QUARANTINE',
    target: 'EML-2026-0842 (cfo@enterprise.com)',
    status: 'EXECUTED',
    executedBy: 'AI Auto-Mitigation Engine',
    timestamp: '2026-09-09T08:42:16Z',
    reason: 'Critical Credential Harvesting threshold exceeded (Score: 87/100). SPF/DKIM/DMARC failed.',
    impactScore: 90
  },
  {
    id: 'ACT-002',
    caseId: 'CASE-2026-0842',
    actionType: 'BLOCK_DOMAIN',
    target: 'micros0ft-security-auth[.]com',
    status: 'EXECUTED',
    executedBy: 'SOC Level 2 Analyst (S. Sharma)',
    timestamp: '2026-09-09T08:44:00Z',
    reason: 'Punycode typosquat domain hosting live credential harvester.',
    impactScore: 95
  },
  {
    id: 'ACT-003',
    caseId: 'CASE-2026-0843',
    actionType: 'ADD_BANNER',
    target: 'EML-2026-0843 (ap-lead@enterprise.com)',
    status: 'EXECUTED',
    executedBy: 'MailTrace Gateway Rule #402',
    timestamp: '2026-09-09T09:15:31Z',
    reason: 'External Executive Impersonation banner injected: High BEC Risk.',
    impactScore: 60
  },
  {
    id: 'ACT-004',
    caseId: 'CASE-2026-0844',
    actionType: 'BLOCK_IP',
    target: '103.145.13[.]77',
    status: 'EXECUTED',
    executedBy: 'Firewall Policy Synchronizer',
    timestamp: '2026-09-09T06:12:30Z',
    reason: 'Known C2 beaconing IP for AgentTesla payload dropper.',
    impactScore: 88
  }
];
