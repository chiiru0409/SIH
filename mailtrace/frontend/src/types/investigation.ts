import { ThreatCategory, ThreatSeverity, EmailRecord } from './email';

export type FindingType = 'AUTHENTICATION' | 'IDENTITY' | 'URL' | 'LANGUAGE' | 'INFRASTRUCTURE' | 'BEHAVIOR' | 'CORRELATION';
export type EvidenceNature = 'OBSERVED' | 'INFERENCE';

export interface ExplainableFinding {
  id: string;
  type: FindingType;
  nature: EvidenceNature;
  title: string;
  category: string;
  observedText: string;
  observedEvidence: string;
  inferenceText: string;
  aiInference: string;
  severity: ThreatSeverity;
  level: ThreatSeverity;
  scoreContribution: number;
  weight: number;
  confidence: number; // 0 - 100
}

export interface RiskBreakdown {
  authentication: number;
  identity: number;
  identitySpoofing: number;
  urlIntelligence: number;
  urlAndPayload: number;
  linguisticSignals: number;
  linguisticIntent: number;
  infrastructure: number;
  infrastructureGeo: number;
  behavior: number;
  behavioralAnomaly: number;
  correlation: number;
  totalScore: number;
  topContributors: string[];
}

export type RiskScoreBreakdown = RiskBreakdown;

export interface BehavioralContext {
  senderFamiliarity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  firstTimeSender: boolean;
  isFirstTimeSender: boolean;
  previousCommunicationCount: number;
  historicalEmailCount: number;
  firstSeenTimestamp: string;
  relationshipTier: 'NEW' | 'CASUAL' | 'ESTABLISHED' | 'VIP';
  displayNameSimilarityScore: number; // e.g. 96% match to Microsoft Support
  targetImpersonatedOrg?: string;
  impersonatedVip?: string;
  executiveTarget: boolean;
}

export interface GeoLocationDetails {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  asnOrg: string;
  isp: string;
  isProxy: boolean;
  isVpn: boolean;
  isTor: boolean;
  isHosting: boolean;
  threatScore: number;
  observedWording: string; // e.g., "Observed sending infrastructure geolocates to Frankfurt, Germany"
}

export interface InvestigationCase {
  id: string;
  caseId: string;
  emailId: string;
  subject: string;
  sender: string;
  recipient: string;
  timestamp: string;
  status: 'PENDING' | 'CONTAINED' | 'INVESTIGATING' | 'RESOLVED' | 'QUARANTINED' | 'BLOCKED';
  createdAt: string;
  updatedAt: string;
  analyst: string;
  verdict: {
    primaryThreat: ThreatCategory;
    secondaryThreats: ThreatCategory[];
    severity: ThreatSeverity;
    riskScore: number;
    overallRiskScore: number;
    confidenceScore: number;
    confidence: number;
    summaryExplanation: string;
    summary: string;
    riskScoreBreakdown: RiskBreakdown;
  };
  findings: ExplainableFinding[];
  explainableFindings: ExplainableFinding[];
  riskBreakdown: RiskBreakdown;
  behavioral: BehavioralContext;
  behavioralContext: BehavioralContext;
  infrastructure: GeoLocationDetails;
  recommendedResponse: {
    primaryAction: 'QUARANTINE' | 'BLOCK' | 'DEFANG' | 'RELEASE' | 'ESCALATE';
    secondaryActions: string[];
    justification: string;
  };
  analystNotes: string[];
  email: EmailRecord;
}
