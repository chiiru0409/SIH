export type ThreatCategory = 
  | 'PHISHING'
  | 'BEC'
  | 'IMPERSONATION'
  | 'CREDENTIAL_HARVESTING'
  | 'SOCIAL_ENGINEERING'
  | 'QUISHING'
  | 'SUSPICIOUS'
  | 'BENIGN';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AuthStatus = 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR';

export type EmailStatus = 'PENDING_REVIEW' | 'INVESTIGATED' | 'QUARANTINED' | 'BLOCKED' | 'RELEASED';

export interface SmtpHop {
  hopNumber: number;
  fromServer?: string;
  fromHost: string;
  fromIp: string;
  byServer?: string;
  byHost: string;
  timestamp: string;
  delaySeconds: number;
  tlsVersion?: string;
  isSuspicious: boolean;
  suspiciousReason?: string;
  anomalyReason?: string;
  country?: string;
  city?: string;
  asn?: string;
  org?: string;
}

export type RelayHop = SmtpHop;

export interface EmailAttachment {
  name: string;
  filename?: string;
  sizeBytes: number;
  mimeType: string;
  sha256: string;
  isSuspicious: boolean;
  threatVerdict?: string;
}

export interface ExtractedUrl {
  originalUrl: string;
  defangedUrl: string;
  domain: string;
  registrableDomain?: string;
  resolvedIp?: string;
  domainAgeDays?: number;
  isLookalike?: boolean;
  redirectChain?: string[];
  ip?: string;
  asn?: string;
  asnOrg?: string;
  country?: string;
  isPunycode: boolean;
  hasSuspiciousKeyword?: boolean;
  isShortener?: boolean;
  isCredentialPath?: boolean;
  reputationScore?: number;
  riskScore: number; // 0 - 100
  threatTags?: string[];
}

export interface EmailHeaderForensics {
  from: string;
  fromDisplayName?: string;
  fromDomain?: string;
  to: string;
  toDisplayName?: string;
  replyTo?: string;
  replyToDomain?: string;
  returnPath: string;
  returnPathDomain?: string;
  messageId: string;
  date: string;
  subject: string;
  spfHeader?: string;
  dkimHeader?: string;
  dmarcHeader?: string;
  receivedHops?: SmtpHop[];
  originatingIp: string;
  xMailer?: string;
  mimeVersion?: string;
  contentType?: string;
  identityMismatch?: boolean;
  identityMismatchDetails?: string;
}

export interface AuthenticationReport {
  overallAlignment: boolean;
  spf: {
    status: AuthStatus;
    domain: string;
    senderIp?: string;
    ip?: string;
    aligned: boolean;
    reason?: string;
    details?: string;
  };
  dkim: {
    status: AuthStatus;
    domain: string;
    selector: string;
    aligned: boolean;
    reason?: string;
    details?: string;
  };
  dmarc: {
    status: AuthStatus;
    policy: 'none' | 'quarantine' | 'reject';
    disposition?: 'none' | 'quarantine' | 'reject';
    headerFromDomain?: string;
    aligned: boolean;
    reason?: string;
    details?: string;
  };
}

export type AuthenticationResults = AuthenticationReport;

export interface EmailRecord {
  id: string;
  caseId: string;
  timestamp: string;
  subject: string;
  senderName: string;
  senderAddress: string;
  recipientAddress: string;
  previewText: string;
  bodyHtml?: string;
  bodyText: string;
  rawHeaders: string;
  threatCategory: ThreatCategory;
  secondaryCategories?: ThreatCategory[];
  severity: ThreatSeverity;
  riskScore: number; // 0 - 100
  confidenceScore: number; // 0 - 100
  status: EmailStatus;
  isQuarantined: boolean;
  isBlocked: boolean;
  isDefanged: boolean;
  campaignId?: string;
  headers: EmailHeaderForensics;
  auth: AuthenticationReport;
  authenticationResults: AuthenticationReport;
  urls: ExtractedUrl[];
  extractedUrls: ExtractedUrl[];
  attachments: EmailAttachment[];
  relayHops: SmtpHop[];
  infrastructure: {
    originatingIp: string;
    originatingAsn: string;
    originatingOrg: string;
    originatingCountry: string;
    originatingCity: string;
    originatingLatitude: number;
    originatingLongitude: number;
    isProxyOrTor: boolean;
  };
  tags: string[];
}

export type EmailMetadata = EmailRecord;
