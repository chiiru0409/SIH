/**
 * MailTrace Types — Strict types corresponding to Backend Pydantic Schemas.
 */

// ------------------------------------------------------------------ //
//  1. Upload Response & Core Email Schemas                            //
// ------------------------------------------------------------------ //

export interface EmailHeaderInfo {
  from: string | null;
  from_display?: string | null;
  to: string[];
  cc: string[];
  subject: string | null;
  date: string | null;
  message_id: string | null;
  reply_to: string | null;
  return_path: string | null;
}

export interface AuthenticationStatus {
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'unknown' | null;
  dkim: 'pass' | 'fail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'unknown' | null;
  dmarc: 'pass' | 'fail' | 'temperror' | 'permerror' | 'unknown' | null;
}

export interface ReceivedHop {
  index: number;
  raw: string;
  by: string | null;
  from: string | null;
  ip: string | null;
  timestamp: string | null;
  is_private: boolean;
}

export interface SMTPTrace {
  hop_count: number;
  received_chain: ReceivedHop[];
  public_ips: string[];
  earliest_node: ReceivedHop | null;
  confidence_note?: string | null;
}

export interface AttachmentRecord {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
}

export interface IndicatorFlags {
  reply_to_mismatch: boolean;
  return_path_mismatch: boolean;
  missing_message_id: boolean;
  has_attachments: boolean;
}

export interface EmailIndicators {
  ips: string[];
  domains: string[];
  urls: string[];
  attachments: AttachmentRecord[];
  flags: IndicatorFlags;
}

export interface EvidenceRecord {
  file_sha256: string;
  parsed_data_sha256?: string;
  integrity_note?: string;
}

// ------------------------------------------------------------------ //
//  2. Forensic Analysis Schemas (Step 3)                             //
// ------------------------------------------------------------------ //

export interface ForensicFinding {
  category: 'AUTHENTICATION' | 'IDENTITY' | 'HEADERS' | 'RELAY' | 'MESSAGE-ID' | 'TIMESTAMPS' | string;
  title: string;
  type: 'FACT' | 'INFERENCE' | string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  description: string;
  evidence: string;
  confidence?: number | null;
  field?: string;
}

export interface ForensicAnalysisResult {
  summary: {
    total_findings: number;
    facts_count: number;
    inferences_count: number;
    highest_severity: string;
    authentication_status: string;
    identity_status: string;
    status?: string;
    error?: string;
  };
  findings: ForensicFinding[];
  facts: ForensicFinding[];
  inferences: ForensicFinding[];
  limitations: string[];
}

// ------------------------------------------------------------------ //
//  3. Threat Analysis Schemas (Step 4)                               //
// ------------------------------------------------------------------ //

export interface ThreatSignals {
  urgency: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  credential_request: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  financial_request: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  impersonation: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  suspicious_link: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  attachment_threat: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  fear_manipulation: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
  authority_pressure: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | string;
}

export interface ThreatIndicator {
  indicator: string;
  category: string;
  weight: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  description: string;
  evidence?: string | null;
}

export interface ThreatAnalysisResult {
  primary_threat: string;
  secondary_threats: string[];
  confidence: number;
  signals: ThreatSignals | Record<string, string>;
  indicators: ThreatIndicator[];
  explanation: string;
  evidence_summary: {
    facts?: string[];
    inferences?: string[];
    [key: string]: string[] | undefined;
  };
  analysis_method?: string;
  model_info?: string;
}

// ------------------------------------------------------------------ //
//  4. Infrastructure Intelligence Schemas (Step 5)                   //
// ------------------------------------------------------------------ //

export interface GeoLocationInfo {
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  source: string;
  status: string;
}

export interface ASNInfo {
  asn: string | null;
  organization: string | null;
  network: string | null;
  registry: string | null;
  source: string;
  status: string;
}

export interface IPRecord {
  ip: string;
  version: number;
  classification: string;
  geo: GeoLocationInfo;
  asn: ASNInfo;
  source: string;
  status: string;
}

export interface DomainRDAP {
  registrar?: string | null;
  creation_date?: string | null;
  created?: string | null;
  updated_date?: string | null;
  updated?: string | null;
  expiration_date?: string | null;
  expires?: string | null;
  nameservers?: string[];
  status?: string[];
  source?: string;
}

export interface DomainRecord {
  domain: string;
  registrable_domain: string;
  subdomain: string | null;
  tld: string | null;
  rdap?: DomainRDAP | Record<string, any>;
  source: string;
  status: string;
}

export interface URLStructureRecord {
  url: string;
  scheme: string;
  hostname: string;
  port: number | null;
  registrable_domain: string;
  path: string;
  query_params_count: number;
  url_hash: string;
  flags: Record<string, boolean>;
  indicators: string[];
}

export interface InfrastructureIntelligenceResult {
  summary: {
    total_ips_enriched?: number;
    public_ips_count?: number;
    private_ips_count?: number;
    total_domains_enriched?: number;
    total_urls_analyzed?: number;
    status?: string;
    [key: string]: any;
  };
  ips: IPRecord[];
  domains: DomainRecord[];
  urls: URLStructureRecord[];
  correlation_entities?: Record<string, any>;
  limitations: string[];
}

// ------------------------------------------------------------------ //
//  5. Risk Assessment Schemas (Step 6)                               //
// ------------------------------------------------------------------ //

export interface RiskFactor {
  factor: string;
  category: string;
  points: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  evidence: string;
  source: string;
}

export interface RiskAssessmentResult {
  risk_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  risk_factors: RiskFactor[];
  category_scores: Record<string, number>;
  top_factors: RiskFactor[];
  explanation: string;
  confidence: number;
  method?: string;
  limitations: string[];
}

// ------------------------------------------------------------------ //
//  6. Full Upload Response                                           //
// ------------------------------------------------------------------ //

export interface UploadResponse {
  case_id: string;
  status: string;
  filename: string;
  sha256: string;
  message: string;
  email: EmailHeaderInfo;
  authentication: AuthenticationStatus;
  smtp_trace: SMTPTrace;
  indicators: EmailIndicators;
  evidence: EvidenceRecord;
  forensic_analysis?: ForensicAnalysisResult | null;
  threat_analysis?: ThreatAnalysisResult | null;
  infrastructure_intelligence?: InfrastructureIntelligenceResult | null;
  risk_assessment?: RiskAssessmentResult | null;
  parse_errors: string[];
}

// ------------------------------------------------------------------ //
//  7. Cases & History Schemas                                        //
// ------------------------------------------------------------------ //

export interface CaseSummary {
  case_id: string;
  original_filename: string;
  status: string;
  risk_score: number | null;
  risk_label: string | null;
  created_at: string;
}

export interface CaseDetail {
  case_id: string;
  original_filename: string;
  status: string;
  created_at: string;
  updated_at: string;
  parsed_email: Record<string, any> | null;
  forensic_analysis: ForensicAnalysisResult | null;
  ai_analysis: ThreatAnalysisResult | null;
  ip_intel: { ips?: IPRecord[]; summary?: any } | null;
  domain_intel: { domains?: DomainRecord[]; summary?: any } | null;
  url_intel: { urls?: URLStructureRecord[]; summary?: any } | null;
  risk_score: number | null;
  risk_label: string | null;
  risk_reasons: RiskAssessmentResult | null;
  campaign_id: string | null;
  correlation_data: Record<string, any> | null;
  report_path: string | null;
  evidence_hash: string | null;
  error_detail: string | null;
}

// ------------------------------------------------------------------ //
//  8. Campaign & Graph Schemas (Step 7)                              //
// ------------------------------------------------------------------ //

export type NodeType = 'CASE' | 'EMAIL' | 'SENDER' | 'DOMAIN' | 'URL' | 'IP' | 'ASN' | 'CAMPAIGN';

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  metadata?: Record<string, any>;
}

export type RelationshipType = 
  | 'CONTAINS'
  | 'SENT_BY'
  | 'REFERENCES'
  | 'HOSTED_ON'
  | 'RESOLVES_TO'
  | 'ANNOUNCED_BY'
  | 'BELONGS_TO'
  | 'CORRELATED_WITH'
  | 'OBSERVED_IP';

export interface GraphEdge {
  source: string;
  target: string;
  relationship: RelationshipType | string;
  strength: number;
  evidence_source?: string;
  metadata?: Record<string, any>;
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface SharedIndicator {
  type: 'url' | 'ip' | 'domain' | 'sender' | 'asn' | string;
  value: string;
  weight: number;
  description?: string | null;
}

export interface CaseCorrelation {
  case_a: string;
  case_b: string;
  correlation_score: number;
  shared_indicators: SharedIndicator[];
  reason: string;
}

export interface CampaignCluster {
  campaign_id: string;
  case_count: number;
  case_ids: string[];
  shared_indicators: Record<string, any>[];
  correlation_strength: number;
  confidence: number;
  explanation: string;
}

export interface CorrelationOverviewResponse {
  total_cases: number;
  total_campaigns: number;
  campaigns: CampaignCluster[];
  correlations: CaseCorrelation[];
  graph: InvestigationGraph;
  limitations: string[];
}

export interface CaseCorrelationDetailResponse {
  case_id: string;
  campaign_id: string | null;
  related_cases: Record<string, any>[];
  shared_indicators: SharedIndicator[];
  campaign: CampaignCluster | null;
  graph: InvestigationGraph;
  limitations: string[];
}

// ------------------------------------------------------------------ //
//  9. Health & System                                                //
// ------------------------------------------------------------------ //

export interface DatabaseStatus {
  engine: 'sqlite' | 'postgresql' | string;
  dialect: 'aiosqlite' | 'asyncpg' | string;
  provider: 'local' | 'neon' | 'postgresql' | string;
  status: 'ready' | 'degraded' | 'unreachable' | string;
  connected: boolean;
}

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  environment: string;
  database: string;
  db_info?: DatabaseStatus | null;
}

// ------------------------------------------------------------------ //
//  10. Step 9: Evidence Integrity & Blockchain Anchoring             //
// ------------------------------------------------------------------ //

export interface ChainOfCustodyEvent {
  id: string | number;
  event_type: 'EVIDENCE_INGESTED' | 'EVIDENCE_HASHED' | 'EVIDENCE_ANALYZED' | 'EVIDENCE_VERIFIED' | 'BLOCKCHAIN_ANCHORED' | string;
  event_hash: string;
  evidence_hash: string;
  previous_event_hash: string | null;
  timestamp: string;
  metadata: Record<string, any>;
}

export interface ChainOfCustodyResponse {
  case_id: string;
  evidence_hash: string;
  total_events: number;
  chain_valid: boolean;
  events: ChainOfCustodyEvent[];
}

export interface BlockchainAnchorInfo {
  enabled: boolean;
  provider: string;
  network: string;
  transaction_id: string | null;
  anchor_data: Record<string, any> | null;
  status: 'not_anchored' | 'anchored' | 'disabled' | 'not_configured' | string;
}

export interface EvidenceManifestResponse {
  case_id: string;
  evidence_type: string;
  original_filename: string;
  file_size_bytes: number;
  file_sha256: string;
  parsed_evidence_sha256: string;
  analysis_sha256: string;
  hash_algorithm: string;
  integrity_status: string;
  created_at: string;
  updated_at: string;
  chain_of_custody: {
    total_events: number;
    events: ChainOfCustodyEvent[];
  };
  blockchain_anchoring: BlockchainAnchorInfo;
  legal_attribution_notice: string;
}

export interface EvidenceVerifyResponse {
  valid: boolean;
  case_id: string;
  file_sha256: string;
  stored_file_sha256: string;
  parsed_evidence_sha256: string;
  stored_parsed_sha256: string;
  analysis_sha256: string;
  stored_analysis_sha256: string;
  verification_method: string;
  chain_of_custody_valid: boolean;
  chain_of_custody_events_count: number;
  blockchain_verified: boolean | null;
  blockchain_details: Record<string, any>;
  details: string[];
  verified_at: string;
}

export interface BlockchainAnchorResponse {
  status: string;
  anchored: boolean;
  case_id: string;
  evidence_hash: string;
  transaction_id: string | null;
  block_number: number | null;
  block_timestamp: string | null;
  network: string | null;
  message: string;
}

// ------------------------------------------------------------------ //
//  6. Enterprise Ecosystem Schemas (Sentaro / GreatHorn / Mimecast)  //
// ------------------------------------------------------------------ //

export interface WarningBannerInfo {
  severity: 'CRITICAL' | 'WARNING' | 'INFO' | 'NONE';
  title: string;
  message: string;
  color: string;
  border_color: string;
  bg_color: string;
  tags: string[];
  html_injected: string;
  plaintext_injected: string;
}

export interface BehavioralRelationshipInfo {
  relationship_tier: string;
  familiarity_score: number;
  is_first_time_sender: boolean;
  is_freemail_provider: boolean;
  warning_banner: WarningBannerInfo;
}

export interface PolicyRuleItem {
  id: string;
  name: string;
  enabled: boolean;
  condition: string;
  action: string;
  description: string;
}

export interface QuarantinedItem {
  case_id: string;
  filename: string;
  sender_email?: string | null;
  sender_display?: string | null;
  sender_domain?: string | null;
  subject: string;
  risk_score: number;
  quarantined_at: string;
  status: string;
  reason: string;
  triggered_rules: string[];
  analyst_notes?: string | null;
}

export interface BlocklistEntry {
  id: string;
  type: 'DOMAIN' | 'SENDER' | 'IP' | string;
  value: string;
  reason: string;
  added_at: string;
  added_by: string;
}

export interface CloudTenantItem {
  id: string;
  provider: 'MICROSOFT_365' | 'GOOGLE_WORKSPACE' | 'SMTP_GATEWAY' | string;
  name: string;
  domain: string;
  status: string;
  sync_mode: string;
  mailboxes_monitored: number;
  threats_intercepted_today: number;
  last_sync: string;
  health: string;
}

export interface LiveTenantStreamEvent {
  event_id: string;
  timestamp: string;
  tenant_id: string;
  tenant_name: string;
  sender: string;
  display_name?: string | null;
  recipient: string;
  subject: string;
  risk_score: number;
  severity: string;
  intent: string;
  policy_action: string;
}

export interface ComplianceControl {
  ref: string;
  title: string;
  requirement: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL';
  mailtrace_mapping: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  category: string;
  score: number;
  status: string;
  controls: ComplianceControl[];
}

export interface ComplianceScorecardResponse {
  overall_compliance_score: number;
  overall_status: string;
  total_controls_audited: number;
  passing_controls: number;
  failing_controls: number;
  last_audited: string;
  frameworks: ComplianceFramework[];
}
