import React, { useState } from 'react';
import { 
  FolderLock, 
  Copy, 
  Check, 
  FileCode, 
  ShieldAlert,
  ShieldCheck, 
  Layers, 
  Search, 
  Compass, 
  Network, 
  ExternalLink,
  Code,
  Mail,
  ArrowLeft,
  Printer,
  FileText
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Tabs } from '../ui/Tabs';
import { Modal } from '../ui/Modal';
import { ForensicReportModal } from './ForensicReportModal';
import { DynamicBannerPreview } from '../threat/DynamicBannerPreview';
import { formatDate, truncateHash } from '../../lib/utils';
import { sanitizeHtml } from '../../lib/sanitize';
import { remediateQuarantine } from '../../lib/api';
import { RiskScoreHero } from '../risk/RiskScoreHero';
import { RiskFactorsList } from '../risk/RiskFactorsList';
import { ThreatClassificationPanel } from '../threat/ThreatClassificationPanel';
import { AuthenticationMatrix } from '../forensic/AuthenticationMatrix';
import { IdentityInspector } from '../forensic/IdentityInspector';
import { RelayTimeline } from '../forensic/RelayTimeline';
import { ForensicEvidencePanel } from '../forensic/ForensicEvidencePanel';
import { InfrastructurePanel } from '../infrastructure/InfrastructurePanel';
import { GeoMap } from '../infrastructure/GeoMap';
import { InvestigationGraphView } from '../graph/InvestigationGraphView';
import { EvidenceIntegrityPanel } from '../evidence/EvidenceIntegrityPanel';
import { ErrorBoundary } from '../ui/ErrorBoundary';
import type { CaseDetail, CaseCorrelationDetailResponse } from '../../types/api';

export interface CaseDetailWorkspaceProps {
  caseData: CaseDetail;
  correlationData?: CaseCorrelationDetailResponse | null;
  onBack: () => void;
  onSelectRelatedCase?: (caseId: string) => void;
  className?: string;
}

export const CaseDetailWorkspace: React.FC<CaseDetailWorkspaceProps> = ({
  caseData,
  correlationData,
  onBack,
  onSelectRelatedCase,
  className = '',
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'forensics' | 'threat' | 'infrastructure' | 'graph' | 'integrity' | 'raw_email'>('overview');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isHeadersModalOpen, setIsHeadersModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [quarantineMsg, setQuarantineMsg] = useState<string | null>(null);

  const handleQuarantineAction = async (action: string) => {
    try {
      await remediateQuarantine(caseId, action, `Direct action ${action} from Case Workspace`);
      setQuarantineMsg(`Case ${caseId.slice(0, 8)} successfully marked as ${action}.`);
      setTimeout(() => setQuarantineMsg(null), 4000);
    } catch (err: any) {
      alert(`Action failed: ${err.message}`);
    }
  };

  const copyToClipboard = (text?: string | null, field?: string) => {
    if (!text || !field) return;
    navigator.clipboard.writeText(String(text));
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Safe Defensive Extractions Helper
  const extractString = (val: any): string | null => {
    if (typeof val === 'string') return val;
    if (val && typeof val === 'object') {
      if (typeof val.email === 'string') return val.email;
      if (typeof val.address === 'string') return val.address;
      if (typeof val.name === 'string') return val.name;
      if (typeof val.value === 'string') return val.value;
      if (typeof val.domain === 'string') return val.domain;
    }
    return null;
  };

  const caseId = typeof caseData?.case_id === 'string' ? caseData.case_id : String(caseData?.case_id || '');
  const originalFilename = typeof caseData?.original_filename === 'string' ? caseData.original_filename : 'unknown.eml';
  const riskLabel = String(caseData?.risk_label || (typeof caseData?.risk_score === 'number' 
    ? (caseData.risk_score >= 80 ? 'CRITICAL' : caseData.risk_score >= 60 ? 'HIGH' : caseData.risk_score >= 30 ? 'MEDIUM' : 'LOW')
    : 'LOW')).toUpperCase();

  const parsed = (caseData?.parsed_email && typeof caseData.parsed_email === 'object')
    ? caseData.parsed_email
    : (caseData as any)?.email_analysis?.parsed_email || {};
  const headers = (parsed?.headers && typeof parsed.headers === 'object') ? parsed.headers : {};
  
  const senderEmail = extractString(parsed?.sender?.email) ||
    extractString(parsed?.from_address) ||
    extractString(parsed?.sender) ||
    extractString(parsed?.from) ||
    (typeof parsed?.from === 'string' ? parsed.from : null);

  const senderDisplayName = extractString(parsed?.sender?.display_name) ||
    extractString(parsed?.from_display_name) ||
    extractString(parsed?.from_display) ||
    null;

  const senderDomain = extractString(parsed?.sender?.domain) ||
    extractString(parsed?.from_domain) ||
    (senderEmail && senderEmail.includes('@') ? senderEmail.split('@')[1] : null);

  const sender = {
    email: senderEmail,
    display_name: senderDisplayName,
    domain: senderDomain,
  };

  const replyToEmail = extractString(parsed?.reply_to?.email) ||
    extractString(parsed?.reply_to) ||
    null;

  const returnPathEmail = extractString(parsed?.return_path?.email) ||
    extractString(parsed?.return_path) ||
    null;

  const returnPathDomain = extractString(parsed?.return_path?.domain) ||
    (returnPathEmail && returnPathEmail.includes('@') ? returnPathEmail.split('@')[1] : returnPathEmail);

  const dkimDomain = extractString(parsed?.authentication?.dkim?.domain) || null;

  const rawTo = parsed?.recipients?.to || parsed?.to_addresses || parsed?.to || [];
  const rawCc = parsed?.recipients?.cc || parsed?.cc_addresses || parsed?.cc || [];
  
  const toRecipients: string[] = Array.isArray(rawTo)
    ? rawTo.map((r: any) => extractString(r) || (typeof r === 'string' ? r : '')).filter(Boolean)
    : typeof rawTo === 'string' ? [rawTo] : (extractString(rawTo) ? [extractString(rawTo)!] : []);

  const ccRecipients: string[] = Array.isArray(rawCc)
    ? rawCc.map((r: any) => extractString(r) || (typeof r === 'string' ? r : '')).filter(Boolean)
    : typeof rawCc === 'string' ? [rawCc] : (extractString(rawCc) ? [extractString(rawCc)!] : []);

  const emailSubject = extractString(headers?.subject) || extractString(parsed?.subject) || (typeof headers?.subject === 'string' ? headers.subject : '(No Subject)');
  const emailDate = extractString(headers?.date_iso) || extractString(headers?.date_raw) || extractString(headers?.date) || extractString(parsed?.date) || null;
  const messageId = extractString(headers?.message_id) || extractString(parsed?.message_id) || null;

  const auth = parsed?.authentication || parsed?.authentication_results || {};
  const relay = parsed?.received_chain || parsed?.routing_hops || parsed?.smtp_trace || {};
  const indicators = parsed?.indicators || {};

  const risk = caseData?.risk_reasons || (caseData as any)?.email_analysis?.risk_assessment || (caseData as any)?.risk_assessment || {
    risk_score: caseData?.risk_score ?? 0,
    severity: riskLabel,
    risk_factors: [],
    category_scores: {},
    top_factors: [],
    explanation: '',
    confidence: 0.8,
    limitations: [],
  };

  const forensicAnalysis = caseData?.forensic_analysis || (caseData as any)?.email_analysis?.forensic_analysis || null;
  const threatAnalysis = caseData?.ai_analysis || (caseData as any)?.threat_analysis || (caseData as any)?.email_analysis?.threat_analysis || null;
  const ipIntel = caseData?.ip_intel || (caseData as any)?.infrastructure || (caseData as any)?.email_analysis?.infrastructure || { ips: [] };
  const domainIntel = caseData?.domain_intel || (caseData as any)?.infrastructure || (caseData as any)?.email_analysis?.infrastructure || { domains: [] };
  const urlIntel = caseData?.url_intel || (caseData as any)?.infrastructure || (caseData as any)?.email_analysis?.infrastructure || { urls: [] };

  const [emailViewMode, setEmailViewMode] = useState<'html' | 'plain'>('html');

  const rawHeaders = parsed?.raw_headers && typeof parsed.raw_headers === 'object' 
    ? parsed.raw_headers 
    : typeof parsed?.raw_headers === 'string' 
    ? { 'Raw Headers': parsed.raw_headers }
    : {};

  let rawHtml: string | null = null;
  let rawPlain: string | null = null;

  if (typeof parsed?.html_body === 'string' && parsed.html_body.trim()) {
    rawHtml = parsed.html_body;
  } else if (typeof parsed?.body_html === 'string' && parsed.body_html.trim()) {
    rawHtml = parsed.body_html;
  } else if (parsed?.body && typeof parsed.body === 'object') {
    if (typeof parsed.body.html === 'string' && parsed.body.html.trim()) {
      rawHtml = parsed.body.html;
    }
  }

  if (typeof parsed?.body === 'string' && parsed.body.trim()) {
    rawPlain = parsed.body;
  } else if (typeof parsed?.body_plain === 'string' && parsed.body_plain.trim()) {
    rawPlain = parsed.body_plain;
  } else if (typeof parsed?.plain_body === 'string' && parsed.plain_body.trim()) {
    rawPlain = parsed.plain_body;
  } else if (parsed?.body && typeof parsed.body === 'object') {
    if (typeof parsed.body.plain === 'string' && parsed.body.plain.trim()) {
      rawPlain = parsed.body.plain;
    } else if (typeof parsed.body.normalized === 'string' && parsed.body.normalized.trim()) {
      rawPlain = parsed.body.normalized;
    }
  }

  const emailHtml = rawHtml ? sanitizeHtml(rawHtml) : null;
  const emailText = typeof rawPlain === 'string' 
    ? rawPlain 
    : (rawPlain ? JSON.stringify(rawPlain, null, 2) : (typeof parsed?.body === 'string' ? parsed.body : ''));

  const findingsCount = Array.isArray(forensicAnalysis?.findings) 
    ? forensicAnalysis.findings.length 
    : 0;

  const graphNodesCount = Array.isArray(correlationData?.graph?.nodes) 
    ? correlationData.graph.nodes.length 
    : 0;

  const tabs = [
    { id: 'overview', label: 'Executive Summary', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
    { id: 'forensics', label: 'Deep Forensics', count: findingsCount, icon: <Search className="w-3.5 h-3.5" /> },
    { id: 'threat', label: 'Threat Intelligence', icon: <Code className="w-3.5 h-3.5" /> },
    { id: 'infrastructure', label: 'Infrastructure & Geo', icon: <Compass className="w-3.5 h-3.5" /> },
    { id: 'graph', label: 'Investigation Graph', count: graphNodesCount, icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'integrity', label: 'Evidence Integrity', icon: <ShieldCheck className="w-3.5 h-3.5" /> },
    { id: 'raw_email', label: 'Email Content', icon: <Mail className="w-3.5 h-3.5" /> },
  ];

  const authAlignmentObj = {
    spf_aligned: parsed?.authentication?.spf?.aligned ?? null,
    dkim_aligned: parsed?.authentication?.dkim?.aligned ?? null,
    dmarc_aligned: parsed?.authentication?.dmarc?.aligned ?? null,
    dmarc_pass: parsed?.authentication?.dmarc?.status === 'pass',
    header_from_domain: senderDomain || null,
    envelope_from_domain: returnPathDomain || null,
    dkim_domain: dkimDomain || null,
  };

  const identityEmailObj = {
    from: senderEmail || null,
    from_display: senderDisplayName || null,
    to: toRecipients,
    cc: ccRecipients,
    subject: emailSubject || null,
    date: emailDate || null,
    message_id: messageId || null,
    reply_to: replyToEmail || null,
    return_path: returnPathEmail || null,
  };

  const relayTraceObj = {
    hop_count: relay?.hop_count || (Array.isArray(relay?.chain || relay?.received_chain) ? (relay?.chain || relay?.received_chain).length : 0),
    received_chain: Array.isArray(relay?.chain || relay?.received_chain) ? (relay.chain || relay.received_chain) : [],
    public_ips: Array.isArray(relay?.public_ips_observed || relay?.public_ips) ? (relay.public_ips_observed || relay.public_ips) : [],
    earliest_node: relay?.earliest_observed_node || relay?.earliest_node || null,
    confidence_note: typeof relay?.confidence_note === 'string' ? relay.confidence_note : null,
  };

  const riskScore = typeof caseData?.risk_score === 'number' 
    ? caseData.risk_score 
    : (typeof (risk as any)?.risk_score === 'number' ? (risk as any).risk_score : 0);

  const bannerSeverity: 'CRITICAL' | 'WARNING' | 'INFO' = riskScore >= 75 ? 'CRITICAL' : riskScore >= 40 ? 'WARNING' : 'INFO';

  const warningBanner = (caseData as any)?.behavioral_relationship?.warning_banner || {
    severity: bannerSeverity,
    title: riskScore >= 75 
      ? '🚨 CRITICAL: SUSPECTED PHISHING / IMPERSONATION ATTACK' 
      : riskScore >= 40 
      ? '⚠️ CAUTION: EXTERNAL SENDER WITH ELEVATED RISK' 
      : 'ℹ️ NOTICE: EXTERNAL COMMUNICATION',
    message: riskScore >= 75 
      ? `This email scored ${riskScore}/100 and violated organizational security policies. Do not click links or provide credentials.`
      : `Message originated outside your corporate domain from <${senderEmail || 'external'}>. Exercise standard caution.`,
    color: riskScore >= 75 ? '#ef4444' : riskScore >= 40 ? '#f59e0b' : '#38bdf8',
    border_color: riskScore >= 75 ? '#dc2626' : riskScore >= 40 ? '#d97706' : '#0284c7',
    bg_color: riskScore >= 75 ? 'rgba(239, 68, 68, 0.15)' : riskScore >= 40 ? 'rgba(245, 158, 11, 0.12)' : 'rgba(2, 132, 199, 0.12)',
    tags: [riskLabel, 'EXTERNAL', ...(Array.isArray(threatAnalysis?.tactics) ? threatAnalysis.tactics : [])],
    html_injected: '',
    plaintext_injected: '',
  };

  return (
    <div className={`space-y-6 ${className}`}>
      
      {/* Top Header Card / Case Metadata Bar */}
      <Card className="border-cyber-borderLight">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          
          {/* Back Action & Case Overview */}
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Button
                variant="ghost"
                size="sm"
                icon={<ArrowLeft className="w-3.5 h-3.5" />}
                onClick={onBack}
              >
                Back to Cases
              </Button>
              <Badge variant="severity" severity={riskLabel} />
              {caseData?.campaign_id && (
                <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-bold">
                  CAMPAIGN: {String(caseData.campaign_id)}
                </span>
              )}
            </div>

            <div>
              <h1 className="text-xl sm:text-2xl font-mono font-extrabold text-slate-100 flex items-center gap-2">
                <span>CASE: {originalFilename}</span>
              </h1>
              <div className="flex items-center space-x-3 text-xs font-mono text-slate-400 mt-1">
                <span>SUBJECT: <strong className="text-slate-200">{emailSubject}</strong></span>
                <span>•</span>
                <span>INGESTED: {caseData?.created_at ? formatDate(caseData.created_at) : 'RECENT'}</span>
              </div>
            </div>
          </div>

          {/* Quick Copy Identifiers & Actions */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 shrink-0">
            {/* Case ID Copy */}
            {caseId && (
              <button
                onClick={() => copyToClipboard(caseId, 'case_id')}
                className="px-3 py-1.5 rounded bg-cyber-bg border border-cyber-border hover:border-cyber-cyan/50 text-slate-300 font-mono text-[11px] flex items-center justify-between space-x-2 transition"
                title="Copy full Case UUID"
              >
                <span>ID: {caseId.slice(0, 8)}…</span>
                {copiedField === 'case_id' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                )}
              </button>
            )}

            {/* SHA-256 Copy */}
            {caseData?.evidence_hash && (
              <button
                onClick={() => copyToClipboard(caseData.evidence_hash, 'hash')}
                className="px-3 py-1.5 rounded bg-cyber-bg border border-cyber-border hover:border-cyber-cyan/50 text-slate-300 font-mono text-[11px] flex items-center justify-between space-x-2 transition"
                title="Copy SHA-256 evidence anchor"
              >
                <span>SHA-256: {truncateHash(caseData.evidence_hash, 6)}</span>
                {copiedField === 'hash' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                )}
              </button>
            )}

            {/* Mimecast-style Quick Quarantine Button */}
            <Button
              variant="danger"
              size="sm"
              icon={<ShieldAlert className="w-3.5 h-3.5" />}
              onClick={() => handleQuarantineAction('QUARANTINED')}
              className="font-mono text-xs"
            >
              Quarantine
            </Button>

            {/* Export Forensic Dossier Button */}
            <Button
              variant="outline"
              size="sm"
              icon={<FileText className="w-3.5 h-3.5 text-cyber-cyan" />}
              onClick={() => setIsReportModalOpen(true)}
              className="font-mono text-xs border-cyber-cyan/30 hover:border-cyber-cyan text-cyber-cyan"
            >
              Export Dossier
            </Button>

            {/* View Raw Headers Modal Button */}
            <Button
              variant="outline"
              size="sm"
              icon={<FileCode className="w-3.5 h-3.5" />}
              onClick={() => setIsHeadersModalOpen(true)}
            >
              Raw Headers
            </Button>
          </div>

        </div>

        {/* Quarantine Success Toast */}
        {quarantineMsg && (
          <div className="mt-4 p-3 bg-red-950/80 border border-red-500/50 rounded-lg text-xs font-mono text-red-300 flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <span>{quarantineMsg}</span>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="mt-6 pt-4 border-t border-cyber-border/80">
          <Tabs
            tabs={tabs}
            activeTab={activeTab}
            onChange={(tab) => setActiveTab(tab as any)}
            variant="underline"
          />
        </div>
      </Card>

      {/* ========================================================= */}
      {/* PERSISTENT TAB CONTAINERS (Isolated Error Boundaries)      */}
      {/* ========================================================= */}

      {/* TAB 1: EXECUTIVE SUMMARY */}
      <div className={activeTab === 'overview' ? 'block space-y-6' : 'hidden'} key="tab-overview">
        <ErrorBoundary fallbackTitle="EXECUTIVE SUMMARY RENDER ERROR">
          
          {/* GreatHorn-style Dynamic Warning Banner */}
          <DynamicBannerPreview banner={warningBanner} />

          {/* Top Row: Risk Hero + Threat Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <RiskScoreHero riskAssessment={risk as any} />
            <ThreatClassificationPanel threatAnalysis={threatAnalysis} />
          </div>

          {/* Second Row: Top Risk Factors + Auth Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <RiskFactorsList factors={risk?.top_factors?.length ? risk.top_factors : (risk?.risk_factors || [])} />
            <AuthenticationMatrix
              auth={auth}
              alignment={authAlignmentObj}
            />
          </div>

          {/* Third Row: Identity Inspector + Relay Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <IdentityInspector
              email={identityEmailObj}
              flags={indicators?.flags || {}}
            />
            <RelayTimeline
              smtpTrace={relayTraceObj}
            />
          </div>
        </ErrorBoundary>
      </div>

      {/* TAB 2: DEEP FORENSICS */}
      <div className={activeTab === 'forensics' ? 'block space-y-6' : 'hidden'} key="tab-forensics">
        <ErrorBoundary fallbackTitle="DEEP FORENSICS RENDER ERROR">
          <ForensicEvidencePanel forensics={forensicAnalysis} />
          <AuthenticationMatrix
            auth={auth}
            alignment={authAlignmentObj}
          />
          <IdentityInspector
            email={identityEmailObj}
            flags={indicators?.flags || {}}
          />
          <RelayTimeline
            smtpTrace={relayTraceObj}
          />
        </ErrorBoundary>
      </div>

      {/* TAB 3: THREAT INTELLIGENCE */}
      <div className={activeTab === 'threat' ? 'block space-y-6' : 'hidden'} key="tab-threat">
        <ErrorBoundary fallbackTitle="THREAT INTELLIGENCE RENDER ERROR">
          <ThreatClassificationPanel threatAnalysis={threatAnalysis} />
          <RiskFactorsList factors={risk?.top_factors?.length ? risk.top_factors : (risk?.risk_factors || [])} />
        </ErrorBoundary>
      </div>

      {/* TAB 4: INFRASTRUCTURE & GEO */}
      <div className={activeTab === 'infrastructure' ? 'block space-y-6' : 'hidden'} key="tab-infrastructure">
        <ErrorBoundary fallbackTitle="INFRASTRUCTURE & GEO RENDER ERROR">
          <GeoMap ips={Array.isArray(ipIntel?.ips) ? ipIntel.ips : []} />
          <InfrastructurePanel
            infrastructure={{
              summary: ipIntel?.summary || {},
              ips: Array.isArray(ipIntel?.ips) ? ipIntel.ips : [],
              domains: Array.isArray(domainIntel?.domains) ? domainIntel.domains : [],
              urls: Array.isArray(urlIntel?.urls) ? urlIntel.urls : [],
              limitations: [],
            }}
          />
        </ErrorBoundary>
      </div>

      {/* TAB 5: INVESTIGATION GRAPH */}
      <div className={activeTab === 'graph' ? 'block space-y-6' : 'hidden'} key="tab-graph">
        <ErrorBoundary fallbackTitle="INVESTIGATION GRAPH RENDER ERROR">
          <InvestigationGraphView
            graph={correlationData?.graph || { nodes: [], edges: [] }}
            selectedCaseId={caseId}
            onSelectCase={onSelectRelatedCase}
          />
        </ErrorBoundary>
      </div>

      {/* TAB 6: EVIDENCE INTEGRITY & BLOCKCHAIN ANCHORING */}
      <div className={activeTab === 'integrity' ? 'block space-y-6' : 'hidden'} key="tab-integrity">
        <ErrorBoundary fallbackTitle="EVIDENCE INTEGRITY RENDER ERROR">
          <EvidenceIntegrityPanel
            caseId={caseId}
            initialEvidenceHash={caseData?.evidence_hash}
          />
        </ErrorBoundary>
      </div>

      {/* TAB 7: EMAIL CONTENT (SAFE SANITIZED PREVIEW) */}
      <div className={activeTab === 'raw_email' ? 'block space-y-6' : 'hidden'} key="tab-raw_email">
        <ErrorBoundary fallbackTitle="EMAIL PREVIEW RENDER ERROR">
          <Card
            title="EXTRACTED EMAIL BODY & MIME CONTENT"
            subtitle="Sandboxed defense-in-depth HTML rendering (scripts stripped, active clicks defanged) & plain text audit"
            icon={<Mail className="w-4 h-4 text-cyber-cyan" />}
            headerActions={
              <div className="flex items-center space-x-2">
                {emailHtml && (
                  <div className="flex items-center space-x-1 p-0.5 rounded-lg bg-cyber-bg border border-cyber-border font-mono text-[11px]">
                    <button
                      onClick={() => setEmailViewMode('html')}
                      className={`px-2.5 py-1 rounded transition ${
                        emailViewMode === 'html'
                          ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-[0_0_8px_rgba(0,240,255,0.2)]'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      RENDERED HTML
                    </button>
                    <button
                      onClick={() => setEmailViewMode('plain')}
                      className={`px-2.5 py-1 rounded transition ${
                        emailViewMode === 'plain'
                          ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-[0_0_8px_rgba(0,240,255,0.2)]'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      PLAIN TEXT
                    </button>
                  </div>
                )}
                <button
                  onClick={() => copyToClipboard(emailText || (rawHtml || ''), 'body')}
                  className="px-2.5 py-1 rounded bg-cyber-bg border border-cyber-border hover:border-cyber-cyan/50 text-slate-300 font-mono text-xs flex items-center space-x-1.5 transition"
                  title="Copy email body to clipboard"
                >
                  {copiedField === 'body' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">COPIED</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-400" />
                      <span>COPY BODY</span>
                    </>
                  )}
                </button>
              </div>
            }
          >
            <div className="space-y-4">
              {emailHtml && emailViewMode === 'html' ? (
                <div className="p-5 rounded-lg bg-slate-900/90 border border-cyber-border max-h-[600px] overflow-y-auto">
                  <div
                    dangerouslySetInnerHTML={{ __html: emailHtml }}
                    className="prose prose-invert max-w-none text-slate-200 text-xs leading-relaxed"
                  />
                </div>
              ) : (
                <pre className="p-5 rounded-lg bg-slate-950 border border-cyber-border font-mono text-xs text-slate-200 whitespace-pre-wrap max-h-[600px] overflow-y-auto leading-relaxed shadow-inner">
                  {emailText || '(No plain-text body content extracted)'}
                </pre>
              )}
            </div>
          </Card>
        </ErrorBoundary>
      </div>

      {/* Raw RFC 5322 Headers Modal */}
      <Modal
        isOpen={isHeadersModalOpen}
        onClose={() => setIsHeadersModalOpen(false)}
        title="RFC 5322 RAW HEADER AUDIT"
        subtitle={`Case ID: ${caseId}`}
        maxWidth="4xl"
      >
        <div className="space-y-4">
          <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border font-mono text-xs space-y-2 max-h-[65vh] overflow-y-auto">
            {!rawHeaders || Object.keys(rawHeaders).length === 0 ? (
              <div className="text-slate-500">No raw headers available.</div>
            ) : (
              Object.entries(rawHeaders).map(([hdrKey, val]) => (
                <div key={hdrKey} className="pb-2 border-b border-cyber-border/40 last:border-b-0">
                  <span className="font-bold text-cyber-cyan select-all">{hdrKey}: </span>
                  <span className="text-slate-300 break-all select-all">
                    {Array.isArray(val) ? val.join('\n  ') : String(val)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </Modal>

      {/* Forensic Report Dossier Modal */}
      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        caseData={caseData}
        correlationData={correlationData}
      />

    </div>
  );
};
