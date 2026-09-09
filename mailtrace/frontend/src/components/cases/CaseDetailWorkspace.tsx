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
  FileText,
  Crosshair,
  Cpu,
  Download,
  Terminal,
  Activity,
  AlertTriangle,
  FileSpreadsheet
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
import { remediateQuarantine, exportCaseIoCs } from '../../lib/api';
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
import type { CaseDetail, CaseCorrelationDetailResponse, IoCExportResponse } from '../../types/api';

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
  const [isIoCModalOpen, setIsIoCModalOpen] = useState(false);
  const [iocData, setIocData] = useState<IoCExportResponse | null>(null);
  const [loadingIoc, setLoadingIoc] = useState<boolean>(false);
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

  const handleOpenIoCModal = async () => {
    setIsIoCModalOpen(true);
    setLoadingIoc(true);
    try {
      const data = await exportCaseIoCs(caseId);
      setIocData(data);
    } catch (err) {
      console.error('Failed to export IoCs:', err);
    } finally {
      setLoadingIoc(false);
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

  const funnelOfFidelity = threatAnalysis?.funnel_of_fidelity;
  const compoundRules = threatAnalysis?.compound_rules || [];
  const mitreAttack = threatAnalysis?.mitre_attack || [];
  const saasAbuse = threatAnalysis?.saas_abuse || [];

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
    { id: 'threat', label: 'Threat Intel & Fidelity', icon: <Crosshair className="w-3.5 h-3.5" /> },
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
    message_id: messageId,
    reply_to: replyToEmail,
    return_path: returnPathEmail,
  };

  const relayTraceObj = {
    hop_count: typeof relay?.hop_count === 'number' ? relay.hop_count : (Array.isArray(relay?.chain) ? relay.chain.length : 0),
    received_chain: Array.isArray(relay?.chain) ? relay.chain : (Array.isArray(relay?.received_chain) ? relay.received_chain : []),
    public_ips: Array.isArray(relay?.public_ips_observed) ? relay.public_ips_observed : (Array.isArray(relay?.public_ips) ? relay.public_ips : []),
    earliest_node: relay?.earliest_observed_node || relay?.earliest_node || null,
    confidence_note: relay?.confidence_note || null,
  };

  const warningBanner = (caseData as any)?.behavioral_relationship?.warning_banner;

  return (
    <div className={`space-y-6 animate-fade-in ${className}`}>
      
      {/* Top Workspace Header Bar */}
      <Card className="p-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          
          <div className="space-y-2">
            <div className="flex items-center space-x-3">
              <Button
                variant="ghost"
                size="sm"
                icon={<ArrowLeft className="w-4 h-4" />}
                onClick={onBack}
                className="font-mono text-xs text-slate-400 hover:text-cyber-cyan"
              >
                Back to Cases
              </Button>
              <div className="h-4 w-px bg-cyber-border" />
              <Badge variant="severity" severity={riskLabel} size="md">
                {riskLabel} RISK
              </Badge>
              {caseData?.campaign_id && (
                <span className="px-2 py-0.5 rounded bg-red-950/70 border border-red-500/40 text-[10px] font-mono font-bold text-red-400">
                  {caseData.campaign_id}
                </span>
              )}
            </div>

            <div className="flex items-center space-x-3">
              <h1 className="text-xl font-mono font-bold text-slate-100 truncate max-w-xl">
                {originalFilename}
              </h1>
              <span className="text-xs font-mono text-slate-500">
                ({caseId.slice(0, 8)}…)
              </span>
            </div>

            {emailSubject && (
              <p className="text-xs font-mono text-cyan-300 font-medium truncate max-w-xl">
                {emailSubject}
              </p>
            )}

            <p className="text-xs font-mono text-slate-400">
              Analyzed at {formatDate(caseData?.created_at)} • SHA-256 Verified
            </p>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {caseData?.evidence_hash && (
              <button
                onClick={() => copyToClipboard(caseData.evidence_hash, 'hash')}
                className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded bg-cyber-surface border border-cyber-border hover:border-cyber-cyan/40 text-xs font-mono text-slate-300 transition"
                title="Copy SHA-256 evidence commitment hash"
              >
                <span>SHA-256: {truncateHash(caseData.evidence_hash, 6)}</span>
                {copiedField === 'hash' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                )}
              </button>
            )}

            {/* Quarantine Button */}
            <Button
              variant="danger"
              size="sm"
              icon={<ShieldAlert className="w-3.5 h-3.5" />}
              onClick={() => handleQuarantineAction('QUARANTINED')}
              className="font-mono text-xs"
            >
              Quarantine
            </Button>

            {/* Export IoC Manifest Button */}
            <Button
              variant="outline"
              size="sm"
              icon={<Crosshair className="w-3.5 h-3.5 text-indigo-400" />}
              onClick={handleOpenIoCModal}
              className="font-mono text-xs border-indigo-500/40 hover:border-indigo-400 text-indigo-300"
            >
              Export IoCs
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

      {/* TAB 3: THREAT INTELLIGENCE & FIDELITY */}
      <div className={activeTab === 'threat' ? 'block space-y-6' : 'hidden'} key="tab-threat">
        <ErrorBoundary fallbackTitle="THREAT INTELLIGENCE RENDER ERROR">
          
          {/* Funnel of Fidelity (SpecterOps 4-Tier Model) */}
          {funnelOfFidelity && (
            <Card className="p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                    <Layers className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-100">Funnel of Fidelity (SpecterOps Model)</h3>
                    <p className="text-xs text-slate-400">4-Tier Distillation: Facts → Inferences → Compounds → Verdict</p>
                  </div>
                </div>
                <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                  {funnelOfFidelity.fidelity_tier}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* Tier 1 */}
                <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Tier 1: Observed Facts</div>
                  <div className="space-y-1 text-xs text-slate-300">
                    {funnelOfFidelity.tier_1_observed_facts.map((fact: string, i: number) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className="text-cyan-400">•</span>
                        <span className="line-clamp-2">{fact}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Tier 2 */}
                <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-xs font-bold text-amber-400 uppercase tracking-wider">Tier 2: Inferences</div>
                  <div className="space-y-1 text-xs text-slate-300">
                    {funnelOfFidelity.tier_2_behavioral_signals.slice(0, 4).map((sig: any, i: number) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className="text-amber-400">•</span>
                        <span className="line-clamp-2">{sig.description}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Tier 3 */}
                <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-xs font-bold text-rose-400 uppercase tracking-wider">Tier 3: Compound Rules</div>
                  <div className="space-y-1 text-xs text-slate-300">
                    {funnelOfFidelity.tier_3_compound_detections.length > 0 ? (
                      funnelOfFidelity.tier_3_compound_detections.map((cr: any, i: number) => (
                        <div key={i} className="flex items-start gap-1.5">
                          <span className="text-rose-400">⚡</span>
                          <span className="font-mono text-[11px] text-rose-300">{cr.name}</span>
                        </div>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 italic">No compound alerts</span>
                    )}
                  </div>
                </div>

                {/* Tier 4 */}
                <div className="p-4 bg-indigo-950/40 rounded-xl border border-indigo-800/60 space-y-2">
                  <div className="text-xs font-bold text-indigo-300 uppercase tracking-wider">Tier 4: Actionable Verdict</div>
                  <div className="text-lg font-bold text-white">
                    {funnelOfFidelity.tier_4_actionable_verdict.verdict}
                  </div>
                  <div className="text-xs text-slate-400">
                    Confidence: {Math.round(funnelOfFidelity.tier_4_actionable_verdict.confidence * 100)}%
                  </div>
                  <div className="text-[11px] font-mono text-indigo-400">
                    {funnelOfFidelity.tier_4_actionable_verdict.requires_quarantine ? '⚠️ QUARANTINE REQUIRED' : '✓ DELIVER WITH BANNER'}
                  </div>
                </div>
              </div>
            </Card>
          )}

          {/* MITRE ATT&CK for Enterprise Email Mapping */}
          {mitreAttack && mitreAttack.length > 0 && (
            <Card className="p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-cyber-cyan" />
                  <h3 className="text-base font-bold text-slate-100">MITRE ATT&CK® Enterprise Email Matrix</h3>
                </div>
                <span className="text-xs font-mono text-slate-400">{mitreAttack.length} Techniques Mapped</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {mitreAttack.map((tech: any) => (
                  <div key={tech.id || tech.technique_id} className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        {tech.technique_id || tech.id}
                      </span>
                      <span className="text-[10px] uppercase font-mono text-slate-400">{tech.tactic}</span>
                    </div>
                    <div className="text-xs font-semibold text-slate-200">{tech.name}</div>
                    <p className="text-[11px] text-slate-400 line-clamp-2">{tech.description}</p>
                    <a
                      href={tech.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] font-mono text-cyber-cyan hover:underline flex items-center gap-1 pt-1"
                    >
                      MITRE Reference <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Living off Legitimate Services (LOLServices) Alert */}
          {saasAbuse && saasAbuse.length > 0 && (
            <div className="p-4 bg-amber-950/30 border border-amber-500/40 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-amber-300 text-sm font-bold">
                <Cpu className="w-4 h-4 text-amber-400" />
                Living off Legitimate Services (LOLServices) Detected
              </div>
              <p className="text-xs text-slate-300">
                Attacker leverages trusted public cloud platforms to bypass domain reputation scoring:
              </p>
              <div className="flex flex-wrap gap-2 pt-1">
                {saasAbuse.map((saas: any, idx: number) => (
                  <div key={idx} className="px-3 py-1 bg-slate-900 rounded-lg border border-amber-500/30 text-xs font-mono text-amber-200">
                    {saas.platform}: <span className="text-slate-400">{saas.url.slice(0, 50)}…</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Palantir ADS Incident Playbook */}
          {(caseData as any)?.policy_evaluation?.incident_playbook && (
            <Card className="p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                <div className="flex items-center gap-2">
                  <Activity className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-base font-bold text-slate-100">SOC Incident Playbook (Palantir ADS Framework)</h3>
                </div>
                <span className="text-xs font-mono text-emerald-400">L2 Actionable Workflow</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries((caseData as any).policy_evaluation.incident_playbook.phases).map(([phaseKey, phaseObj]: any) => (
                  <div key={phaseKey} className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
                    <div className="text-xs font-bold text-slate-200 uppercase tracking-wider">{phaseObj.title}</div>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {phaseObj.actions.map((act: string, aIdx: number) => (
                        <li key={aIdx} className="flex items-start gap-2">
                          <span className="text-emerald-400 mt-0.5">•</span>
                          <span>{act}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </Card>
          )}

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

      {/* TAB 6: EVIDENCE INTEGRITY */}
      <div className={activeTab === 'integrity' ? 'block space-y-6' : 'hidden'} key="tab-integrity">
        <ErrorBoundary fallbackTitle="EVIDENCE INTEGRITY RENDER ERROR">
          <EvidenceIntegrityPanel
            caseId={caseId}
          />
        </ErrorBoundary>
      </div>

      {/* TAB 7: RAW EMAIL & HEADERS */}
      <div className={activeTab === 'raw_email' ? 'block space-y-6' : 'hidden'} key="tab-raw-email">
        <ErrorBoundary fallbackTitle="EMAIL CONTENT RENDER ERROR">
          <Card className="p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-2">
                <Mail className="w-4 h-4 text-cyber-cyan" />
                <h3 className="font-mono text-sm font-bold text-slate-100 uppercase">
                  Sanitized Email Payload Viewer
                </h3>
              </div>
              
              <div className="flex items-center space-x-2">
                {emailHtml && (
                  <button
                    onClick={() => setEmailViewMode('html')}
                    className={`px-3 py-1 rounded text-xs font-mono transition ${
                      emailViewMode === 'html'
                        ? 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40 font-bold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    HTML
                  </button>
                )}
                <button
                  onClick={() => setEmailViewMode('plain')}
                  className={`px-3 py-1 rounded text-xs font-mono transition ${
                    emailViewMode === 'plain'
                      ? 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Plain Text
                </button>
              </div>
            </div>

            {/* Rendered Email Content with Safe Sandboxing */}
            {emailViewMode === 'html' && emailHtml ? (
              <div className="p-4 bg-white text-slate-900 rounded-lg overflow-auto max-h-[600px] border border-cyber-border">
                <div
                  dangerouslySetInnerHTML={{ __html: emailHtml }}
                  className="prose prose-sm max-w-none font-sans"
                />
              </div>
            ) : (
              <pre className="p-4 bg-cyber-bg text-slate-300 font-mono text-xs rounded-lg overflow-auto max-h-[600px] border border-cyber-border whitespace-pre-wrap">
                {emailText || '(No plain text body content found in message)'}
              </pre>
            )}
          </Card>
        </ErrorBoundary>
      </div>

      {/* Raw Headers Modal */}
      <Modal
        isOpen={isHeadersModalOpen}
        onClose={() => setIsHeadersModalOpen(false)}
        title="RFC-822 Raw Headers Inspector"
        maxWidth="4xl"
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">
              Total Header Fields: {Object.keys(rawHeaders).length}
            </span>
            <Button
              variant="outline"
              size="sm"
              icon={<Copy className="w-3.5 h-3.5" />}
              onClick={() => copyToClipboard(JSON.stringify(rawHeaders, null, 2), 'raw_headers')}
            >
              {copiedField === 'raw_headers' ? 'Copied' : 'Copy All'}
            </Button>
          </div>

          <pre className="p-4 bg-cyber-bg text-cyber-cyan font-mono text-xs rounded-lg overflow-auto max-h-[500px] border border-cyber-border whitespace-pre-wrap">
            {JSON.stringify(rawHeaders, null, 2)}
          </pre>
        </div>
      </Modal>

      {/* IoC Manifest Export Modal */}
      <Modal
        isOpen={isIoCModalOpen}
        onClose={() => setIsIoCModalOpen(false)}
        title="Standardized Technical IoC Manifest (SIEM / EDR)"
        maxWidth="4xl"
      >
        <div className="space-y-4">
          {loadingIoc ? (
            <div className="py-12 text-center text-slate-400 font-mono text-xs">
              Extracting Indicators of Compromise…
            </div>
          ) : iocData ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-300">
                  Total IoCs Identified: <strong className="text-white">{iocData.total_iocs}</strong>
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    icon={<Copy className="w-3.5 h-3.5" />}
                    onClick={() => copyToClipboard(iocData.csv_export, 'csv_ioc')}
                  >
                    {copiedField === 'csv_ioc' ? 'Copied CSV' : 'Copy CSV'}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    icon={<Download className="w-3.5 h-3.5" />}
                    onClick={() => {
                      const blob = new Blob([iocData.csv_export], { type: 'text/csv' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `mailtrace-iocs-${caseId.slice(0, 8)}.csv`;
                      a.click();
                    }}
                  >
                    Download CSV
                  </Button>
                </div>
              </div>

              {/* IoC Table */}
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Type</th>
                      <th className="p-2.5">Indicator Value</th>
                      <th className="p-2.5">Context</th>
                      <th className="p-2.5">MITRE Tactic</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {iocData.iocs.map((ioc: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="p-2.5 text-indigo-400 uppercase font-semibold">{ioc.type}</td>
                        <td className="p-2.5 text-white truncate max-w-xs">{ioc.value}</td>
                        <td className="p-2.5 text-slate-400">{ioc.context}</td>
                        <td className="p-2.5 text-emerald-400">{ioc.mitre_tactic}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* STIX 2.1 Patterns */}
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  STIX 2.1 Pattern Mappings:
                </span>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  {iocData.stix_patterns.join('\n')}
                </pre>
              </div>
            </div>
          ) : (
            <div className="text-xs text-rose-400">Failed to load IoC manifest.</div>
          )}
        </div>
      </Modal>

      {/* Forensic Report Export Dossier Modal */}
      {isReportModalOpen && (
        <ForensicReportModal
          isOpen={isReportModalOpen}
          onClose={() => setIsReportModalOpen(false)}
          caseData={caseData}
        />
      )}

    </div>
  );
};
