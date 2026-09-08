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
  ArrowLeft
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Tabs } from '../ui/Tabs';
import { Modal } from '../ui/Modal';
import { formatDate, truncateHash } from '../../lib/utils';
import { sanitizeHtml } from '../../lib/sanitize';
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
  className,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'forensics' | 'threat' | 'infrastructure' | 'graph' | 'integrity' | 'raw_email'>('overview');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isHeadersModalOpen, setIsHeadersModalOpen] = useState(false);

  const copyToClipboard = (text: string, field: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const caseId = caseData?.case_id || '';
  const originalFilename = caseData?.original_filename || 'unknown.eml';
  const riskLabel = caseData?.risk_label || 'LOW';

  const parsed = caseData?.parsed_email || (caseData as any)?.email_analysis?.parsed_email || {};
  const headers = parsed?.headers || parsed || {};
  const sender = parsed?.sender || {
    email: parsed?.from_address || parsed?.from || null,
    display_name: parsed?.from_display_name || parsed?.from_display || null,
    domain: parsed?.from_domain || (typeof parsed?.from_address === 'string' ? parsed.from_address.split('@')[1] : null),
  };
  const recips = parsed?.recipients || {
    to: parsed?.to_addresses || parsed?.to || [],
    cc: parsed?.cc_addresses || parsed?.cc || [],
  };
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

  const toRecipients = Array.isArray(recips.to)
    ? recips.to.map((r: any) => (typeof r === 'string' ? r : r?.address || r?.email || '')).filter(Boolean)
    : typeof recips.to === 'string' ? [recips.to] : [];

  const ccRecipients = Array.isArray(recips.cc)
    ? recips.cc.map((r: any) => (typeof r === 'string' ? r : r?.address || r?.email || '')).filter(Boolean)
    : typeof recips.cc === 'string' ? [recips.cc] : [];

  const rawHeaders = parsed.raw_headers && typeof parsed.raw_headers === 'object' 
    ? parsed.raw_headers 
    : typeof parsed.raw_headers === 'string' 
    ? { 'Raw Headers': parsed.raw_headers }
    : {};
  const emailHtml = parsed.html_body || parsed.body_html ? sanitizeHtml(parsed.html_body || parsed.body_html) : null;
  const emailText = parsed.body || parsed.body_plain || '';

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

  return (
    <div className={`space-y-6 ${className || ''}`}>
      
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
                  CAMPAIGN: {caseData.campaign_id}
                </span>
              )}
            </div>

            <div>
              <h1 className="text-xl sm:text-2xl font-mono font-extrabold text-slate-100 flex items-center gap-2">
                <span>CASE: {originalFilename}</span>
              </h1>
              <div className="flex items-center space-x-3 text-xs font-mono text-slate-400 mt-1">
                <span>SUBJECT: <strong className="text-slate-200">{headers?.subject || parsed?.subject || '(No Subject)'}</strong></span>
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
                onClick={() => copyToClipboard(caseData.evidence_hash!, 'hash')}
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

      {/* TAB 1: EXECUTIVE SUMMARY */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Top Row: Risk Hero + Threat Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <RiskScoreHero riskAssessment={risk as any} />
            <ThreatClassificationPanel threatAnalysis={threatAnalysis} />
          </div>

          {/* Second Row: Top Risk Factors + Auth Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <RiskFactorsList factors={risk.top_factors?.length ? risk.top_factors : (risk.risk_factors || [])} />
            <AuthenticationMatrix
              auth={auth}
              alignment={{
                spf_aligned: parsed?.authentication?.spf?.aligned,
                dkim_aligned: parsed?.authentication?.dkim?.aligned,
                dmarc_aligned: parsed?.authentication?.dmarc?.aligned,
                dmarc_pass: parsed?.authentication?.dmarc?.status === 'pass',
                header_from_domain: sender?.domain,
                envelope_from_domain: parsed?.return_path?.domain,
                dkim_domain: parsed?.authentication?.dkim?.domain,
              }}
            />
          </div>

          {/* Third Row: Identity Inspector + Relay Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <IdentityInspector
              email={{
                from: sender?.email || null,
                from_display: sender?.display_name || null,
                to: toRecipients,
                cc: ccRecipients,
                subject: headers?.subject || null,
                date: headers?.date_iso || headers?.date_raw || null,
                message_id: headers?.message_id || null,
                reply_to: parsed?.reply_to?.email || null,
                return_path: parsed?.return_path?.email || null,
              }}
              flags={indicators?.flags}
            />
            <RelayTimeline
              smtpTrace={{
                hop_count: relay?.hop_count || 0,
                received_chain: relay?.chain || [],
                public_ips: relay?.public_ips_observed || [],
                earliest_node: relay?.earliest_observed_node || null,
                confidence_note: relay?.confidence_note,
              }}
            />
          </div>
        </div>
      )}

      {/* TAB 2: DEEP FORENSICS */}
      {activeTab === 'forensics' && (
        <div className="space-y-6">
          <ForensicEvidencePanel forensics={forensicAnalysis} />
          <AuthenticationMatrix
            auth={auth}
            alignment={{
              spf_aligned: parsed?.authentication?.spf?.aligned,
              dkim_aligned: parsed?.authentication?.dkim?.aligned,
              dmarc_aligned: parsed?.authentication?.dmarc?.aligned,
              dmarc_pass: parsed?.authentication?.dmarc?.status === 'pass',
              header_from_domain: sender?.domain,
              envelope_from_domain: parsed?.return_path?.domain,
              dkim_domain: parsed?.authentication?.dkim?.domain,
            }}
          />
          <IdentityInspector
            email={{
              from: sender?.email || null,
              from_display: sender?.display_name || null,
              to: toRecipients,
              cc: ccRecipients,
              subject: headers?.subject || null,
              date: headers?.date_iso || headers?.date_raw || null,
              message_id: headers?.message_id || null,
              reply_to: parsed?.reply_to?.email || null,
              return_path: parsed?.return_path?.email || null,
            }}
            flags={indicators?.flags}
          />
          <RelayTimeline
            smtpTrace={{
              hop_count: relay?.hop_count || 0,
              received_chain: relay?.chain || [],
              public_ips: relay?.public_ips_observed || [],
              earliest_node: relay?.earliest_observed_node || null,
              confidence_note: relay?.confidence_note,
            }}
          />
        </div>
      )}

      {/* TAB 3: THREAT INTELLIGENCE */}
      {activeTab === 'threat' && (
        <div className="space-y-6">
          <ThreatClassificationPanel threatAnalysis={threatAnalysis} />
          <RiskFactorsList factors={risk.top_factors?.length ? risk.top_factors : (risk.risk_factors || [])} />
        </div>
      )}

      {/* TAB 4: INFRASTRUCTURE & GEO */}
      {activeTab === 'infrastructure' && (
        <div className="space-y-6">
          <GeoMap ips={ipIntel?.ips || []} />
          <InfrastructurePanel
            infrastructure={{
              summary: ipIntel?.summary || {},
              ips: ipIntel?.ips || [],
              domains: domainIntel?.domains || [],
              urls: urlIntel?.urls || [],
              limitations: [],
            }}
          />
        </div>
      )}

      {/* TAB 5: INVESTIGATION GRAPH */}
      {activeTab === 'graph' && (
        <div className="space-y-6">
          <InvestigationGraphView
            graph={correlationData?.graph || { nodes: [], edges: [] }}
            selectedCaseId={caseId}
            onSelectCase={onSelectRelatedCase}
          />
        </div>
      )}

      {/* TAB 6: EVIDENCE INTEGRITY & BLOCKCHAIN ANCHORING */}
      {activeTab === 'integrity' && (
        <EvidenceIntegrityPanel
          caseId={caseId}
          initialEvidenceHash={caseData?.evidence_hash}
        />
      )}

      {/* TAB 7: EMAIL CONTENT (SAFE SANITIZED PREVIEW) */}
      {activeTab === 'raw_email' && (
        <div className="space-y-6">
          <Card
            title="EXTRACTED EMAIL BODY"
            subtitle="Sandboxed defense-in-depth HTML rendering (scripts stripped, active clicks defanged)"
            icon={<Mail className="w-4 h-4 text-cyber-cyan" />}
          >
            <div className="space-y-4">
              {emailHtml ? (
                <div className="p-4 rounded-lg bg-slate-900 border border-cyber-border max-h-[600px] overflow-y-auto">
                  <div
                    dangerouslySetInnerHTML={{ __html: emailHtml }}
                    className="prose prose-invert max-w-none text-slate-200 text-xs"
                  />
                </div>
              ) : (
                <pre className="p-4 rounded-lg bg-cyber-surface border border-cyber-border font-mono text-xs text-slate-300 whitespace-pre-wrap max-h-[600px] overflow-y-auto">
                  {emailText || '(No plain-text body content extracted)'}
                </pre>
              )}
            </div>
          </Card>
        </div>
      )}

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
            {Object.keys(rawHeaders).length === 0 ? (
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

    </div>
  );
};
