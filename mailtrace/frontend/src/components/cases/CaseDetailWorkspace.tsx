import React, { useState } from 'react';
import { 
  FolderLock, 
  Copy, 
  Check, 
  FileCode, 
  ShieldAlert, 
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
  const [activeTab, setActiveTab] = useState<'overview' | 'forensics' | 'threat' | 'infrastructure' | 'graph' | 'raw_email'>('overview');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isHeadersModalOpen, setIsHeadersModalOpen] = useState(false);

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const parsed = caseData.parsed_email || {};
  const headers = parsed.headers || {};
  const sender = parsed.sender || {};
  const recips = parsed.recipients || {};
  const auth = parsed.authentication || {};
  const relay = parsed.received_chain || {};
  const indicators = parsed.indicators || {};
  const risk = caseData.risk_reasons || {
    risk_score: caseData.risk_score || 0,
    severity: caseData.risk_label || 'LOW',
    risk_factors: [],
    category_scores: {},
    top_factors: [],
    explanation: '',
    confidence: 0.8,
    limitations: [],
  };

  const rawHeaders = parsed.raw_headers || {};
  const emailHtml = parsed.html_body ? sanitizeHtml(parsed.html_body) : null;
  const emailText = parsed.body || '';

  const tabs = [
    { id: 'overview', label: 'Executive Summary', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
    { id: 'forensics', label: 'Deep Forensics', count: caseData.forensic_analysis?.findings?.length, icon: <Search className="w-3.5 h-3.5" /> },
    { id: 'threat', label: 'Threat Intelligence', icon: <Code className="w-3.5 h-3.5" /> },
    { id: 'infrastructure', label: 'Infrastructure & Geo', icon: <Compass className="w-3.5 h-3.5" /> },
    { id: 'graph', label: 'Investigation Graph', count: correlationData?.graph?.nodes?.length, icon: <Network className="w-3.5 h-3.5" /> },
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
              <Badge variant="severity" severity={caseData.risk_label || 'LOW'} />
              {caseData.campaign_id && (
                <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-bold">
                  CAMPAIGN: {caseData.campaign_id}
                </span>
              )}
            </div>

            <div>
              <h1 className="text-xl sm:text-2xl font-mono font-extrabold text-slate-100 flex items-center gap-2">
                <span>CASE: {caseData.original_filename}</span>
              </h1>
              <div className="flex items-center space-x-3 text-xs font-mono text-slate-400 mt-1">
                <span>SUBJECT: <strong className="text-slate-200">{headers.subject || '(No Subject)'}</strong></span>
                <span>•</span>
                <span>INGESTED: {formatDate(caseData.created_at)}</span>
              </div>
            </div>
          </div>

          {/* Quick Copy Identifiers & Actions */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 shrink-0">
            {/* Case ID Copy */}
            <button
              onClick={() => copyToClipboard(caseData.case_id, 'case_id')}
              className="px-3 py-1.5 rounded bg-cyber-bg border border-cyber-border hover:border-cyber-cyan/50 text-slate-300 font-mono text-[11px] flex items-center justify-between space-x-2 transition"
              title="Copy full Case UUID"
            >
              <span>ID: {caseData.case_id.slice(0, 8)}…</span>
              {copiedField === 'case_id' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5 text-slate-500" />
              )}
            </button>

            {/* SHA-256 Copy */}
            {caseData.evidence_hash && (
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
            <ThreatClassificationPanel threatAnalysis={caseData.ai_analysis} />
          </div>

          {/* Second Row: Top Risk Factors + Auth Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <RiskFactorsList factors={risk.top_factors || risk.risk_factors || []} />
            <AuthenticationMatrix
              auth={auth}
              alignment={{
                spf_aligned: parsed.authentication?.spf?.aligned,
                dkim_aligned: parsed.authentication?.dkim?.aligned,
                dmarc_aligned: parsed.authentication?.dmarc?.aligned,
                dmarc_pass: parsed.authentication?.dmarc?.status === 'pass',
                header_from_domain: sender.domain,
                envelope_from_domain: parsed.return_path?.domain,
                dkim_domain: parsed.authentication?.dkim?.domain,
              }}
            />
          </div>

          {/* Third Row: Identity Inspector + Relay Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <IdentityInspector
              email={{
                from: sender.email,
                from_display: sender.display_name,
                to: (recips.to || []).map((r: any) => r.email),
                cc: (recips.cc || []).map((r: any) => r.email),
                subject: headers.subject,
                date: headers.date_iso || headers.date_raw,
                message_id: headers.message_id,
                reply_to: parsed.reply_to?.email,
                return_path: parsed.return_path?.email,
              }}
              flags={indicators.flags}
            />
            <RelayTimeline
              smtpTrace={{
                hop_count: relay.hop_count || 0,
                received_chain: relay.chain || [],
                public_ips: relay.public_ips_observed || [],
                earliest_node: relay.earliest_observed_node,
                confidence_note: relay.confidence_note,
              }}
            />
          </div>
        </div>
      )}

      {/* TAB 2: DEEP FORENSICS */}
      {activeTab === 'forensics' && (
        <div className="space-y-6">
          <ForensicEvidencePanel forensics={caseData.forensic_analysis} />
          <AuthenticationMatrix
            auth={auth}
            alignment={{
              spf_aligned: parsed.authentication?.spf?.aligned,
              dkim_aligned: parsed.authentication?.dkim?.aligned,
              dmarc_aligned: parsed.authentication?.dmarc?.aligned,
              dmarc_pass: parsed.authentication?.dmarc?.status === 'pass',
              header_from_domain: sender.domain,
              envelope_from_domain: parsed.return_path?.domain,
              dkim_domain: parsed.authentication?.dkim?.domain,
            }}
          />
          <IdentityInspector
            email={{
              from: sender.email,
              from_display: sender.display_name,
              to: (recips.to || []).map((r: any) => r.email),
              cc: (recips.cc || []).map((r: any) => r.email),
              subject: headers.subject,
              date: headers.date_iso || headers.date_raw,
              message_id: headers.message_id,
              reply_to: parsed.reply_to?.email,
              return_path: parsed.return_path?.email,
            }}
            flags={indicators.flags}
          />
          <RelayTimeline
            smtpTrace={{
              hop_count: relay.hop_count || 0,
              received_chain: relay.chain || [],
              public_ips: relay.public_ips_observed || [],
              earliest_node: relay.earliest_observed_node,
              confidence_note: relay.confidence_note,
            }}
          />
        </div>
      )}

      {/* TAB 3: THREAT INTELLIGENCE */}
      {activeTab === 'threat' && (
        <div className="space-y-6">
          <ThreatClassificationPanel threatAnalysis={caseData.ai_analysis} />
          <RiskFactorsList factors={risk.top_factors || risk.risk_factors || []} />
        </div>
      )}

      {/* TAB 4: INFRASTRUCTURE & GEO */}
      {activeTab === 'infrastructure' && (
        <div className="space-y-6">
          <GeoMap ips={caseData.ip_intel?.ips || []} />
          <InfrastructurePanel
            infrastructure={{
              summary: caseData.ip_intel?.summary || {},
              ips: caseData.ip_intel?.ips || [],
              domains: caseData.domain_intel?.domains || [],
              urls: caseData.url_intel?.urls || [],
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
            selectedCaseId={caseData.case_id}
            onSelectCase={onSelectRelatedCase}
          />
        </div>
      )}

      {/* TAB 6: EMAIL CONTENT (SAFE SANITIZED PREVIEW) */}
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
        subtitle={`Case ID: ${caseData.case_id}`}
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
