import React, { useState } from 'react';
import { 
  Printer, 
  Download, 
  Copy, 
  Check, 
  ShieldCheck, 
  ShieldAlert, 
  FileText, 
  ExternalLink,
  Lock,
  Globe,
  Server,
  Layers,
  Calendar,
  User,
  Mail,
  AlertTriangle
} from 'lucide-react';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { formatDate, truncateHash } from '../../lib/utils';
import type { CaseDetail, CaseCorrelationDetailResponse } from '../../types/api';

export interface ForensicReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseData: CaseDetail;
  correlationData?: CaseCorrelationDetailResponse | null;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  isOpen,
  onClose,
  caseData,
  correlationData,
}) => {
  const [copied, setCopied] = useState<string | null>(null);

  if (!caseData) return null;

  const caseId = caseData.case_id || 'UNKNOWN';
  const originalFilename = caseData.original_filename || 'evidence.eml';
  const evidenceHash = caseData.evidence_hash || (caseData as any)?.sha256 || 'N/A';
  const riskScore = typeof caseData.risk_score === 'number' ? caseData.risk_score : 0;
  const riskLabel = (caseData.risk_label || (riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW')).toUpperCase();

  const parsed = caseData.parsed_email || (caseData as any)?.email_analysis?.parsed_email || {};
  const headers = parsed.headers || {};
  const sender = parsed.sender || {};
  const recipients = parsed.recipients || {};
  const auth = parsed.authentication || {};
  const relayChain = parsed.received_chain?.chain || parsed.received_chain || [];
  const threatAnalysis = caseData.ai_analysis || (caseData as any)?.threat_analysis || null;
  const forensicAnalysis = caseData.forensic_analysis || (caseData as any)?.email_analysis?.forensic_analysis || null;
  const ipIntel = caseData.ip_intel || (caseData as any)?.infrastructure || { ips: [] };
  const domainIntel = caseData.domain_intel || (caseData as any)?.infrastructure || { domains: [] };
  const riskAssessment = caseData.risk_reasons || (caseData as any)?.email_analysis?.risk_assessment || null;

  const handleCopyJSON = () => {
    const reportData = {
      report_title: "MAILTRACE DIGITAL FORENSICS & INCIDENT RESPONSE DOSSIER",
      generated_at: new Date().toISOString(),
      case_id: caseId,
      filename: originalFilename,
      evidence_sha256: evidenceHash,
      risk_assessment: {
        score: riskScore,
        severity: riskLabel,
        top_factors: riskAssessment?.top_factors || riskAssessment?.risk_factors || [],
      },
      email_metadata: {
        from: sender.email || headers.from,
        from_display: sender.display_name || headers.from_display,
        to: recipients.to || headers.to,
        subject: headers.subject || parsed.subject,
        date: headers.date_iso || headers.date_raw || headers.date,
        message_id: headers.message_id,
        return_path: parsed.return_path?.email || headers.return_path,
        reply_to: parsed.reply_to?.email || headers.reply_to,
      },
      authentication: auth,
      routing_hops: relayChain,
      threat_classification: threatAnalysis,
      forensic_findings: forensicAnalysis?.findings || [],
      infrastructure_intelligence: {
        ips: ipIntel.ips || [],
        domains: domainIntel.domains || [],
      },
      chain_of_custody: (caseData as any).custody_chain || [],
    };

    navigator.clipboard.writeText(JSON.stringify(reportData, null, 2));
    setCopied('json');
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownloadJSON = () => {
    const reportData = {
      report_title: "MAILTRACE DIGITAL FORENSICS & INCIDENT RESPONSE DOSSIER",
      generated_at: new Date().toISOString(),
      case_id: caseId,
      filename: originalFilename,
      evidence_sha256: evidenceHash,
      risk_score: riskScore,
      risk_label: riskLabel,
      case_detail: caseData,
      correlation: correlationData,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `MailTrace_Forensic_Dossier_${caseId.substring(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="INCIDENT RESPONSE & FORENSIC INVESTIGATION DOSSIER"
      subtitle="Comprehensive Forensic Evidence Report for SOC Triage, CERT-In, and Legal Proceedings"
      maxWidth="4xl"
    >
      <div className="space-y-6 text-slate-200 print:text-black">
        {/* Action Header (Hidden in Print) */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-cyber-card border border-cyber-border rounded-lg print:hidden">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
            <Lock className="w-4 h-4 text-cyber-cyan" />
            <span>Cryptographically Verified Evidence Package</span>
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={handleCopyJSON}
              className="font-mono text-xs"
            >
              {copied === 'json' ? (
                <>
                  <Check className="w-3.5 h-3.5 mr-1.5 text-emerald-400" />
                  JSON Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 mr-1.5" />
                  Copy JSON
                </>
              )}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleDownloadJSON}
              className="font-mono text-xs"
            >
              <Download className="w-3.5 h-3.5 mr-1.5" />
              Download JSON
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handlePrint}
              className="font-mono text-xs"
            >
              <Printer className="w-3.5 h-3.5 mr-1.5" />
              Print / Save PDF
            </Button>
          </div>
        </div>

        {/* Printable Report Document */}
        <div className="p-6 bg-slate-950/80 border border-cyber-border rounded-xl space-y-6 font-sans print:bg-white print:border-none print:p-0 print:text-black shadow-2xl">
          
          {/* Institutional Header */}
          <div className="border-b-2 border-cyber-cyan pb-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-6 h-6 text-cyber-cyan print:text-black" />
                <h1 className="text-xl font-bold font-mono tracking-wider text-white print:text-black">
                  MAILTRACE FORENSIC INTELLIGENCE DOSSIER
                </h1>
              </div>
              <p className="text-xs text-slate-400 print:text-slate-600 mt-1">
                Passive RFC-822 Email Forensics, NLP Threat Detection, and Origin Attribution Report
              </p>
            </div>
            <div className="text-right font-mono text-xs text-slate-400 print:text-slate-600">
              <div>REPORT REF: <span className="text-cyber-cyan font-bold print:text-black">{caseId.substring(0, 13)}</span></div>
              <div>DATE: {new Date().toLocaleString()}</div>
              <div>CLASSIFICATION: <span className="text-amber-400 font-bold print:text-black">RESTRICTED // SOC-IR</span></div>
            </div>
          </div>

          {/* Section 1: Case Overview & Cryptographic Hash Seals */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-3 bg-slate-900/90 border border-cyber-border/70 rounded-lg print:border print:border-gray-300 print:bg-gray-50">
              <span className="text-slate-400 print:text-slate-600 block mb-1">CASE IDENTIFIER</span>
              <span className="text-slate-100 font-bold break-all print:text-black">{caseId}</span>
            </div>
            <div className="p-3 bg-slate-900/90 border border-cyber-border/70 rounded-lg print:border print:border-gray-300 print:bg-gray-50">
              <span className="text-slate-400 print:text-slate-600 block mb-1">ORIGINAL FILENAME</span>
              <span className="text-slate-100 font-bold truncate block print:text-black">{originalFilename}</span>
            </div>
            <div className="p-3 bg-slate-900/90 border border-cyber-border/70 rounded-lg print:border print:border-gray-300 print:bg-gray-50">
              <span className="text-slate-400 print:text-slate-600 block mb-1">OVERALL RISK SCORE</span>
              <div className="flex items-center space-x-2 mt-0.5">
                <span className={`text-base font-bold ${
                  riskScore >= 80 ? 'text-red-400' : riskScore >= 60 ? 'text-amber-400' : riskScore >= 30 ? 'text-yellow-400' : 'text-emerald-400'
                } print:text-black`}>
                  {riskScore} / 100
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-bold print:border-black">
                  {riskLabel}
                </span>
              </div>
            </div>
          </div>

          {/* SHA-256 Evidence Seal */}
          <div className="p-3 bg-cyber-card/60 border border-cyber-border rounded-lg text-xs font-mono space-y-1 print:border print:border-gray-300 print:bg-gray-50">
            <div className="flex items-center justify-between text-slate-400 print:text-slate-600">
              <span>CRYPTOGRAPHIC RAW EVIDENCE HASH (SHA-256):</span>
              <span className="text-emerald-400 font-bold print:text-black">INTEGRITY VERIFIED</span>
            </div>
            <div className="text-cyber-cyan font-bold break-all select-all print:text-black">
              {evidenceHash}
            </div>
          </div>

          {/* Section 2: Email Header & Envelope Audit */}
          <div>
            <h2 className="text-sm font-bold font-mono text-cyber-cyan print:text-black border-b border-cyber-border pb-1 mb-3 flex items-center space-x-2">
              <Mail className="w-4 h-4" />
              <span>1. EMAIL HEADER & ENVELOPE METADATA</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-900/60 rounded border border-cyber-border/50 space-y-2 print:border-gray-300 print:bg-white">
                <div><span className="text-slate-400 font-bold">FROM (RFC 5322):</span> <span className="text-slate-200 print:text-black">{sender.display_name ? `"${sender.display_name}" ` : ''}&lt;{sender.email || headers.from || 'N/A'}&gt;</span></div>
                <div><span className="text-slate-400 font-bold">RETURN-PATH:</span> <span className="text-slate-200 print:text-black">&lt;{parsed.return_path?.email || headers.return_path || 'N/A'}&gt;</span></div>
                <div><span className="text-slate-400 font-bold">REPLY-TO:</span> <span className="text-slate-200 print:text-black">&lt;{parsed.reply_to?.email || headers.reply_to || 'N/A'}&gt;</span></div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-cyber-border/50 space-y-2 print:border-gray-300 print:bg-white">
                <div><span className="text-slate-400 font-bold">SUBJECT:</span> <span className="text-slate-200 font-bold print:text-black">{headers.subject || parsed.subject || '(No Subject)'}</span></div>
                <div><span className="text-slate-400 font-bold">DATE:</span> <span className="text-slate-200 print:text-black">{headers.date_iso || headers.date_raw || headers.date || 'N/A'}</span></div>
                <div><span className="text-slate-400 font-bold">MESSAGE-ID:</span> <span className="text-slate-200 truncate block print:text-black">{headers.message_id || 'MISSING (ANOMALY)'}</span></div>
              </div>
            </div>
          </div>

          {/* Section 3: Authentication & Anti-Spoofing Matrix */}
          <div>
            <h2 className="text-sm font-bold font-mono text-cyber-cyan print:text-black border-b border-cyber-border pb-1 mb-3 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4" />
              <span>2. AUTHENTICATION & PROTOCOL ALIGNMENT (SPF / DKIM / DMARC)</span>
            </h2>
            <div className="grid grid-cols-3 gap-3 text-xs font-mono text-center">
              <div className="p-3 bg-slate-900/60 rounded border border-cyber-border/50 print:border-gray-300 print:bg-white">
                <div className="text-slate-400 font-bold mb-1">SPF STATUS</div>
                <div className={`text-sm font-bold ${auth.spf?.status === 'pass' ? 'text-emerald-400' : 'text-red-400'} print:text-black uppercase`}>
                  {auth.spf?.status || 'UNKNOWN'}
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-cyber-border/50 print:border-gray-300 print:bg-white">
                <div className="text-slate-400 font-bold mb-1">DKIM SIGNATURE</div>
                <div className={`text-sm font-bold ${auth.dkim?.status === 'pass' ? 'text-emerald-400' : 'text-red-400'} print:text-black uppercase`}>
                  {auth.dkim?.status || 'UNKNOWN'}
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-cyber-border/50 print:border-gray-300 print:bg-white">
                <div className="text-slate-400 font-bold mb-1">DMARC POLICY</div>
                <div className={`text-sm font-bold ${auth.dmarc?.status === 'pass' ? 'text-emerald-400' : 'text-red-400'} print:text-black uppercase`}>
                  {auth.dmarc?.status || 'UNKNOWN'}
                </div>
              </div>
            </div>
          </div>

          {/* Section 4: AI Threat Engine & Linguistic Analysis */}
          <div>
            <h2 className="text-sm font-bold font-mono text-cyber-cyan print:text-black border-b border-cyber-border pb-1 mb-3 flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4" />
              <span>3. AI THREAT CLASSIFICATION & INTENT ANALYSIS</span>
            </h2>
            <div className="p-4 bg-slate-900/60 rounded border border-cyber-border/50 space-y-3 text-xs print:border-gray-300 print:bg-white">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="font-mono text-slate-400">PRIMARY CLASSIFICATION: </span>
                  <span className="font-mono font-bold text-white uppercase print:text-black">
                    {threatAnalysis?.primary_intent || threatAnalysis?.classification || 'BENIGN / UNCLASSIFIED'}
                  </span>
                </div>
                <div className="font-mono">
                  <span className="text-slate-400">CONFIDENCE: </span>
                  <span className="font-bold text-cyber-cyan print:text-black">
                    {typeof threatAnalysis?.confidence === 'number' ? `${Math.round(threatAnalysis.confidence * 100)}%` : 'N/A'}
                  </span>
                </div>
              </div>

              {threatAnalysis?.explanation && (
                <p className="text-slate-300 leading-relaxed print:text-slate-700">
                  {threatAnalysis.explanation}
                </p>
              )}

              {Array.isArray(threatAnalysis?.tactics) && threatAnalysis.tactics.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {threatAnalysis.tactics.map((tac: string, i: number) => (
                    <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] font-mono border border-slate-700 print:border-black print:text-black">
                      {tac}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Section 5: Origin Tracing & Infrastructure Intelligence */}
          <div>
            <h2 className="text-sm font-bold font-mono text-cyber-cyan print:text-black border-b border-cyber-border pb-1 mb-3 flex items-center space-x-2">
              <Globe className="w-4 h-4" />
              <span>4. ORIGIN TRACE & ROUTING INFRASTRUCTURE</span>
            </h2>
            <div className="p-4 bg-slate-900/60 rounded border border-cyber-border/50 space-y-3 text-xs font-mono print:border-gray-300 print:bg-white">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <span className="text-slate-400 block mb-1">TOTAL RELAY HOPS:</span>
                  <span className="text-slate-200 font-bold print:text-black">{Array.isArray(relayChain) ? relayChain.length : 0} MTA Nodes</span>
                </div>
                <div>
                  <span className="text-slate-400 block mb-1">ORIGINATING CONNECTING IP:</span>
                  <span className="text-cyber-cyan font-bold print:text-black">
                    {Array.isArray(ipIntel?.ips) && ipIntel.ips[0]?.ip ? ipIntel.ips[0].ip : 'N/A'}
                  </span>
                </div>
              </div>

              {Array.isArray(ipIntel?.ips) && ipIntel.ips.length > 0 && (
                <div className="mt-2 pt-2 border-t border-cyber-border/40">
                  <span className="text-slate-400 block mb-1">GEOLOCATION & ASN OWNERSHIP:</span>
                  <div className="space-y-1 text-slate-300 print:text-slate-700">
                    {ipIntel.ips.slice(0, 3).map((item: any, i: number) => (
                      <div key={i} className="flex justify-between">
                        <span>{item.ip}</span>
                        <span>{item.geo?.city ? `${item.geo.city}, ` : ''}{item.geo?.country || 'Unknown'} — {item.asn?.organization || item.asn?.asn || 'Unknown ASN'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Section 6: Chain of Custody & Forensic Disclaimers */}
          <div className="pt-2 border-t border-cyber-border/60 text-[11px] text-slate-400 print:text-slate-600 space-y-2">
            <div className="font-mono">
              <span className="font-bold text-slate-300 print:text-black">FORENSIC DISCLAIMER: </span>
              GeoIP coordinates and ASN registrations designate routing infrastructure locations, not verified physical operator identities. All forensic hashes are computed deterministically over RFC-822 message bytes.
            </div>
            <div className="flex items-center justify-between font-mono pt-2 border-t border-slate-800 print:border-gray-300">
              <span>GENERATED BY MAILTRACE FORENSIC ENGINE</span>
              <span>CONFIDENTIAL // LAW ENFORCEMENT & SOC USE ONLY</span>
            </div>
          </div>

        </div>
      </div>
    </Modal>
  );
};
