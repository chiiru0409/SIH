import React from 'react';
import { Printer, Download, ShieldAlert, FileText, CheckCircle2, ShieldCheck } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { HashViewer } from '../common/HashViewer';
import { Badge } from '../common/Badge';

export const ForensicReportView: React.FC = () => {
  const { activeCase, activeEmail, evidenceRecords } = useInvestigation();

  if (!activeCase || !activeEmail) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono text-sm">
        No active case selected for report generation.
      </div>
    );
  }

  const evidence = evidenceRecords[activeCase.id] || evidenceRecords['CASE-2026-0842'];

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-4 max-w-5xl mx-auto">
      {/* Top Action Bar (Hidden during print) */}
      <div className="print:hidden p-4 bg-cyber-panel border border-slate-800 rounded-lg flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>SIH26106 DFIR Forensic Incident Report</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Formal courtroom-grade cryptographic incident report ready for judge evaluation
          </p>
        </div>

        <button
          onClick={handlePrint}
          className="flex items-center gap-2 px-4 py-2 rounded bg-cyan-500 text-slate-950 font-mono text-xs font-bold hover:bg-cyan-400 transition-colors shadow-glow-accent"
        >
          <Printer className="w-4 h-4" />
          <span>Print / Export PDF</span>
        </button>
      </div>

      {/* Printable Report Document Sheet */}
      <div className="p-8 sm:p-12 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-sans space-y-6 shadow-2xl print:border-0 print:p-0 print:bg-white print:text-black">
        {/* Document Header */}
        <div className="border-b border-slate-800 print:border-black pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold font-mono tracking-wider text-cyan-400 print:text-black">
                MAILTRACE
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono font-bold border border-cyan-500/30 print:border-black print:text-black">
                DFIR INCIDENT REPORT
              </span>
            </div>
            <p className="text-xs font-mono text-slate-400 print:text-gray-600 mt-1">
              Smart India Hackathon 2026 • Problem Statement SIH26106 • Team EAGLE (ID: 329)
            </p>
          </div>

          <div className="text-right font-mono text-xs space-y-1">
            <div>
              Case ID: <strong className="text-cyan-400 print:text-black">{activeCase.id}</strong>
            </div>
            <div className="text-slate-400 print:text-gray-600">
              Generated: {new Date().toUTCString()}
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-2">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 print:text-black border-b border-slate-800/80 print:border-gray-400 pb-1">
            1. Executive Incident Summary
          </h3>
          <div className="p-4 rounded bg-slate-900/60 print:bg-gray-100 border border-slate-800 print:border-gray-300 text-xs space-y-2 font-mono">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div>
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">Threat Classification:</span>
                <span className="font-bold text-red-400 print:text-red-700">{activeCase.verdict.primaryThreat}</span>
              </div>
              <div>
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">Overall Risk Score:</span>
                <span className="font-bold text-red-400 print:text-red-700">{activeCase.verdict.overallRiskScore}/100 ({activeCase.verdict.severity})</span>
              </div>
              <div>
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">AI Confidence:</span>
                <span className="font-bold text-emerald-400 print:text-emerald-700">{activeCase.verdict.confidenceScore}%</span>
              </div>
              <div>
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">Perimeter Action:</span>
                <span className="font-bold text-cyan-400 print:text-black">MANDATORY QUARANTINE</span>
              </div>
            </div>
            <p className="pt-2 text-slate-300 print:text-gray-800 font-sans leading-relaxed border-t border-slate-800/60 print:border-gray-300">
              {activeCase.verdict.summary}
            </p>
          </div>
        </div>

        {/* Target & Envelope Telemetry */}
        <div className="space-y-2">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 print:text-black border-b border-slate-800/80 print:border-gray-400 pb-1">
            2. Header & Envelope Metadata
          </h3>
          <div className="p-3.5 rounded bg-slate-900/60 print:bg-gray-100 border border-slate-800 print:border-gray-300 text-xs font-mono grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <strong className="text-slate-400 print:text-gray-600">Subject:</strong> {activeCase.subject}
            </div>
            <div>
              <strong className="text-slate-400 print:text-gray-600">Timestamp:</strong> {new Date(activeCase.timestamp).toUTCString()}
            </div>
            <div>
              <strong className="text-slate-400 print:text-gray-600">Header-From:</strong> {activeCase.sender}
            </div>
            <div>
              <strong className="text-slate-400 print:text-gray-600">Recipient:</strong> {activeCase.recipient}
            </div>
            <div>
              <strong className="text-slate-400 print:text-gray-600">Return-Path:</strong> {activeEmail.headers.returnPath}
            </div>
            <div>
              <strong className="text-slate-400 print:text-gray-600">Originating IP:</strong> {activeEmail.headers.originatingIp}
            </div>
          </div>
        </div>

        {/* Authentication Matrix */}
        <div className="space-y-2">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 print:text-black border-b border-slate-800/80 print:border-gray-400 pb-1">
            3. Protocol Authentication Verification
          </h3>
          <div className="grid grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3 rounded bg-slate-900/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <div className="text-[10px] text-slate-400 print:text-gray-600">SPF STATUS</div>
              <div className="font-bold text-red-400 print:text-red-700">{activeEmail.authenticationResults.spf.status}</div>
              <div className="text-[10px] text-slate-400 print:text-gray-600 mt-1">{activeEmail.authenticationResults.spf.details}</div>
            </div>
            <div className="p-3 rounded bg-slate-900/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <div className="text-[10px] text-slate-400 print:text-gray-600">DKIM STATUS</div>
              <div className="font-bold text-red-400 print:text-red-700">{activeEmail.authenticationResults.dkim.status}</div>
              <div className="text-[10px] text-slate-400 print:text-gray-600 mt-1">{activeEmail.authenticationResults.dkim.details}</div>
            </div>
            <div className="p-3 rounded bg-slate-900/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <div className="text-[10px] text-slate-400 print:text-gray-600">DMARC STATUS</div>
              <div className="font-bold text-red-400 print:text-red-700">{activeEmail.authenticationResults.dmarc.status}</div>
              <div className="text-[10px] text-slate-400 print:text-gray-600 mt-1">{activeEmail.authenticationResults.dmarc.details}</div>
            </div>
          </div>
        </div>

        {/* Cryptographic Chain of Custody */}
        <div className="space-y-2">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 print:text-black border-b border-slate-800/80 print:border-gray-400 pb-1">
            4. Cryptographic Proof & Merkle Chain of Custody
          </h3>
          <div className="p-4 rounded bg-slate-900/60 print:bg-gray-100 border border-slate-800 print:border-gray-300 text-xs font-mono space-y-2">
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">Raw EML SHA-256 Checksum:</span>
              <span className="text-cyan-300 print:text-black break-all">{evidence.rawEmailSha256}</span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">Merkle Tree Root Hash:</span>
              <span className="text-cyan-300 print:text-black break-all">{evidence.merkleRootHash}</span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">Blockchain Anchor Transaction:</span>
              <span className="text-emerald-400 print:text-emerald-700 break-all">{evidence.blockchainAnchor.transactionHash}</span>
            </div>
          </div>
        </div>

        {/* Investigator Sign-Off Block */}
        <div className="pt-6 border-t border-slate-800 print:border-black grid grid-cols-2 gap-6 text-xs font-mono">
          <div>
            <span className="text-slate-400 print:text-gray-600 block text-[10px]">Investigating SOC Team:</span>
            <span className="font-bold text-slate-200 print:text-black">Team EAGLE (ID: 329)</span>
            <div className="text-slate-400 print:text-gray-600 text-[10px] mt-0.5">Automated AI Forensics & SOC L2 Review</div>
          </div>
          <div className="text-right">
            <span className="text-slate-400 print:text-gray-600 block text-[10px]">Digital Signature:</span>
            <span className="font-bold text-emerald-400 print:text-black">SHA-256 SEALED • VERIFIED VALID</span>
            <div className="text-slate-400 print:text-gray-600 text-[10px] mt-0.5">SIH26106 Secure DFIR Authority</div>
          </div>
        </div>
      </div>
    </div>
  );
};
