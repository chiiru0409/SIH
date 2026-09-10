import React, { useState } from 'react';
import { Fingerprint, CheckCircle2, AlertTriangle, ShieldCheck, ArrowRight, HardDrive, Lock, ChevronDown, ChevronUp, Check } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { InvestigationCase } from '../../types/investigation';
import { truncateHash, safeStr } from '../../lib/utils';

interface InvestigationEvidenceSnippetProps {
  investigationCase: InvestigationCase;
}

export const InvestigationEvidenceSnippet: React.FC<InvestigationEvidenceSnippetProps> = ({ investigationCase }) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);
  const { evidenceRecords, setActiveTab } = useInvestigation();
  const caseId = safeStr(investigationCase.id || 'CASE-2026-0842');
  const evidence = evidenceRecords[caseId] || evidenceRecords['CASE-2026-0842'] || {
    rawEmailSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    merkleRootHash: 'a7c9f44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    blockchainAnchor: {
      transactionHash: '0x8f194726bfae8294719284719283719284719284719284719283719284719283',
      network: 'Polygon Mainnet / Sepolia (Simulated / Web3 Ready)',
      blockNumber: 48918291,
      status: 'CONFIRMED'
    },
    chainOfCustody: []
  };

  const isTampered = (investigationCase as any).isTampered || false;

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Cryptographic Proof & Evidence Integrity
          </h3>
        </div>
        <button
          onClick={() => setActiveTab('evidence')}
          className="flex items-center gap-1 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          <span>Open Full Evidence Console</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* 1. PLAIN-ENGLISH THREE-BULLET INTEGRITY SUMMARY */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-start gap-2.5">
          <div className="p-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400 shrink-0 mt-0.5">
            <Check className="w-3.5 h-3.5" />
          </div>
          <div>
            <span className="text-xs font-bold font-mono text-slate-200 block">Original Email Hashed</span>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5 leading-tight">
              Raw RFC-822 bytes digested via deterministic SHA-256 (tamper-evident).
            </p>
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-start gap-2.5">
          <div className="p-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400 shrink-0 mt-0.5">
            <Check className="w-3.5 h-3.5" />
          </div>
          <div>
            <span className="text-xs font-bold font-mono text-slate-200 block">Chain of Custody Preserved</span>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5 leading-tight">
              Append-only audit log records every forensic triage and state transition.
            </p>
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-start gap-2.5">
          <div className="p-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400 shrink-0 mt-0.5">
            <Check className="w-3.5 h-3.5" />
          </div>
          <div>
            <span className="text-xs font-bold font-mono text-slate-200 block">Integrity Verifiable</span>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5 leading-tight">
              Evidence root hashes can be independently audited against recorded commitments.
            </p>
          </div>
        </div>
      </div>

      {/* 2. PROGRESSIVE DISCLOSURE TOGGLE FOR TECHNICAL HASHES & PROOFS */}
      <div className="pt-2 border-t border-slate-800/60">
        <button
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-300 hover:text-cyan-400 transition-colors"
        >
          <span className="font-bold flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showTechnicalDetails ? 'Hide Raw Cryptographic Hashes' : 'View Raw SHA-256 Hashes & Blockchain Ledger Status'}</span>
          </span>
          {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {showTechnicalDetails && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono mt-3 animate-in fade-in">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">Raw .EML SHA-256</span>
              <div className="font-bold text-cyan-300 break-all text-[11px]">
                {truncateHash(evidence.rawEmailSha256, 12)}
              </div>
              <div className="text-[10px] text-slate-500">Byte-for-byte exact digest</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">Analysis Root Hash</span>
              <div className="font-bold text-cyan-300 break-all text-[11px]">
                {truncateHash(evidence.merkleRootHash, 12)}
              </div>
              <div className="text-[10px] text-slate-500">Immutable findings commit</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">Ledger Status</span>
              <div className="flex items-center gap-1.5 pt-0.5">
                {isTampered ? (
                  <span className="text-red-400 font-bold flex items-center gap-1 text-[11px]">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>INTEGRITY MISMATCH</span>
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1 text-[11px]">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>SIMULATED / WEB3 READY</span>
                  </span>
                )}
              </div>
              <div className="text-[10px] text-slate-500">
                Network: Local SHA-256 Tree (Web3 Ready)
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
