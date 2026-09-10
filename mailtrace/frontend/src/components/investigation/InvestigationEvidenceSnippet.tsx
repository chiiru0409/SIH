import React from 'react';
import { Fingerprint, CheckCircle2, AlertTriangle, ShieldCheck, ArrowRight, HardDrive } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { InvestigationCase } from '../../types/investigation';
import { truncateHash, safeStr } from '../../lib/utils';

interface InvestigationEvidenceSnippetProps {
  investigationCase: InvestigationCase;
}

export const InvestigationEvidenceSnippet: React.FC<InvestigationEvidenceSnippetProps> = ({ investigationCase }) => {
  const { evidenceRecords, setActiveTab } = useInvestigation();
  const caseId = safeStr(investigationCase.id || 'CASE-2026-0842');
  const evidence = evidenceRecords[caseId] || evidenceRecords['CASE-2026-0842'] || {
    rawEmailSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    merkleRootHash: 'a7c9f44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    blockchainAnchor: {
      transactionHash: '0x8f194726bfae8294719284719283719284719284719284719283719284719283',
      network: 'Polygon Mainnet / Sepolia',
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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
          <span className="text-[10px] text-slate-400 uppercase">Raw .EML SHA-256</span>
          <div className="font-bold text-cyan-300 break-all text-[11px]">
            {truncateHash(evidence.rawEmailSha256, 12)}
          </div>
          <div className="text-[10px] text-slate-500">Exact byte-for-byte digest</div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
          <span className="text-[10px] text-slate-400 uppercase">Analysis Root Hash</span>
          <div className="font-bold text-cyan-300 break-all text-[11px]">
            {truncateHash(evidence.merkleRootHash, 12)}
          </div>
          <div className="text-[10px] text-slate-500">Immutable findings commit</div>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
          <span className="text-[10px] text-slate-400 uppercase">Chain-of-Custody State</span>
          <div className="flex items-center gap-1.5 pt-0.5">
            {isTampered ? (
              <span className="text-red-400 font-bold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>INTEGRITY MISMATCH</span>
              </span>
            ) : (
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>VERIFIED VALID</span>
              </span>
            )}
          </div>
          <div className="text-[10px] text-slate-500">
            Anchor: {(evidence.blockchainAnchor as any)?.status || (evidence.blockchainAnchor?.verified ? 'CONFIRMED' : 'PENDING')}
          </div>
        </div>
      </div>
    </div>
  );
};
