import React, { useState } from 'react';
import { Fingerprint, ShieldCheck, ShieldAlert, CheckCircle2, AlertTriangle, RefreshCw, Lock, Link, Copy, Check } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { HashViewer } from '../common/HashViewer';

export const EvidenceIntegrity: React.FC = () => {
  const { activeCaseId, evidenceRecords, simulateTamper, restoreTamper } = useInvestigation();
  const evidence = evidenceRecords[activeCaseId] || evidenceRecords['CASE-2026-0842'];

  const isTampered = evidence.tamperStatus === 'TAMPER_DETECTED';

  return (
    <div className="space-y-4">
      {/* Header with Live Verification Banner */}
      <div
        className={`p-5 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
          isTampered
            ? 'bg-red-950/20 border-red-500/50 shadow-glow-critical'
            : 'bg-cyber-panel border-slate-800'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <Fingerprint className={`w-5 h-5 ${isTampered ? 'text-red-400 animate-pulse' : 'text-cyan-400'}`} />
            <h2 className="text-base font-bold font-mono text-slate-100">
              Cryptographic Evidence Chain of Custody (SIH DFIR Standard)
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Case: <strong className="text-cyan-400">{evidence.caseId}</strong> • Immutable Merkle Tree & Multi-Stage Checksums
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {isTampered ? (
            <button
              onClick={() => restoreTamper(evidence.caseId)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500 text-slate-950 text-xs font-mono font-bold hover:bg-cyan-400 transition-colors shadow-glow-accent"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Recalculate & Restore Pristine Hashes</span>
            </button>
          ) : (
            <button
              onClick={() => simulateTamper(evidence.caseId)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600/20 border border-red-500/40 text-red-300 hover:bg-red-600/30 text-xs font-mono font-semibold transition-colors"
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Simulate Tamper Attack</span>
            </button>
          )}

          <div
            className={`px-3 py-1.5 rounded text-xs font-mono font-bold flex items-center gap-1.5 ${
              isTampered
                ? 'bg-red-500/20 text-red-400 border border-red-500/50 animate-pulse'
                : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
            }`}
          >
            {isTampered ? (
              <>
                <ShieldAlert className="w-4 h-4" />
                <span>INTEGRITY VIOLATION DETECTED</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>VERIFIED CRYPTOGRAPHICALLY VALID</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 4-Stage Cryptographic Hash Pipeline */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Stage 1: Raw Ingested RFC-822 Hash */}
        <div className="p-4 rounded-lg bg-cyber-panel border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 font-bold">STAGE 1: RAW RFC-822 EML INGESTION</span>
            <span className="text-emerald-400">Pristine Checksum</span>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Computed immediately upon ingress at boundary mail gateway before memory parsing.
          </p>
          <HashViewer
            hash={evidence.rawEmailSha256}
            label="Raw EML Checksum"
            algorithm="SHA-256"
          />
        </div>

        {/* Stage 2: Parsed Structural Artifact Hash */}
        <div className="p-4 rounded-lg bg-cyber-panel border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 font-bold">STAGE 2: PARSED CANONICAL METADATA</span>
            <span className="text-emerald-400">MIME Tree Sealed</span>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Canonicalized JSON representation of extracted headers, hops, and MIME body parts.
          </p>
          <HashViewer
            hash={evidence.parsedMetadataSha256}
            label="Metadata Hash"
            algorithm="SHA-256"
          />
        </div>

        {/* Stage 3: AI Analysis Artifact Hash */}
        <div className="p-4 rounded-lg bg-cyber-panel border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 font-bold">STAGE 3: FORENSIC VERDICT ARTIFACT</span>
            <span className="text-emerald-400">Features Locked</span>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Deterministic feature vectors, risk engine outputs, and multi-vendor IOC reputation scores.
          </p>
          <HashViewer
            hash={evidence.analysisArtifactSha256}
            label="Analysis Artifact"
            algorithm="SHA-256"
          />
        </div>

        {/* Stage 4: Merkle Root & Simulated Blockchain Anchor */}
        <div className="p-4 rounded-lg bg-cyber-panel border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 font-bold">STAGE 4: MERKLE TREE ROOT ANCHOR</span>
            <span className="text-cyan-400 font-bold">Immutable Ledger</span>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Cryptographic root aggregating stages 1-3 anchored into tamper-evident block header.
          </p>
          <HashViewer
            hash={evidence.merkleRootHash}
            label="Merkle Root Hash"
            algorithm="SHA-256"
          />
        </div>
      </div>

      {/* Simulated Blockchain Anchor Details */}
      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2 text-cyan-400 font-bold">
            <Lock className="w-4 h-4" />
            <span>Immutable Distributed Ledger Anchor (Simulated Proof)</span>
          </div>
          <span className="text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> Block #{evidence.blockchainAnchor.blockNumber} Confirmed
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
          <div>
            <span className="text-slate-400 block text-[10px]">Anchor Transaction Hash:</span>
            <span className="text-cyan-300 break-all">{evidence.blockchainAnchor.transactionHash}</span>
          </div>
          <div>
            <span className="text-slate-400 block text-[10px]">Anchoring Timestamp:</span>
            <span>{new Date(evidence.blockchainAnchor.anchoredAt).toUTCString()}</span>
          </div>
        </div>
      </div>

      {/* Audit Step Trail */}
      <div className="p-4 rounded-lg bg-cyber-panel border border-slate-800 space-y-3 font-mono text-xs">
        <div className="text-slate-200 font-bold pb-2 border-b border-slate-800 flex items-center justify-between">
          <span>Sequential Custody Audit Trail</span>
          <span className="text-slate-400">{evidence.auditTrail.length} Logged Transactions</span>
        </div>

        <div className="space-y-2">
          {evidence.auditTrail.map((step, idx) => (
            <div
              key={idx}
              className={`p-2.5 rounded border flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                step.status === 'ANOMALOUS'
                  ? 'bg-red-950/40 border-red-500/50 text-red-300'
                  : 'bg-slate-900 border-slate-800 text-slate-300'
              }`}
            >
              <div className="flex items-start gap-2.5">
                <span className="font-bold text-cyan-400">#{step.step}</span>
                <div>
                  <div className="font-semibold text-slate-200">{step.action}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Actor: {step.actor} • Time: {new Date(step.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              <div className="text-right text-[11px] font-mono">
                <span
                  className={`px-2 py-0.5 rounded font-bold ${
                    step.status === 'ANOMALOUS'
                      ? 'bg-red-500/20 text-red-400'
                      : 'bg-emerald-500/20 text-emerald-400'
                  }`}
                >
                  {step.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
