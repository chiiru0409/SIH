import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Link,
  Cpu,
  Lock,
  FileCheck2,
  Download,
  RefreshCw,
  Clock,
  ExternalLink,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Blocks,
  FileCode2,
  Copy,
  Check
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { truncateHash, formatDate } from '../../lib/utils';
import {
  fetchEvidenceManifest,
  verifyEvidence,
  anchorEvidence,
  fetchChainOfCustody
} from '../../lib/api';
import type {
  EvidenceManifestResponse,
  EvidenceVerifyResponse,
  ChainOfCustodyEvent,
  BlockchainAnchorResponse
} from '../../types/api';

export interface EvidenceIntegrityPanelProps {
  caseId: string;
  initialEvidenceHash?: string | null;
  className?: string;
}

export const EvidenceIntegrityPanel: React.FC<EvidenceIntegrityPanelProps> = ({
  caseId,
  initialEvidenceHash,
  className,
}) => {
  const [manifest, setManifest] = useState<EvidenceManifestResponse | null>(null);
  const [verification, setVerification] = useState<EvidenceVerifyResponse | null>(null);
  const [events, setEvents] = useState<ChainOfCustodyEvent[]>([]);
  const [chainValid, setChainValid] = useState<boolean>(true);
  
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [anchoring, setAnchoring] = useState<boolean>(false);
  const [anchorSuccess, setAnchorSuccess] = useState<BlockchainAnchorResponse | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadEvidenceData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [manifestData, chainData] = await Promise.all([
        fetchEvidenceManifest(caseId),
        fetchChainOfCustody(caseId),
      ]);
      setManifest(manifestData);
      setEvents(chainData.events || []);
      setChainValid(chainData.chain_valid);
    } catch (err: any) {
      setError(err.message || 'Failed to load evidence manifest.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvidenceData();
  }, [caseId]);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await verifyEvidence(caseId);
      setVerification(result);
      // Reload chain of custody to capture new verification event
      const chainData = await fetchChainOfCustody(caseId);
      setEvents(chainData.events || []);
      setChainValid(chainData.chain_valid);
    } catch (err: any) {
      setError(err.message || 'Verification failed.');
    } finally {
      setVerifying(false);
    }
  };

  const handleAnchor = async () => {
    setAnchoring(true);
    try {
      const receipt = await anchorEvidence(caseId);
      setAnchorSuccess(receipt);
      await loadEvidenceData();
    } catch (err: any) {
      setError(err.message || 'Anchoring failed.');
    } finally {
      setAnchoring(false);
    }
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleExportManifest = () => {
    if (!manifest) return;
    const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `evidence_manifest_${caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <Card className={`p-8 text-center border-cyber-border ${className || ''}`}>
        <div className="flex flex-col items-center justify-center space-y-3">
          <RefreshCw className="w-8 h-8 text-cyber-cyan animate-spin" />
          <p className="font-mono text-sm text-slate-400">Loading cryptographic evidence commitments…</p>
        </div>
      </Card>
    );
  }

  const isVerified = verification ? verification.valid : (manifest?.integrity_status === 'verified');
  const fileHash = manifest?.file_sha256 || initialEvidenceHash || '';
  const parsedHash = manifest?.parsed_evidence_sha256 || '';
  const analysisHash = manifest?.analysis_sha256 || '';
  const blockchain = manifest?.blockchain_anchoring;

  return (
    <div className={`space-y-6 ${className || ''}`}>
      
      {/* 1. Header Hero Card with Actions */}
      <Card className="border-cyber-borderLight bg-gradient-to-br from-cyber-surface/90 to-cyber-bg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <span className="px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                <Lock className="w-3 h-3 text-cyan-400" />
                FIPS 180-4 Standard
              </span>
              {isVerified ? (
                <span className="px-2.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 font-mono text-xs font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  INTEGRITY VERIFIED
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded bg-rose-950/80 border border-rose-500/50 text-rose-300 font-mono text-xs font-bold flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5 text-rose-400" />
                  INTEGRITY MISMATCH
                </span>
              )}
              {blockchain?.status === 'anchored' && (
                <span className="px-2.5 py-0.5 rounded bg-purple-950/80 border border-purple-500/50 text-purple-300 font-mono text-xs font-bold flex items-center gap-1">
                  <Blocks className="w-3.5 h-3.5 text-purple-400" />
                  ON-CHAIN ANCHORED
                </span>
              )}
            </div>
            <h2 className="text-xl sm:text-2xl font-mono font-bold text-slate-100 flex items-center gap-2">
              <span>Tamper-Evident Evidence & Blockchain Anchoring</span>
            </h2>
            <p className="text-xs font-mono text-slate-400 max-w-3xl">
              Cryptographically secures raw EML bytes, structured parsed attributes, forensic findings, and chronological chain-of-custody logs with deterministic SHA-256 hash chaining.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <Button
              variant="primary"
              size="sm"
              icon={verifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              onClick={handleVerify}
              disabled={verifying}
            >
              {verifying ? 'Verifying Integrity…' : 'Verify Evidence'}
            </Button>

            <Button
              variant="outline"
              size="sm"
              icon={anchoring ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Blocks className="w-4 h-4 text-purple-400" />}
              onClick={handleAnchor}
              disabled={anchoring || blockchain?.status === 'anchored'}
            >
              {blockchain?.status === 'anchored' ? 'Already Anchored' : anchoring ? 'Anchoring…' : 'Anchor to Ledger'}
            </Button>

            <Button
              variant="ghost"
              size="sm"
              icon={<Download className="w-4 h-4 text-cyan-400" />}
              onClick={handleExportManifest}
            >
              Export Manifest JSON
            </Button>
          </div>
        </div>

        {/* Verification Status Banner if recently verified */}
        {verification && (
          <div className={`mt-6 p-4 rounded-lg border font-mono text-xs space-y-2 ${
            verification.valid 
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200' 
              : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
          }`}>
            <div className="flex items-center space-x-2 font-bold text-sm">
              {verification.valid ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>ALL CRYPTOGRAPHIC COMMITMENTS VERIFIED</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>INTEGRITY MISMATCH DETECTED</span>
                </>
              )}
            </div>
            <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1">
              {verification.details.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 font-mono text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </Card>

      {/* 2. Cryptographic Commitments Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Original File Hash */}
        <Card className="border-cyber-border hover:border-cyber-cyan/50 transition">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <FileCheck2 className="w-3.5 h-3.5 text-cyber-cyan" />
              Original File SHA-256
            </span>
            <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 font-mono text-[10px] font-bold">Raw Bytes</span>
          </div>
          <p className="font-mono text-xs text-slate-200 break-all bg-cyber-bg p-3 rounded border border-cyber-border/80 select-all">
            {fileHash || 'N/A'}
          </p>
          <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Size: {manifest?.file_size_bytes ? `${manifest.file_size_bytes} B` : 'Direct'}</span>
            <button
              onClick={() => copyToClipboard(fileHash, 'fileHash')}
              className="text-cyber-cyan hover:underline flex items-center gap-1"
            >
              {copiedField === 'fileHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedField === 'fileHash' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </Card>

        {/* Parsed Evidence Structure Hash */}
        <Card className="border-cyber-border hover:border-cyber-cyan/50 transition">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <FileCode2 className="w-3.5 h-3.5 text-emerald-400" />
              Parsed Evidence Hash
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 font-mono text-[10px] font-bold">Canonical JSON</span>
          </div>
          <p className="font-mono text-xs text-slate-200 break-all bg-cyber-bg p-3 rounded border border-cyber-border/80 select-all">
            {parsedHash || 'N/A'}
          </p>
          <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Deterministic MIME Model</span>
            <button
              onClick={() => copyToClipboard(parsedHash, 'parsedHash')}
              className="text-cyber-cyan hover:underline flex items-center gap-1"
            >
              {copiedField === 'parsedHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedField === 'parsedHash' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </Card>

        {/* Forensic Analysis Record Hash */}
        <Card className="border-cyber-border hover:border-cyber-cyan/50 transition">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              Analysis Record Hash
            </span>
            <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-bold">Findings & Risk</span>
          </div>
          <p className="font-mono text-xs text-slate-200 break-all bg-cyber-bg p-3 rounded border border-cyber-border/80 select-all">
            {analysisHash || 'N/A'}
          </p>
          <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Risk & Threat Commitment</span>
            <button
              onClick={() => copyToClipboard(analysisHash, 'analysisHash')}
              className="text-cyber-cyan hover:underline flex items-center gap-1"
            >
              {copiedField === 'analysisHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedField === 'analysisHash' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </Card>

      </div>

      {/* 3. Blockchain Anchoring Details */}
      <Card
        title="BLOCKCHAIN LEDGER ANCHORING"
        subtitle="Zero-knowledge cryptographic timestamping on distributed ledger (no email content on-chain)"
        icon={<Blocks className="w-4 h-4 text-purple-400" />}
      >
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-3 bg-cyber-bg rounded border border-cyber-border">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Provider Status</span>
            <div className="mt-1 font-mono font-bold text-sm text-slate-200 flex items-center gap-1.5">
              {blockchain?.enabled ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span>ACTIVE ({blockchain.provider})</span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-slate-500" />
                  <span>NOT CONFIGURED / LOCAL</span>
                </>
              )}
            </div>
          </div>

          <div className="p-3 bg-cyber-bg rounded border border-cyber-border">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Ledger Network</span>
            <div className="mt-1 font-mono font-bold text-sm text-slate-200 uppercase">
              {blockchain?.network || 'LOCAL-OFFLINE'}
            </div>
          </div>

          <div className="p-3 bg-cyber-bg rounded border border-cyber-border md:col-span-2">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Transaction ID</span>
            <div className="mt-1 font-mono text-xs text-slate-200 break-all select-all flex items-center justify-between">
              <span>{blockchain?.transaction_id || 'Not yet anchored'}</span>
              {blockchain?.transaction_id && (
                <button
                  onClick={() => copyToClipboard(blockchain.transaction_id!, 'tx_id')}
                  className="text-cyber-cyan hover:underline ml-2"
                >
                  {copiedField === 'tx_id' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              )}
            </div>
          </div>
        </div>

        {blockchain?.anchor_data && (
          <div className="mt-4 p-3 bg-slate-900/60 rounded border border-purple-500/30 font-mono text-xs text-slate-300">
            <div className="font-bold text-purple-300 mb-1">Receipt Commitment:</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-slate-400 text-[11px]">
              <div>Block Number: <strong className="text-slate-200">{blockchain.anchor_data.block_number || 'N/A'}</strong></div>
              <div>Block Time: <strong className="text-slate-200">{blockchain.anchor_data.block_timestamp || 'N/A'}</strong></div>
              <div>Status: <strong className="text-emerald-400">{blockchain.anchor_data.status || 'Verified'}</strong></div>
            </div>
          </div>
        )}
      </Card>

      {/* 4. Chain of Custody Timeline */}
      <Card
        title={`CHAIN OF CUSTODY TIMELINE (${events.length} EVENTS)`}
        subtitle="Unbroken hash-chained chronological audit log (event_n = SHA256(event_type + case_id + hash + prev_hash))"
        icon={<Link className="w-4 h-4 text-cyber-cyan" />}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-2 border-b border-cyber-border">
            <span>Audit Trail Integrity: {chainValid ? (
              <strong className="text-emerald-400">UNBROKEN VALID CHAIN</strong>
            ) : (
              <strong className="text-rose-400">CHAIN TAMPER DETECTED</strong>
            )}</span>
            <span>Total Logged Events: {events.length}</span>
          </div>

          <div className="space-y-3 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-cyber-border before:z-0">
            {events.map((ev, idx) => (
              <div key={ev.id || idx} className="relative z-10 flex items-start space-x-3 text-xs font-mono">
                <div className="w-7 h-7 rounded-full bg-cyber-bg border border-cyber-cyan/50 flex items-center justify-center shrink-0 text-[11px] font-bold text-cyber-cyan">
                  {idx + 1}
                </div>
                <div className="flex-1 p-3 rounded-lg bg-cyber-bg border border-cyber-border hover:border-cyber-cyan/40 transition">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                    <span className="font-bold text-slate-200 flex items-center gap-1.5">
                      <span className="px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 font-mono text-[10px] font-bold">
                        {ev.event_type}
                      </span>
                      <span className="text-slate-400 text-[11px]">• {formatDate(ev.timestamp)}</span>
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      PREV: {ev.previous_event_hash ? truncateHash(ev.previous_event_hash, 4) : 'GENESIS'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2 pt-2 border-t border-cyber-border/40 text-[11px] text-slate-400">
                    <div>
                      <span className="text-slate-500">Evidence Hash: </span>
                      <span className="text-slate-300">{truncateHash(ev.evidence_hash || ev.event_hash, 6)}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Event Commitment: </span>
                      <span className="text-cyber-cyan">{truncateHash(ev.event_hash, 6)}</span>
                    </div>
                  </div>

                  {ev.metadata && Object.keys(ev.metadata).length > 0 && (
                    <div className="mt-2 text-[10px] text-slate-400 bg-cyber-surface/60 p-2 rounded">
                      <strong className="text-slate-500">Metadata: </strong>
                      {JSON.stringify(ev.metadata)}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* 5. Legal Attribution & Non-Repudiation Notice */}
      <Card className="border-cyber-border/80 bg-slate-900/40">
        <div className="flex items-start space-x-3">
          <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1 font-mono text-xs">
            <h4 className="font-bold text-slate-200">Forensic Integrity vs. Legal Attribution Disclaimer</h4>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              {manifest?.legal_attribution_notice || (
                "Evidence integrity establishes cryptographic proof that original bytes, parsed forensic data, " +
                "and analysis scores match their recorded SHA-256 commitments. " +
                "Integrity validation proves non-tampering; it does not represent proof of author identity or criminal attribution."
              )}
            </p>
          </div>
        </div>
      </Card>

    </div>
  );
};
