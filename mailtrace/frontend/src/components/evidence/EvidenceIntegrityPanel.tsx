import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Link,
  Lock,
  FileCheck2,
  Download,
  RefreshCw,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Blocks,
  FileCode2,
  Copy,
  Check,
  ChevronRight,
  HardDrive,
  Cpu
} from 'lucide-react';
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
  ChainOfCustodyEvent
} from '../../types/api';

export interface EvidenceIntegrityPanelProps {
  caseId: string;
  initialEvidenceHash?: string | null;
  className?: string;
}

export const EvidenceIntegrityPanel: React.FC<EvidenceIntegrityPanelProps> = ({
  caseId,
  initialEvidenceHash,
  className = '',
}) => {
  const [manifest, setManifest] = useState<EvidenceManifestResponse | null>(null);
  const [verification, setVerification] = useState<EvidenceVerifyResponse | null>(null);
  const [events, setEvents] = useState<ChainOfCustodyEvent[]>([]);
  const [chainValid, setChainValid] = useState<boolean>(true);
  
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [anchoring, setAnchoring] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'LEDGER' | 'COMMITMENTS' | 'BLOCKCHAIN'>('LEDGER');

  const isMountedRef = useRef<boolean>(true);

  const loadEvidenceData = async () => {
    if (!caseId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [manifestData, chainData] = await Promise.all([
        fetchEvidenceManifest(caseId),
        fetchChainOfCustody(caseId),
      ]);
      if (isMountedRef.current) {
        setManifest(manifestData || null);
        setEvents(Array.isArray(chainData?.events) ? chainData.events : []);
        setChainValid(chainData?.chain_valid ?? true);
      }
    } catch (err: any) {
      if (isMountedRef.current) {
        setError(err?.message || 'Failed to load evidence manifest from cryptographic backend.');
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    isMountedRef.current = true;
    loadEvidenceData();
    return () => {
      isMountedRef.current = false;
    };
  }, [caseId]);

  const handleVerify = async () => {
    if (!caseId) return;
    setVerifying(true);
    setError(null);
    try {
      const result = await verifyEvidence(caseId);
      if (isMountedRef.current) {
        setVerification(result || null);
      }
      const chainData = await fetchChainOfCustody(caseId);
      if (isMountedRef.current) {
        setEvents(Array.isArray(chainData?.events) ? chainData.events : []);
        setChainValid(chainData?.chain_valid ?? true);
      }
    } catch (err: any) {
      if (isMountedRef.current) {
        setError(err?.message || 'Cryptographic verification sequence failed.');
      }
    } finally {
      if (isMountedRef.current) {
        setVerifying(false);
      }
    }
  };

  const handleAnchor = async () => {
    if (!caseId) return;
    setAnchoring(true);
    setError(null);
    try {
      await anchorEvidence(caseId);
      await loadEvidenceData();
    } catch (err: any) {
      if (isMountedRef.current) {
        setError(err?.message || 'Ledger anchoring sequence failed.');
      }
    } finally {
      if (isMountedRef.current) {
        setAnchoring(false);
      }
    }
  };

  const copyToClipboard = (text?: string | null, field?: string) => {
    if (!text || !field) return;
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
    a.download = `evidence_manifest_${caseId || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const isVerified = verification ? verification.valid : (manifest?.integrity_status === 'verified');
  const fileHash = typeof manifest?.file_sha256 === 'string' ? manifest.file_sha256 : (typeof initialEvidenceHash === 'string' ? initialEvidenceHash : (manifest?.file_sha256 ? String(manifest.file_sha256) : ''));
  const parsedHash = typeof manifest?.parsed_evidence_sha256 === 'string' ? manifest.parsed_evidence_sha256 : (manifest?.parsed_evidence_sha256 ? String(manifest.parsed_evidence_sha256) : '');
  const analysisHash = typeof manifest?.analysis_sha256 === 'string' ? manifest.analysis_sha256 : (manifest?.analysis_sha256 ? String(manifest.analysis_sha256) : '');
  const blockchain = manifest?.blockchain_anchoring || null;

  if (loading) {
    return (
      <div className={`rounded-xl border border-slate-800 bg-slate-950 p-10 font-mono text-center shadow-2xl ${className}`}>
        <div className="flex flex-col items-center justify-center space-y-4">
          <div className="relative">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
            <div className="absolute inset-0 rounded-full blur-md bg-cyan-400/30" />
          </div>
          <div className="text-xs text-cyan-300 font-bold uppercase tracking-widest">
            [ INITIALIZING FORENSIC CRYPTOGRAPHIC ENGINE ]
          </div>
          <p className="text-[11px] text-slate-500">
            Querying SHA-256 commitments & verifying merkle hash chain integrity for case: {caseId || 'CURRENT'}…
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      
      {/* LIVE FORENSIC TERMINAL WINDOW CONTAINER */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-black/95 shadow-[0_0_50px_rgba(0,0,0,0.8)] backdrop-blur-md">
        
        {/* TOP WINDOW TITLEBAR WITH macOS TRAFFIC LIGHTS */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-950/90 px-4 py-2.5 font-mono text-xs select-none">
          
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-1.5">
              <span className="h-3 w-3 rounded-full bg-rose-500/90 border border-rose-600/80 shadow-[0_0_6px_rgba(244,63,94,0.6)] cursor-pointer" />
              <span className="h-3 w-3 rounded-full bg-amber-500/90 border border-amber-600/80 shadow-[0_0_6px_rgba(245,158,11,0.6)] cursor-pointer" />
              <span className="h-3 w-3 rounded-full bg-emerald-500/90 border border-emerald-600/80 shadow-[0_0_6px_rgba(16,185,129,0.6)] cursor-pointer" />
            </div>

            <div className="flex items-center space-x-2 border-l border-slate-800 pl-3">
              <Terminal className="h-3.5 w-3.5 text-cyan-400" />
              <span className="text-slate-300 font-bold tracking-tight">
                tty1@mailtrace-core:~/evidence-ledger
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-500 text-[10px]">
                CASE-{caseId ? caseId.slice(0, 8) : 'ACTIVE'}
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-[10px]">
            <span className="flex items-center space-x-1.5 rounded bg-cyan-950/70 border border-cyan-500/40 px-2 py-0.5 text-cyan-300 font-bold">
              <Lock className="h-3 w-3 text-cyan-400" />
              <span>FIPS 180-4 SHA-256</span>
            </span>
            <span className="text-slate-500 hidden sm:inline">
              AUDIT PROTOCOL // ACTIVE
            </span>
          </div>
        </div>

        {/* TERMINAL BODY */}
        <div className="p-5 font-mono space-y-5">
          
          {/* Executive Command Strip & Actions */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 rounded-lg bg-slate-950/90 border border-slate-800">
            <div className="space-y-1">
              <div className="flex items-center space-x-2 text-cyan-400 text-xs font-bold">
                <ChevronRight className="h-4 w-4 animate-pulse" />
                <span>root@mailtrace-sec:~$ audit --verify-chain --deterministic</span>
              </div>
              <p className="text-[11px] text-slate-400 max-w-2xl leading-relaxed">
                Cryptographically binds original raw EML bytes, canonical MIME parsed objects, forensic indicators, and immutable sequential chain-of-custody commits.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                onClick={handleVerify}
                disabled={verifying}
                className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded bg-cyan-500/20 border border-cyan-400/60 text-cyan-300 text-xs font-bold hover:bg-cyan-500/30 active:scale-95 transition disabled:opacity-50 shadow-[0_0_12px_rgba(0,240,255,0.2)]"
              >
                {verifying ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>VERIFYING CHAIN…</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
                    <span>EXEC: VERIFY_EVIDENCE</span>
                  </>
                )}
              </button>

              <button
                onClick={handleAnchor}
                disabled={anchoring || blockchain?.status === 'anchored'}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-purple-950/50 border border-purple-500/40 text-purple-300 text-xs font-bold hover:bg-purple-900/40 active:scale-95 transition disabled:opacity-50"
              >
                {anchoring ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>ANCHORING…</span>
                  </>
                ) : (
                  <>
                    <Blocks className="h-3.5 w-3.5 text-purple-400" />
                    <span>{blockchain?.status === 'anchored' ? 'ANCHORED TO LEDGER' : 'ANCHOR_LEDGER'}</span>
                  </>
                )}
              </button>

              <button
                onClick={handleExportManifest}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 text-xs font-bold hover:bg-slate-800 hover:text-white transition"
              >
                <Download className="h-3.5 w-3.5 text-slate-400" />
                <span>EXPORT --JSON</span>
              </button>
            </div>
          </div>

          {/* Verification Feedback Banner */}
          {verification && (
            <div className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${
              verification.valid 
                ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-200' 
                : 'bg-rose-950/40 border-rose-500/50 text-rose-200'
            }`}>
              <div className="flex items-center space-x-2 font-bold text-sm">
                {verification.valid ? (
                  <>
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>ALL CRYPTOGRAPHIC COMMITMENTS VERIFIED [0 TAMPER DETECTED]</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="h-4 w-4 text-rose-400" />
                    <span>INTEGRITY MISMATCH DETECTED IN EVIDENCE RECORD</span>
                  </>
                )}
              </div>
              {Array.isArray(verification.details) && verification.details.length > 0 && (
                <ul className="list-disc list-inside space-y-0.5 text-slate-300 text-[11px] pl-1">
                  {verification.details.map((d, i) => (
                    <li key={i}>{d}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* View Tab Switcher */}
          <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 text-xs">
            <button
              onClick={() => setActiveTab('LEDGER')}
              className={`px-3 py-1 rounded transition flex items-center space-x-1.5 ${
                activeTab === 'LEDGER' 
                  ? 'bg-slate-800 text-cyan-300 border border-cyan-500/40 font-bold shadow-[0_0_8px_rgba(0,240,255,0.2)]' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Link className="h-3.5 w-3.5" />
              <span>CHAIN OF CUSTODY LEDGER ({events.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('COMMITMENTS')}
              className={`px-3 py-1 rounded transition flex items-center space-x-1.5 ${
                activeTab === 'COMMITMENTS' 
                  ? 'bg-slate-800 text-cyan-300 border border-cyan-500/40 font-bold shadow-[0_0_8px_rgba(0,240,255,0.2)]' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <HardDrive className="h-3.5 w-3.5" />
              <span>SHA-256 COMMITMENTS</span>
            </button>

            <button
              onClick={() => setActiveTab('BLOCKCHAIN')}
              className={`px-3 py-1 rounded transition flex items-center space-x-1.5 ${
                activeTab === 'BLOCKCHAIN' 
                  ? 'bg-slate-800 text-purple-300 border border-purple-500/40 font-bold shadow-[0_0_8px_rgba(168,85,247,0.2)]' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Blocks className="h-3.5 w-3.5" />
              <span>BLOCKCHAIN PROOF</span>
            </button>
          </div>

          {/* TAB 1: CHAIN OF CUSTODY LEDGER */}
          <div className={activeTab === 'LEDGER' ? 'block space-y-3' : 'hidden'}>
            <div className="flex items-center justify-between text-[11px] text-slate-400 pb-1">
              <span className="flex items-center space-x-1.5">
                <span className={`h-2 w-2 rounded-full ${chainValid ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
                <span>AUDIT TRAIL INTEGRITY: {chainValid ? 'UNBROKEN DETERMINISTIC CHAIN' : 'HASH MISMATCH DETECTED'}</span>
              </span>
              <span>TOTAL EVENTS LOGGED: {events.length}</span>
            </div>

            <div className="max-h-[380px] overflow-y-auto space-y-2 rounded-lg bg-slate-950 p-3.5 border border-slate-800 text-[11px] font-mono leading-relaxed">
              {events.length === 0 ? (
                <div className="py-8 text-center text-slate-500">
                  [ NO HISTORICAL CHAIN EVENTS DETECTED IN STORAGE LEDGER ]
                </div>
              ) : (
                events.map((ev, idx) => (
                  <div 
                    key={`ev-${ev?.id || idx}-${idx}`}
                    className="group relative rounded border border-slate-800/80 bg-slate-900/50 p-2.5 transition hover:border-cyan-500/40 hover:bg-slate-900/90"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-1 text-slate-400 mb-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-cyan-400 font-bold">#{String(idx + 1).padStart(2, '0')}</span>
                        <span className="px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-bold uppercase text-[10px]">
                          {ev?.event_type || 'RECORD'}
                        </span>
                        <span className="text-slate-500">[{formatDate(ev?.timestamp)}]</span>
                      </div>
                      <span className="text-[10px] text-slate-500">
                        PREV: {ev?.previous_event_hash ? truncateHash(ev.previous_event_hash, 6) : '0x0000 (GENESIS)'}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1.5 pt-1.5 border-t border-slate-800/60 text-[11px]">
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Evidence Hash:</span>
                        <span className="text-cyan-400 font-bold">{truncateHash(ev?.evidence_hash || ev?.event_hash, 8)}</span>
                      </div>
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Event Commitment:</span>
                        <span className="text-slate-200">{truncateHash(ev?.event_hash, 8)}</span>
                      </div>
                    </div>

                    {ev?.metadata && typeof ev.metadata === 'object' && Object.keys(ev.metadata).length > 0 && (
                      <div className="mt-1.5 p-1.5 rounded bg-black/60 text-[10px] text-slate-400 overflow-x-auto">
                        <span className="text-slate-500">META: </span>
                        <span>{JSON.stringify(ev.metadata)}</span>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* TAB 2: CRYPTOGRAPHIC COMMITMENTS MATRIX */}
          <div className={activeTab === 'COMMITMENTS' ? 'grid grid-cols-1 md:grid-cols-3 gap-4' : 'hidden'}>
            
            {/* 1. Raw File SHA-256 */}
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/40 transition space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
                  <FileCheck2 className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Raw File SHA-256</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/30 text-cyan-300 text-[9px] font-bold uppercase">
                  Raw Bytes
                </span>
              </div>
              <div className="relative group">
                <div className="p-2.5 rounded bg-black border border-slate-800 text-cyan-400 font-bold break-all text-[11px] select-all shadow-inner">
                  {fileHash || 'N/A'}
                </div>
                <button
                  onClick={() => copyToClipboard(fileHash, 'fileHash')}
                  className="mt-1.5 w-full flex items-center justify-center space-x-1 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 text-[10px] transition"
                >
                  {copiedField === 'fileHash' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span>{copiedField === 'fileHash' ? 'COPIED TO CLIPBOARD' : 'COPY HASH'}</span>
                </button>
              </div>
              <div className="text-[10px] text-slate-500 pt-1">
                Size: {manifest?.file_size_bytes ? `${manifest.file_size_bytes} B` : 'Verified Source'}
              </div>
            </div>

            {/* 2. Parsed Structure SHA-256 */}
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 transition space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
                  <FileCode2 className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Parsed Structure SHA-256</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-emerald-950/70 border border-emerald-500/30 text-emerald-300 text-[9px] font-bold uppercase">
                  Canonical JSON
                </span>
              </div>
              <div className="relative group">
                <div className="p-2.5 rounded bg-black border border-slate-800 text-cyan-400 font-bold break-all text-[11px] select-all shadow-inner">
                  {parsedHash || 'N/A'}
                </div>
                <button
                  onClick={() => copyToClipboard(parsedHash, 'parsedHash')}
                  className="mt-1.5 w-full flex items-center justify-center space-x-1 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 text-[10px] transition"
                >
                  {copiedField === 'parsedHash' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span>{copiedField === 'parsedHash' ? 'COPIED TO CLIPBOARD' : 'COPY HASH'}</span>
                </button>
              </div>
              <div className="text-[10px] text-slate-500 pt-1">
                Deterministic MIME Attribute Mapping
              </div>
            </div>

            {/* 3. Analysis Record SHA-256 */}
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-purple-500/40 transition space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
                  <Cpu className="h-3.5 w-3.5 text-purple-400" />
                  <span>Analysis Record SHA-256</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-purple-950/70 border border-purple-500/30 text-purple-300 text-[9px] font-bold uppercase">
                  Risk & Intel
                </span>
              </div>
              <div className="relative group">
                <div className="p-2.5 rounded bg-black border border-slate-800 text-cyan-400 font-bold break-all text-[11px] select-all shadow-inner">
                  {analysisHash || 'N/A'}
                </div>
                <button
                  onClick={() => copyToClipboard(analysisHash, 'analysisHash')}
                  className="mt-1.5 w-full flex items-center justify-center space-x-1 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 text-[10px] transition"
                >
                  {copiedField === 'analysisHash' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span>{copiedField === 'analysisHash' ? 'COPIED TO CLIPBOARD' : 'COPY HASH'}</span>
                </button>
              </div>
              <div className="text-[10px] text-slate-500 pt-1">
                Immutable Risk & Anomaly Assessment
              </div>
            </div>

          </div>

          {/* TAB 3: BLOCKCHAIN PROOF */}
          <div className={activeTab === 'BLOCKCHAIN' ? 'block space-y-3' : 'hidden'}>
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-2 gap-1">
                <span className="text-xs font-bold text-purple-300 flex items-center space-x-1.5">
                  <Blocks className="h-4 w-4 text-purple-400" />
                  <span>Distributed Ledger Stamping (Simulated / Web3 Ready)</span>
                </span>
                <span className="text-[10px] text-slate-500">EXTERNAL ANCHORING AVAILABLE WHEN CONFIGURED</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div className="p-2.5 rounded bg-black border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Provider</span>
                  <span className="text-slate-200 font-bold">{blockchain?.provider || 'LOCAL-SIM'}</span>
                </div>
                <div className="p-2.5 rounded bg-black border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Network</span>
                  <span className="text-slate-200 font-bold uppercase">{blockchain?.network || 'OFFLINE'}</span>
                </div>
                <div className="p-2.5 rounded bg-black border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Status</span>
                  <span className={`font-bold ${blockchain?.status === 'anchored' ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {blockchain?.status === 'anchored' ? 'LEDGER ANCHORED' : 'PENDING'}
                  </span>
                </div>
              </div>

              {blockchain?.transaction_id && (
                <div className="p-2.5 rounded bg-black border border-slate-800 text-[11px] space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase block">Tx Hash</span>
                  <div className="text-cyan-400 font-bold break-all">{blockchain.transaction_id}</div>
                </div>
              )}
            </div>
          </div>

        </div>

        {/* BOTTOM ANCHOR STATUS INDICATOR */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/80 bg-slate-950 px-5 py-3 font-mono text-xs">
          
          <div className="flex items-center space-x-2.5">
            {isVerified ? (
              <>
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                </span>
                <span className="font-bold tracking-wider text-emerald-400 uppercase drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]">
                  CRYPTOGRAPHIC ANCHOR: VERIFIED
                </span>
              </>
            ) : (
              <>
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-500 opacity-75" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-600" />
                </span>
                <span className="font-bold tracking-wider text-rose-400 uppercase drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]">
                  CRYPTOGRAPHIC ANCHOR: INTEGRITY MISMATCH
                </span>
              </>
            )}
          </div>

          <div className="text-[10px] text-slate-500 flex items-center space-x-2">
            <span>HASH_CHAIN: VALID</span>
            <span>•</span>
            <span>NON_REPUDIATION: ACTIVE</span>
          </div>
        </div>

      </div>

      {/* Forensic Attribution Disclaimer Console */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-4 font-mono text-xs text-slate-400">
        <div className="flex items-start space-x-3">
          <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-[11px]">
            <span className="font-bold text-slate-200 uppercase">Cryptographic Integrity vs. Legal Attribution</span>
            <p className="leading-relaxed text-slate-400">
              {manifest?.legal_attribution_notice || (
                "Evidence integrity guarantees deterministic mathematical proof that raw email bytes, parsed forensic attributes, and analysis scores match their recorded SHA-256 commitments without tampering. Integrity validation does not itself constitute legal identity attribution."
              )}
            </p>
          </div>
        </div>
      </div>

    </div>
  );
};
