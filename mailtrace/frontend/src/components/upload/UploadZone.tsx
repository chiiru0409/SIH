import React, { useState, useRef, useCallback } from 'react';
import { 
  Upload, 
  FileText, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  Cpu, 
  Lock, 
  Search, 
  Network, 
  ArrowRight,
  RefreshCw
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Alert } from '../ui/Alert';
import { calculateSha256, formatBytes } from '../../lib/utils';
import { uploadEmail } from '../../lib/api';
import type { UploadResponse } from '../../types/api';

export interface UploadZoneProps {
  onAnalysisComplete: (result: UploadResponse) => void;
  onViewInvestigations: () => void;
}

type Stage = 'IDLE' | 'INGESTING' | 'PARSING' | 'EXTRACTING' | 'ANALYZING' | 'CORRELATING' | 'COMPLETE' | 'ERROR';

const STAGES: { key: Stage; label: string; desc: string; icon: React.ReactNode }[] = [
  { key: 'INGESTING', label: 'INGESTING', desc: 'Anchoring SHA-256 hash & validating MIME container', icon: <Lock className="w-3.5 h-3.5" /> },
  { key: 'PARSING', label: 'PARSING', desc: 'Disassembling RFC 5322 headers, MIME parts & attachments', icon: <FileText className="w-3.5 h-3.5" /> },
  { key: 'EXTRACTING', label: 'EXTRACTING', desc: 'Evaluating SPF, DKIM, DMARC & Received hop chain', icon: <Search className="w-3.5 h-3.5" /> },
  { key: 'ANALYZING', label: 'ANALYZING', desc: 'NLP intent heuristic scoring & infrastructure enrichment', icon: <Cpu className="w-3.5 h-3.5" /> },
  { key: 'CORRELATING', label: 'CORRELATING', desc: 'Synthesizing unified risk & mapping investigation graph', icon: <Network className="w-3.5 h-3.5" /> },
];

export const UploadZone: React.FC<UploadZoneProps> = ({ onAnalysisComplete, onViewInvestigations }) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [clientHash, setClientHash] = useState<string | null>(null);
  const [stage, setStage] = useState<Stage>('IDLE');
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [recentResult, setRecentResult] = useState<UploadResponse | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndSelectFile = async (file: File) => {
    setErrorMsg(null);
    setRecentResult(null);

    // Extension check
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setErrorMsg('Invalid file format. Only RFC 822 / MIME .eml files are accepted for forensic analysis.');
      setSelectedFile(null);
      setClientHash(null);
      return;
    }

    // Size check: max 25 MB
    const maxBytes = 25 * 1024 * 1024;
    if (file.size > maxBytes) {
      setErrorMsg(`File exceeds maximum size of 25 MB (${formatBytes(file.size)}).`);
      setSelectedFile(null);
      setClientHash(null);
      return;
    }

    if (file.size === 0) {
      setErrorMsg('File is empty (0 bytes).');
      setSelectedFile(null);
      setClientHash(null);
      return;
    }

    setSelectedFile(file);
    try {
      const hash = await calculateSha256(file);
      setClientHash(hash);
    } catch {
      setClientHash('Calculating hash on server…');
    }
  };

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
  }, []);

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSelectFile(e.target.files[0]);
    }
  };

  const executeAnalysis = async () => {
    if (!selectedFile) return;

    setErrorMsg(null);
    setStage('INGESTING');
    setCurrentStageIdx(0);

    // Simulate forensic stage transitions while upload is processing
    const stageTimer = setInterval(() => {
      setCurrentStageIdx((prev) => {
        if (prev < STAGES.length - 1) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      const result = await uploadEmail(selectedFile);
      clearInterval(stageTimer);
      setStage('COMPLETE');
      setRecentResult(result);
      onAnalysisComplete(result);
    } catch (err: any) {
      clearInterval(stageTimer);
      setStage('ERROR');
      setErrorMsg(err.message || 'An unexpected error occurred during email forensic analysis.');
    }
  };

  const resetUpload = () => {
    setSelectedFile(null);
    setClientHash(null);
    setStage('IDLE');
    setCurrentStageIdx(0);
    setErrorMsg(null);
    setRecentResult(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8">
      
      {/* Hero Welcome Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/40 border border-cyan-500/30 text-cyan-400 font-mono text-xs uppercase tracking-wider">
          <ShieldAlert className="w-3.5 h-3.5 text-cyber-cyan animate-pulse-subtle" />
          <span>Deterministic Threat Detection & Deep Email Forensics</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white font-mono">
          FROM DETECTION TO <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400">FORENSIC INTELLIGENCE</span>
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
          MailTrace analyzes RFC 5322 email headers, verifies cryptographic authentication (SPF/DKIM/DMARC), extracts threat signals, enriches routing infrastructure, and maps multi-case campaign graphs.
        </p>
      </div>

      {/* Upload Box or Progress State */}
      <div className="cyber-panel rounded-xl p-6 sm:p-8 border border-cyber-borderLight shadow-2xl relative overflow-hidden">
        
        {/* Decorative corner accents */}
        <div className="absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 border-cyber-cyan" />
        <div className="absolute top-0 right-0 w-3 h-3 border-t-2 border-r-2 border-cyber-cyan" />
        <div className="absolute bottom-0 left-0 w-3 h-3 border-b-2 border-l-2 border-cyber-cyan" />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 border-cyber-cyan" />

        {stage === 'IDLE' && (
          <div className="space-y-6">
            {/* Drop Zone */}
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center cursor-pointer transition-all duration-200 ${
                dragActive
                  ? 'border-cyber-cyan bg-cyan-950/30 shadow-[0_0_25px_rgba(0,240,255,0.2)]'
                  : 'border-cyber-border hover:border-cyan-500/60 hover:bg-cyber-surface/50'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,message/rfc822"
                onChange={handleFileInputChange}
                className="hidden"
              />

              <div className="w-16 h-16 mx-auto rounded-2xl bg-cyber-surface border border-cyber-border flex items-center justify-center mb-4 text-cyber-cyan shadow-inner">
                <Upload className="w-8 h-8 animate-pulse-subtle" />
              </div>

              <h3 className="font-mono text-sm sm:text-base font-bold text-slate-100 uppercase tracking-wide">
                DROP RAW <span className="text-cyber-cyan">.EML</span> FILE HERE OR BROWSE
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Accepted: Standard RFC 822 / MIME email files (up to 25 MB)
              </p>
            </div>

            {/* Selected File Details Bar */}
            {selectedFile && (
              <div className="bg-cyber-surface/80 rounded-lg p-4 border border-cyber-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 animate-fadeIn">
                <div className="flex items-start space-x-3 overflow-hidden">
                  <div className="w-9 h-9 rounded bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyber-cyan shrink-0">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div className="overflow-hidden">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-slate-200 truncate">
                        {selectedFile.name}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded">
                        {formatBytes(selectedFile.size)}
                      </span>
                    </div>
                    {clientHash && (
                      <div className="font-mono text-[10px] text-slate-400 truncate mt-0.5">
                        <span className="text-cyber-cyan/70">SHA-256: </span>
                        {clientHash}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center space-x-2 w-full sm:w-auto">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      resetUpload();
                    }}
                  >
                    Clear
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    icon={<ShieldAlert className="w-3.5 h-3.5" />}
                    onClick={(e) => {
                      e.stopPropagation();
                      executeAnalysis();
                    }}
                  >
                    Execute Forensic Analysis
                  </Button>
                </div>
              </div>
            )}

            {/* Quick Actions / Navigation */}
            <div className="flex items-center justify-between pt-2 border-t border-cyber-border/40 text-xs">
              <span className="text-slate-400 font-mono text-[11px]">
                Ready to ingest evidence file into forensic pipeline
              </span>
              <button
                onClick={onViewInvestigations}
                className="text-cyber-cyan hover:text-cyan-300 font-mono text-xs flex items-center space-x-1.5 transition"
              >
                <span>View Existing Investigations</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Forensic Execution Stages Progress View */}
        {(stage !== 'IDLE' && stage !== 'COMPLETE') && (
          <div className="py-8 space-y-8">
            <div className="text-center space-y-2">
              <div className="w-12 h-12 mx-auto rounded-xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyber-cyan">
                <RefreshCw className="w-6 h-6 animate-spin text-cyber-cyan" />
              </div>
              <h3 className="font-mono text-base font-bold text-slate-100 uppercase tracking-widest">
                ANALYZING EVIDENCE CONTAINER
              </h3>
              <p className="text-xs font-mono text-cyan-400/90 truncate max-w-md mx-auto">
                {selectedFile?.name} {clientHash ? `(${clientHash.slice(0, 16)}…)` : ''}
              </p>
            </div>

            {/* Stage Timeline */}
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 max-w-3xl mx-auto">
              {STAGES.map((s, idx) => {
                const isPassed = idx < currentStageIdx;
                const isCurrent = idx === currentStageIdx;
                return (
                  <div
                    key={s.key}
                    className={`p-3 rounded-lg border text-center transition-all ${
                      isCurrent
                        ? 'bg-cyan-950/40 border-cyan-500 text-cyan-200 shadow-[0_0_15px_rgba(0,240,255,0.2)]'
                        : isPassed
                        ? 'bg-slate-900/60 border-emerald-500/40 text-emerald-400'
                        : 'bg-slate-900/30 border-cyber-border text-slate-500'
                    }`}
                  >
                    <div className="flex items-center justify-center mb-1.5">
                      {isPassed ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : isCurrent ? (
                        <span className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin inline-block" />
                      ) : (
                        s.icon
                      )}
                    </div>
                    <div className="font-mono text-[11px] font-bold tracking-wider">{s.label}</div>
                    <div className="text-[9px] text-slate-400 mt-1 leading-tight hidden sm:block">
                      {s.desc}
                    </div>
                  </div>
                );
              })}
            </div>

            {errorMsg && (
              <Alert variant="error" title="Analysis Error">
                {errorMsg}
                <div className="mt-3">
                  <Button variant="outline" size="sm" onClick={resetUpload}>
                    Try Again
                  </Button>
                </div>
              </Alert>
            )}
          </div>
        )}

        {/* Complete State Banner */}
        {stage === 'COMPLETE' && recentResult && (
          <div className="py-6 space-y-6 text-center animate-fadeIn">
            <div className="w-14 h-14 mx-auto rounded-full bg-emerald-950/60 border border-emerald-500/50 flex items-center justify-center text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.3)]">
              <CheckCircle2 className="w-8 h-8" />
            </div>

            <div className="space-y-1">
              <h3 className="font-mono text-lg font-bold text-slate-100 uppercase tracking-wider">
                FORENSIC ANALYSIS COMPLETE
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Case ID: <span className="text-cyber-cyan font-bold">{recentResult.case_id}</span>
              </p>
              <p className="text-[11px] font-mono text-slate-400">
                SHA-256: <span className="text-slate-300">{recentResult.sha256}</span>
              </p>
            </div>

            <div className="flex items-center justify-center space-x-3 pt-2">
              <Button
                variant="outline"
                size="md"
                onClick={resetUpload}
              >
                Analyze Another Email
              </Button>
              <Button
                variant="primary"
                size="md"
                icon={<ArrowRight className="w-4 h-4" />}
                onClick={() => onAnalysisComplete(recentResult)}
              >
                Inspect Full Investigation
              </Button>
            </div>
          </div>
        )}

      </div>

      {errorMsg && stage === 'IDLE' && (
        <Alert variant="error" title="Upload Validation Failed">
          {errorMsg}
        </Alert>
      )}

    </div>
  );
};
