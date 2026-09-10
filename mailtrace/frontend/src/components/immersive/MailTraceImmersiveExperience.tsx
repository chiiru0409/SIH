import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Radio,
  Search,
  Crosshair,
  Network,
  Fingerprint,
  FileText,
  ArrowRight,
  ArrowLeft,
  ChevronRight,
  ExternalLink,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Activity,
  Layers,
  Sparkles,
  Server,
  Globe,
  Share2,
  Cpu,
  RefreshCw,
  Terminal,
  FileCode,
  ShieldCheck,
  Maximize2
} from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { ForensicParticleCanvas } from './ForensicParticleCanvas';

interface StepDefinition {
  id: number;
  label: string;
  tagline: string;
  subtitle: string;
  badge: string;
  color: string;
}

const STAGES: StepDefinition[] = [
  {
    id: 1,
    label: 'DETECT',
    tagline: 'ANOMALY DETECTED',
    subtitle: 'Triple-Protocol Header Analysis & Behavioral NLP Ingestion',
    badge: 'STAGE 01',
    color: 'from-cyan-500 to-blue-600',
  },
  {
    id: 2,
    label: 'TRACE',
    tagline: 'FOLLOW THE INFRASTRUCTURE',
    subtitle: 'Reverse-Hop MTA Routing & Observed Network Attribution',
    badge: 'STAGE 02',
    color: 'from-blue-500 to-indigo-600',
  },
  {
    id: 3,
    label: 'INVESTIGATE',
    tagline: 'CONNECT THE INCIDENTS',
    subtitle: 'Graph Correlation, Shared IOCs & Campaign Clustering',
    badge: 'STAGE 03',
    color: 'from-purple-500 to-rose-600',
  },
  {
    id: 4,
    label: 'EVIDENCE',
    tagline: 'PRESERVE THE TRUTH',
    subtitle: 'Cryptographic Hashing, Merkle Audits & Blockchain Anchoring',
    badge: 'STAGE 04',
    color: 'from-emerald-500 to-cyan-600',
  },
];

export const MailTraceImmersiveExperience: React.FC = () => {
  const {
    activeCaseId,
    cases,
    selectAndInvestigate,
    setActiveTab,
    simulateTamper,
    restoreTamper,
  } = useInvestigation();

  const [currentStep, setCurrentStep] = useState<number>(1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [tamperedState, setTamperedState] = useState<boolean>(false);
  const [activeHeaderTab, setActiveHeaderTab] = useState<'parsed' | 'raw' | 'nlp'>('parsed');

  const activeCase = cases.find(c => c.id === activeCaseId) || cases[0] || {
    id: 'CASE-2026-0842',
    subject: 'URGENT: Microsoft 365 Account Suspension Warning',
    sender: 'security-alerts@auth-ms-portal-update.com',
    recipient: 'cfo.director@enterprise-corp.com',
    receivedTime: '2026-09-09T08:14:25Z',
    verdict: {
      primaryThreat: 'PHISHING',
      severity: 'CRITICAL',
      riskScore: 87,
      confidenceScore: 94,
    },
  };

  // Auto-play timeline loop if enabled
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setCurrentStep(prev => (prev >= 4 ? 1 : prev + 1));
    }, 6500);
    return () => clearInterval(interval);
  }, [isPlaying]);

  const handleTamperToggle = () => {
    if (!tamperedState) {
      simulateTamper(activeCase.id);
      setTamperedState(true);
    } else {
      restoreTamper(activeCase.id);
      setTamperedState(false);
    }
  };

  const handleLaunchSOCStudio = () => {
    selectAndInvestigate(activeCase.id);
    setActiveTab('investigation');
  };

  return (
    <div className="relative min-h-screen w-full bg-[#040711] text-slate-100 font-sans overflow-x-hidden selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background Interactive WebGL/Canvas Particle Grid */}
      <ForensicParticleCanvas stage={currentStep} intensity={1.1} />

      {/* Atmospheric Vignette and Gradient Lighting */}
      <div className="pointer-events-none fixed inset-0 bg-radial-vignette opacity-80" />
      <div className="pointer-events-none fixed -top-40 -left-40 w-96 h-96 rounded-full bg-cyan-600/10 blur-[120px]" />
      <div className="pointer-events-none fixed -bottom-40 -right-40 w-96 h-96 rounded-full bg-purple-600/10 blur-[120px]" />

      {/* Top Floating Control Bar */}
      <header className="sticky top-0 z-40 backdrop-blur-xl bg-[#070c18]/85 border-b border-slate-800/80 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3.5">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-glow-cyan">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold tracking-widest text-slate-100 uppercase">
                MAILTRACE
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold">
                CINEMATIC SOC
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-400">
              Target: <span className="text-cyan-400 font-semibold">{activeCase.id}</span> • SIH26106 Enterprise DFIR
            </p>
          </div>
        </div>

        {/* Stage Pills Navigation */}
        <nav className="hidden md:flex items-center gap-1.5 p-1 rounded-xl bg-slate-950/80 border border-slate-800/90 shadow-inner">
          {STAGES.map(s => {
            const isActive = currentStep === s.id;
            return (
              <button
                key={s.id}
                onClick={() => {
                  setCurrentStep(s.id);
                  setIsPlaying(false);
                }}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-glow-cyan'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${isActive ? 'bg-cyan-400 animate-ping' : 'bg-slate-600'}`} />
                <span>{s.badge} {s.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Header Action Buttons */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-xs border transition-colors ${
              isPlaying
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                : 'bg-slate-900/80 text-slate-300 border-slate-700/80 hover:bg-slate-800'
            }`}
          >
            <Activity className={`w-3.5 h-3.5 ${isPlaying ? 'animate-spin' : ''}`} />
            <span>{isPlaying ? 'Auto-Cycle ON' : 'Auto-Cycle OFF'}</span>
          </button>

          <button
            onClick={() => setActiveTab('overview')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 font-mono text-xs font-medium transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>SOC Portal</span>
          </button>

          <button
            onClick={handleLaunchSOCStudio}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono text-xs font-bold transition-all shadow-glow-cyan"
          >
            <span>Launch SOC Studio</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Main Narrative Viewport */}
      <main className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 z-10">
        
        {/* Stage Hero Title Card */}
        <div className="relative p-6 sm:p-8 rounded-2xl bg-gradient-to-b from-slate-900/90 via-slate-950/95 to-[#060a16] border border-slate-800/90 shadow-2xl backdrop-blur-md overflow-hidden">
          <div className="absolute -top-24 right-10 w-80 h-80 rounded-full bg-cyan-500/10 blur-[100px] pointer-events-none" />
          
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="space-y-2 max-w-3xl">
              <div className="flex items-center gap-2.5">
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  {STAGES[currentStep - 1].badge}
                </span>
                <span className="text-xs font-mono text-slate-400 tracking-wider uppercase">
                  FORENSIC INVESTIGATION PIPELINE
                </span>
              </div>
              <h2 className="text-2xl sm:text-4xl font-extrabold font-mono tracking-tight text-white flex items-center gap-3">
                <span className="bg-gradient-to-r from-white via-slate-100 to-cyan-300 bg-clip-text text-transparent">
                  {STAGES[currentStep - 1].tagline}
                </span>
              </h2>
              <p className="text-sm sm:text-base text-slate-300 font-sans leading-relaxed">
                {STAGES[currentStep - 1].subtitle}
              </p>
            </div>

            {/* Quick Step Switcher */}
            <div className="flex items-center gap-2 shrink-0">
              <button
                disabled={currentStep === 1}
                onClick={() => setCurrentStep(prev => Math.max(1, prev - 1))}
                className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none border border-slate-700 text-slate-300 transition-colors"
                title="Previous Stage"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
              <div className="font-mono text-xs text-slate-400 px-3 py-2 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-cyan-400 font-bold">{currentStep}</span> / 4
              </div>
              <button
                disabled={currentStep === 4}
                onClick={() => setCurrentStep(prev => Math.min(4, prev + 1))}
                className="p-2.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 disabled:opacity-30 disabled:pointer-events-none border border-cyan-500/40 text-cyan-300 transition-colors"
                title="Next Stage"
              >
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* STAGE 1: DETECT */}
        {/* ========================================================================= */}
        {currentStep === 1 && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Top Signal Badges */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/40 flex items-center gap-3.5">
                <div className="p-2.5 rounded-lg bg-red-500/20 text-red-400">
                  <XCircle className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-[10px] font-mono text-red-400 uppercase tracking-wider font-semibold">
                    SPF / DKIM / DMARC
                  </div>
                  <div className="text-sm font-mono font-bold text-slate-100">
                    TRIPLE PROTOCOL FAILURE
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/40 flex items-center gap-3.5">
                <div className="p-2.5 rounded-lg bg-amber-500/20 text-amber-400">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-[10px] font-mono text-amber-400 uppercase tracking-wider font-semibold">
                    NLP Urgency Signal
                  </div>
                  <div className="text-sm font-mono font-bold text-slate-100">
                    92% Coercive Pressure
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/40 flex items-center gap-3.5">
                <div className="p-2.5 rounded-lg bg-purple-500/20 text-purple-400">
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-[10px] font-mono text-purple-400 uppercase tracking-wider font-semibold">
                    Typosquat Classification
                  </div>
                  <div className="text-sm font-mono font-bold text-slate-100">
                    `micros0ft` (0 vs o)
                  </div>
                </div>
              </div>
            </div>

            {/* Ingestion & Deep Inspection Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left: Email Header Telemetry */}
              <div className="lg:col-span-7 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span className="font-mono text-xs font-bold text-slate-200 uppercase">
                      Inbound Email Packet Stream
                    </span>
                  </div>
                  <div className="flex gap-1">
                    <button
                      onClick={() => setActiveHeaderTab('parsed')}
                      className={`px-2.5 py-1 text-[11px] font-mono rounded ${
                        activeHeaderTab === 'parsed'
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'text-slate-400 hover:bg-slate-800'
                      }`}
                    >
                      Parsed Model
                    </button>
                    <button
                      onClick={() => setActiveHeaderTab('raw')}
                      className={`px-2.5 py-1 text-[11px] font-mono rounded ${
                        activeHeaderTab === 'raw'
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'text-slate-400 hover:bg-slate-800'
                      }`}
                    >
                      Raw RFC 822
                    </button>
                    <button
                      onClick={() => setActiveHeaderTab('nlp')}
                      className={`px-2.5 py-1 text-[11px] font-mono rounded ${
                        activeHeaderTab === 'nlp'
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'text-slate-400 hover:bg-slate-800'
                      }`}
                    >
                      NLP Vectors
                    </button>
                  </div>
                </div>

                {activeHeaderTab === 'parsed' && (
                  <div className="space-y-3 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <div className="text-slate-400 text-[10px]">SUBJECT:</div>
                      <div className="text-slate-200 font-bold">{activeCase.subject}</div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                        <div className="text-slate-400 text-[10px]">SENDER (ENVELOPE FROM):</div>
                        <div className="text-red-400 font-semibold truncate">{activeCase.sender || 'security-alerts@auth-ms-portal-update.com'}</div>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                        <div className="text-slate-400 text-[10px]">CLAIMED DISPLAY NAME:</div>
                        <div className="text-amber-300 font-semibold">Microsoft 365 Security Team</div>
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <div className="text-slate-400 text-[10px]">ORIGINATING ROUTE IP:</div>
                      <div className="text-cyan-400 font-bold flex items-center justify-between">
                        <span>185.220.101.42 (Tor Exit / Relay AS60729)</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40">
                          UNAUTHORIZED SPF
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {activeHeaderTab === 'raw' && (
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed">
{`Received: from relay-east-02.ams.nl (185.220.101.42)
  by mx.enterprise-defense.net with ESMTP id 8429184
  for <cfo.director@enterprise-corp.com>; Wed, 09 Sep 2026 08:14:25 UTC
Authentication-Results: mx.enterprise-defense.net;
  spf=fail (sender IP 185.220.101.42 not permitted by auth-ms-portal-update.com)
  dkim=fail header.d=auth-ms-portal-update.com (bad signature)
  dmarc=fail action=quarantine
From: "Microsoft 365 Security Team" <security-alerts@auth-ms-portal-update.com>
Reply-To: security-reply-gate@proton.me
Message-ID: <20260909081425.48201.sec@auth-ms-portal-update.com>
X-Mailer: Automated Security Dispatcher v4.1`}
                  </pre>
                )}

                {activeHeaderTab === 'nlp' && (
                  <div className="space-y-2.5 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-slate-950/90 border border-amber-500/30 space-y-1.5">
                      <div className="text-amber-400 font-bold flex items-center justify-between">
                        <span>Coercive NLP Tokens Extracted:</span>
                        <span className="text-[10px] bg-amber-500/20 px-2 py-0.5 rounded">High Severity</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {['"expire in 2 hours"', '"permanent account suspension"', '"action required immediately"', '"verify credentials"'].map(token => (
                          <span key={token} className="px-2 py-0.5 rounded bg-amber-950/40 border border-amber-500/40 text-amber-300 text-[11px]">
                            {token}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Right: Automated Verdict Gauge */}
              <div className="lg:col-span-5 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl flex flex-col justify-between space-y-6">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                      Automated Threat Classifier
                    </span>
                    <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-mono text-[10px] font-bold border border-red-500/40">
                      HIGH CONFIDENCE
                    </span>
                  </div>
                  <div className="mt-4 p-4 rounded-xl bg-slate-950/90 border border-red-500/30 space-y-3 text-center">
                    <div className="text-xs font-mono text-slate-400">SYNTHESIZED RISK SCORE</div>
                    <div className="text-5xl font-extrabold font-mono text-red-400 tracking-tight">
                      87<span className="text-2xl text-slate-500">/100</span>
                    </div>
                    <div className="text-xs font-mono text-red-300 font-bold">
                      VERDICT: CREDENTIAL HARVESTING PHISHING
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-400">Next Recommended Action:</div>
                  <button
                    onClick={() => setCurrentStep(2)}
                    className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-glow-cyan"
                  >
                    <span>Proceed to Stage 02: Trace MTA Infrastructure</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* STAGE 2: TRACE */}
        {/* ========================================================================= */}
        {currentStep === 2 && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Reverse-Hop MTA Flow Visualization */}
            <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="font-mono text-base font-bold text-slate-100 flex items-center gap-2">
                    <Server className="w-5 h-5 text-blue-400" />
                    <span>Reverse-Hop MTA Routing Sequence</span>
                  </h3>
                  <p className="text-xs font-sans text-slate-400">
                    Reconstructed from RFC 822 `Received` headers from perimeter ingestion to origin MTA.
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded bg-blue-500/20 text-blue-300 font-mono text-xs border border-blue-500/40">
                  3 Hops Reconstructed
                </span>
              </div>

              {/* Hop Cards Flow */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 relative">
                {/* Hop 01 */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-red-500/40 space-y-2 relative">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-bold border border-red-500/30">
                      HOP 01 • INJECTION ORIGIN
                    </span>
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  </div>
                  <div className="font-mono text-sm font-bold text-red-400">185.220.101.42</div>
                  <div className="text-xs font-mono text-slate-300">AS60729 (Zwiebelfreunde Tor Relay)</div>
                  <div className="text-[11px] font-mono text-slate-400">
                    Observed Location: Amsterdam, Netherlands
                  </div>
                  <div className="text-[10px] text-red-400/90 pt-1 font-mono">
                    ⚠️ Anonymizing Tor Relay Exit Node
                  </div>
                </div>

                {/* Hop 02 */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-blue-500/40 space-y-2 relative">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold border border-blue-500/30">
                      HOP 02 • INTERMEDIATE MTA
                    </span>
                    <span className="w-2 h-2 rounded-full bg-blue-400" />
                  </div>
                  <div className="font-mono text-sm font-bold text-blue-400">relay-east-02.ams.nl</div>
                  <div className="text-xs font-mono text-slate-300">ESMTP Gateway Router</div>
                  <div className="text-[11px] font-mono text-slate-400">
                    Transit Delay: +480ms
                  </div>
                  <div className="text-[10px] text-slate-400 pt-1 font-mono">
                    Forwarded with forged envelope
                  </div>
                </div>

                {/* Hop 03 */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-emerald-500/40 space-y-2 relative">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                      HOP 03 • DEFENSE PERIMETER
                    </span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  </div>
                  <div className="font-mono text-sm font-bold text-emerald-400">mx.enterprise-defense.net</div>
                  <div className="text-xs font-mono text-slate-300">Enterprise Ingestion Gateway</div>
                  <div className="text-[11px] font-mono text-slate-400">
                    Received: 2026-09-09 08:14:25 UTC
                  </div>
                  <div className="text-[10px] text-emerald-400 pt-1 font-mono">
                    ✓ Quarantined for SOC Review
                  </div>
                </div>
              </div>

              {/* Observed Infrastructure Geolocation Map Box */}
              <div className="p-5 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <span className="font-mono text-xs font-bold text-slate-200 uppercase">
                      Observed Infrastructure Geolocation & ASN Profile
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    Coordinates: 52.3676° N, 4.9041° E
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-400 uppercase">Autonomous System</div>
                    <div className="font-bold text-cyan-400">AS60729</div>
                    <div className="text-[11px] text-slate-300">Zwiebelfreunde e.V.</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-400 uppercase">Observed Region</div>
                    <div className="font-bold text-slate-200">Amsterdam, NL</div>
                    <div className="text-[11px] text-slate-400">Western Europe</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-400 uppercase">Infrastructure Type</div>
                    <div className="font-bold text-red-400">Tor Relay / Anonymizer</div>
                    <div className="text-[11px] text-slate-400">Non-Residential Hosted</div>
                  </div>
                </div>

                {/* Technical Accuracy Forensic Disclaimer */}
                <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/30 text-[11px] font-mono text-blue-300 flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                  <span>
                    <strong>Forensic Attribution Integrity Note:</strong> Geolocation denotes the physical location of the observed upstream routing infrastructure node (Tor exit relay), not the physical presence of the threat actor.
                  </span>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={() => setCurrentStep(3)}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-glow-cyan"
                >
                  <span>Proceed to Stage 03: Correlate Campaign Incidents</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* STAGE 3: INVESTIGATE */}
        {/* ========================================================================= */}
        {currentStep === 3 && (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="font-mono text-base font-bold text-slate-100 flex items-center gap-2">
                    <Network className="w-5 h-5 text-purple-400" />
                    <span>Multi-Incident Graph Correlation & Campaign Cluster</span>
                  </h3>
                  <p className="text-xs font-sans text-slate-400">
                    MailTrace automated correlation engine links distinct cases across shared ASN, lookalike domain, and credential harvesting kits.
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded bg-purple-500/20 text-purple-300 font-mono text-xs border border-purple-500/40">
                  Cluster: CAMP-FIN-0842
                </span>
              </div>

              {/* Correlation Graph Representation */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Visual Cluster Diagram */}
                <div className="lg:col-span-7 p-6 rounded-xl bg-slate-950/90 border border-slate-800 relative flex flex-col justify-center items-center min-h-[340px] overflow-hidden">
                  <div className="absolute inset-0 cyber-grid opacity-30 pointer-events-none" />
                  
                  {/* Central Campaign Core */}
                  <div className="relative z-10 p-4 rounded-2xl bg-gradient-to-r from-purple-900/60 to-rose-900/60 border border-purple-500/60 text-center shadow-2xl space-y-1 animate-pulse">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/30 text-purple-200 uppercase font-bold">
                      CAMPAIGN CLUSTER
                    </span>
                    <div className="font-mono text-sm font-bold text-white">CAMP-FIN-0842</div>
                    <div className="text-[11px] font-mono text-purple-300">FIN-SPEAR-M365 Phishing</div>
                  </div>

                  {/* Radiating Case Nodes */}
                  <div className="w-full grid grid-cols-3 gap-3 mt-8 relative z-10 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-slate-900/90 border border-red-500/50 text-center space-y-1">
                      <div className="text-[10px] text-red-400 font-bold">CASE-2026-0842 (Active)</div>
                      <div className="text-[11px] text-slate-300 truncate">cfo.director@enterprise</div>
                      <div className="text-[9px] text-slate-500">AS60729 • Tor Exit</div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900/90 border border-purple-500/50 text-center space-y-1">
                      <div className="text-[10px] text-purple-400 font-bold">CASE-2026-0843</div>
                      <div className="text-[11px] text-slate-300 truncate">vp.finance@enterprise</div>
                      <div className="text-[9px] text-slate-500">Shared Domain IOC</div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900/90 border border-purple-500/50 text-center space-y-1">
                      <div className="text-[10px] text-purple-400 font-bold">CASE-2026-0844</div>
                      <div className="text-[11px] text-slate-300 truncate">hr.payroll@enterprise</div>
                      <div className="text-[9px] text-slate-500">Shared Credential Kit</div>
                    </div>
                  </div>
                </div>

                {/* Shared IOC Summary */}
                <div className="lg:col-span-5 space-y-3 font-mono text-xs">
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3">
                    <div className="text-slate-400 text-[10px] uppercase tracking-wider font-bold">
                      Correlation Vectors Detected:
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <div className="text-cyan-400 font-bold flex items-center justify-between">
                        <span>1. Shared ASN Infrastructure</span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300">100% Match</span>
                      </div>
                      <div className="text-[11px] text-slate-400">All 3 emails routed via AS60729 Tor Exit Nodes.</div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <div className="text-purple-400 font-bold flex items-center justify-between">
                        <span>2. Lookalike Domain Architecture</span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300">Identical Registrar</span>
                      </div>
                      <div className="text-[11px] text-slate-400">`auth-ms-portal-update.com` registered with same Namecheap token.</div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <div className="text-amber-400 font-bold flex items-center justify-between">
                        <span>3. Target Archetype</span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">Executive Tier</span>
                      </div>
                      <div className="text-[11px] text-slate-400">C-Suite & Finance accounts targeted within 22-minute window.</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={() => setCurrentStep(4)}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-glow-cyan"
                >
                  <span>Proceed to Stage 04: Cryptographic Evidence Vault</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* STAGE 4: EVIDENCE */}
        {/* ========================================================================= */}
        {currentStep === 4 && (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="font-mono text-base font-bold text-slate-100 flex items-center gap-2">
                    <Fingerprint className="w-5 h-5 text-emerald-400" />
                    <span>Cryptographic Evidence & Chain of Custody Vault</span>
                  </h3>
                  <p className="text-xs font-sans text-slate-400">
                    Dual-hash SHA-256 verification and immutable blockchain anchor proof for legal admissibility.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded font-mono text-xs border font-bold ${
                    tamperedState
                      ? 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    {tamperedState ? '⚠️ INTEGRITY VIOLATION DETECTED' : '✓ EVIDENCE SEALED & VERIFIED'}
                  </span>
                </div>
              </div>

              {/* Cryptographic Vault Card */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-8 p-6 rounded-xl bg-slate-950/90 border border-slate-800 space-y-4 font-mono text-xs">
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                    <div className="text-slate-400 text-[10px]">CANONICAL ARTIFACT ID:</div>
                    <div className="text-emerald-400 font-bold">EVID-EML-0842-RAW (Original RFC 822 Payload)</div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                    <div className="text-slate-400 text-[10px]">SHA-256 CANONICAL DIGEST:</div>
                    <div className={`font-mono text-xs break-all ${tamperedState ? 'text-red-400 line-through' : 'text-cyan-300'}`}>
                      3a7f8b9c2d1e0f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a
                    </div>
                    {tamperedState && (
                      <div className="text-red-400 text-[11px] pt-1">
                        Calculated Hash: 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e (MISMATCH!)
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                      <div className="text-slate-400 text-[10px]">BLAKE3 DUAL-HASH:</div>
                      <div className="text-slate-300 truncate font-mono text-[11px]">
                        7c4a1b8e9f2d3e4c5b6a7d8e9f0a1b2c
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                      <div className="text-slate-400 text-[10px]">CHAIN ANCHOR CAPABILITY:</div>
                      <div className="text-slate-300 font-mono text-[11px]">
                        Polygon PoS Sandbox (Tx: 0x8f2a...c4e1)
                      </div>
                    </div>
                  </div>
                </div>

                {/* Interactive Tamper Simulator */}
                <div className="lg:col-span-4 p-6 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col justify-between space-y-4">
                  <div>
                    <div className="text-xs font-mono text-slate-300 font-bold flex items-center gap-2">
                      <Lock className="w-4 h-4 text-emerald-400" />
                      <span>Judge Live Tamper Simulation</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans mt-1">
                      Demonstrates how MailTrace instantly detects even a 1-bit modification to stored RFC 822 evidence headers.
                    </p>
                  </div>

                  <button
                    onClick={handleTamperToggle}
                    className={`w-full py-3 rounded-xl font-mono text-xs font-bold transition-all flex items-center justify-center gap-2 ${
                      tamperedState
                        ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-glow-emerald'
                        : 'bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40'
                    }`}
                  >
                    {tamperedState ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Restore Cryptographic Integrity</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Simulate 1-Bit Header Tamper</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Action Jump to SOC Studio */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-gradient-to-r from-slate-950 to-cyan-950/40 border border-cyan-500/30">
                <div className="text-xs font-mono text-slate-300">
                  Ready to inspect full raw artifact, run response actions, or generate court-ready PDF?
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setActiveTab('reports')}
                    className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 font-mono text-xs"
                  >
                    Generate PDF Report
                  </button>
                  <button
                    onClick={handleLaunchSOCStudio}
                    className="flex items-center gap-2 px-6 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-glow-cyan"
                  >
                    <span>Open in Investigation Workspace</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

      </main>
    </div>
  );
};

export default MailTraceImmersiveExperience;
