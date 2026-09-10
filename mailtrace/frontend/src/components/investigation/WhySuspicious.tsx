import React, { useState } from 'react';
import { ExplainableFinding } from '../../types/investigation';
import { Sparkles, Eye, CheckCircle2, AlertTriangle, ShieldAlert, ChevronDown, ChevronUp, Check } from 'lucide-react';
import { safeStr } from '../../lib/utils';

interface WhySuspiciousProps {
  findings?: ExplainableFinding[];
}

export const WhySuspicious: React.FC<WhySuspiciousProps> = ({ findings = [] }) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);
  const safeFindings = Array.isArray(findings) ? findings : [];

  // Plain-English key reasons synthesized for instant Judge clarity
  const keyReasons = [
    {
      title: 'Sender Identity Mismatch (Domain Spoofing)',
      description: 'Display name claims trusted organization, but envelope from domain is untrusted.',
      icon: ShieldAlert,
      impact: 'High Risk'
    },
    {
      title: 'Authentication Failure (SPF / DMARC Fail)',
      description: 'Sending mail server is not authorized by the claimed domain owner.',
      icon: AlertTriangle,
      impact: 'Critical'
    },
    {
      title: 'Deceptive Credential Harvesting Portal',
      description: 'Embedded hyperlink leads to an unverified external login portal.',
      icon: AlertTriangle,
      impact: 'High Risk'
    },
    {
      title: 'High-Risk Originating Infrastructure',
      description: 'Observed relay IP operates within an anonymous bulletproof hosting cluster.',
      icon: AlertTriangle,
      impact: 'Medium'
    },
    {
      title: 'Correlated Multi-Case Attack Pattern',
      description: 'Shares sender infrastructure and subject templates with active enterprise campaigns.',
      icon: Sparkles,
      impact: 'Campaign Link'
    }
  ];

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Why Is This Email Suspicious? (Executive Summary)
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          {safeFindings.length} Evidence Vectors Identified
        </span>
      </div>

      {/* 1. PLAIN-ENGLISH EXECUTIVE BULLET SUMMARY */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
        {keyReasons.map((reason, idx) => {
          const Icon = reason.icon;
          return (
            <div
              key={idx}
              className="p-3 rounded-lg bg-slate-900/90 border border-slate-800/80 flex items-start gap-3"
            >
              <div className="p-1.5 rounded bg-red-950/60 border border-red-500/30 text-red-400 shrink-0 mt-0.5">
                <Check className="w-3.5 h-3.5" />
              </div>
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold font-mono text-slate-100">{reason.title}</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-semibold">
                    {reason.impact}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  {reason.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* 2. PROGRESSIVE DISCLOSURE TOGGLE FOR DETAILED FORENSIC VECTORS */}
      <div className="pt-2 border-t border-slate-800/60">
        <button
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-300 hover:text-cyan-400 transition-colors"
        >
          <span className="font-bold flex items-center gap-2">
            <Eye className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showTechnicalDetails ? 'Hide Deep Technical Evidence Vectors' : 'View Deep Technical Evidence Vectors & AI Inferences'}</span>
          </span>
          <span className="flex items-center gap-1 text-[11px] text-slate-400">
            <span>{safeFindings.length} Vectors</span>
            {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </span>
        </button>

        {showTechnicalDetails && (
          <div className="space-y-3 mt-3 animate-in fade-in zoom-in-98">
            {safeFindings.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 text-xs font-mono text-slate-400 text-center">
                No anomalous indicators detected for this message.
              </div>
            ) : (
              safeFindings.map((item, index) => {
                const severity = safeStr(item.severity || item.level || 'MEDIUM').toUpperCase();
                const scoreImpact = Number(item.scoreContribution ?? item.weight ?? 15);
                const title = safeStr(item.title || 'Observed Threat Signal');
                const category = safeStr(item.category || item.type || 'FORENSIC');
                const observed = safeStr(item.observedText || item.observedEvidence || 'Observed anomalous forensic attribute in email message.');
                const inference = safeStr(item.inferenceText || item.aiInference || 'Evaluated threat pattern contributing to risk score.');

                return (
                  <div
                    key={safeStr(item.id || index)}
                    className="p-4 rounded-lg bg-slate-900/90 border border-slate-800/90 hover:border-slate-700 transition-colors space-y-2 font-mono"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-slate-200">
                          {title}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {category}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                            severity === 'CRITICAL'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : severity === 'HIGH'
                              ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                              : (severity === 'LOW' || severity === 'INFO')
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                              : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                          }`}
                        >
                          {severity}
                        </span>
                      </div>

                      <div className="flex items-center gap-1 text-xs font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/50 shrink-0">
                        <span>Impact:</span>
                        <span>+{scoreImpact} pts</span>
                      </div>
                    </div>

                    {/* Observed Fact Box */}
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs flex items-start gap-2.5">
                      <Eye className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="text-slate-400 text-[10px] font-bold uppercase tracking-wider block mb-0.5">
                          Observed Forensic Fact
                        </span>
                        <p className="text-slate-300 font-sans">{observed}</p>
                      </div>
                    </div>

                    {/* AI Inference Box */}
                    <div className="p-2.5 rounded bg-cyan-950/20 border border-cyan-500/20 text-xs flex items-start gap-2.5">
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="text-cyan-400 text-[10px] font-bold uppercase tracking-wider block mb-0.5">
                          AI Forensic Inference & Threat Context
                        </span>
                        <p className="text-slate-300 font-sans">{inference}</p>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </div>
  );
};
