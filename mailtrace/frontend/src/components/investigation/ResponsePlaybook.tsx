import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, Ban, CheckCircle2, AlertTriangle, ArrowRight, Activity, Terminal } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { InvestigationCase } from '../../types/investigation';
import { safeStr } from '../../lib/utils';

interface ResponsePlaybookProps {
  investigationCase: InvestigationCase;
}

export const ResponsePlaybook: React.FC<ResponsePlaybookProps> = ({ investigationCase }) => {
  const { addResponseAction, updateCaseStatus, responses } = useInvestigation();
  const [feedback, setFeedback] = useState<string | null>(null);

  const caseId = safeStr(investigationCase.id || 'CASE-UNKNOWN');
  const severity = safeStr(investigationCase.verdict?.severity || 'HIGH').toUpperCase();
  const primaryThreat = safeStr(investigationCase.verdict?.primaryThreat || 'SUSPICIOUS');
  const sender = safeStr(investigationCase.sender || 'unknown@domain.com');
  const recipient = safeStr(investigationCase.recipient || 'target@enterprise.com');
  const domain = sender.includes('@') ? sender.split('@')[1] : 'sender-domain.com';

  const isCritical = severity === 'CRITICAL';
  const isBenign = severity === 'LOW' || severity === 'INFO' || primaryThreat === 'BENIGN';

  const recommendedAction = isCritical
    ? 'QUARANTINE'
    : isBenign
    ? 'MARK_SAFE'
    : 'BLOCK_DOMAIN';

  const executeAction = (actionType: 'QUARANTINE' | 'BLOCK_DOMAIN' | 'BLOCK_IP' | 'MARK_SAFE' | 'ESCALATE') => {
    let target = recipient;
    let reason = '';
    let status = 'EXECUTED' as const;

    if (actionType === 'QUARANTINE') {
      target = recipient;
      reason = `Automated quarantine applied to message ${caseId} (${primaryThreat})`;
      updateCaseStatus(caseId, 'CONTAINED');
    } else if (actionType === 'BLOCK_DOMAIN') {
      target = domain;
      reason = `Perimeter block enacted for sender domain ${domain}`;
    } else if (actionType === 'MARK_SAFE') {
      target = recipient;
      reason = `Message marked as legitimate baseline communication`;
      updateCaseStatus(caseId, 'RESOLVED');
    } else if (actionType === 'ESCALATE') {
      target = 'SOC Incident Commander';
      reason = `Escalated for senior digital forensics and CERT-In notification`;
    }

    addResponseAction({
      caseId,
      actionType: actionType === 'MARK_SAFE' ? 'RELEASE' : actionType === 'ESCALATE' ? 'ADD_BANNER' : actionType,
      target,
      status,
      executedBy: 'SOC Analyst (Demonstration Action)',
      reason,
      impactScore: isCritical ? 90 : 40,
    });

    setFeedback(`Demonstration action "${actionType}" executed and recorded to audit ledger.`);
    setTimeout(() => setFeedback(null), 3000);
  };

  const caseResponses = responses.filter(r => r.caseId === caseId);

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Incident Response & Mitigation Playbook
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-slate-800 font-bold">
          DEMO RESPONSE SIMULATOR
        </span>
      </div>

      {/* Recommended Action Banner */}
      <div
        className={`p-4 rounded-lg border ${
          isCritical
            ? 'bg-red-950/30 border-red-500/40'
            : isBenign
            ? 'bg-emerald-950/30 border-emerald-500/40'
            : 'bg-amber-950/30 border-amber-500/40'
        } flex flex-col md:flex-row md:items-center justify-between gap-4`}
      >
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400 uppercase">Recommended Strategy:</span>
            <span
              className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                isCritical
                  ? 'bg-red-500/20 text-red-300'
                  : isBenign
                  ? 'bg-emerald-500/20 text-emerald-300'
                  : 'bg-amber-500/20 text-amber-300'
              }`}
            >
              {recommendedAction}
            </span>
          </div>
          <p className="text-xs text-slate-300 max-w-xl font-sans leading-relaxed">
            {isCritical
              ? 'Multi-vector threat findings confirm unauthorized sender identity and credential capture URLs. Recommend immediate perimeter containment.'
              : isBenign
              ? 'Full cryptographic authentication achieved across internal infrastructure. Safe to release to recipient.'
              : 'Suspicious anomalies detected without definitive payload. Recommend quarantine and user notification banner.'}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={() => executeAction('QUARANTINE')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600/20 border border-red-500/50 hover:bg-red-600/30 text-red-300 text-xs font-mono font-bold transition-all shadow-glow-critical"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Quarantine</span>
          </button>

          <button
            onClick={() => executeAction('BLOCK_DOMAIN')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-orange-600/20 border border-orange-500/40 hover:bg-orange-600/30 text-orange-300 text-xs font-mono transition-colors"
          >
            <Ban className="w-3.5 h-3.5" />
            <span>Block Domain</span>
          </button>

          <button
            onClick={() => executeAction('MARK_SAFE')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-600/20 border border-emerald-500/40 hover:bg-emerald-600/30 text-emerald-300 text-xs font-mono transition-colors"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Mark Safe</span>
          </button>

          <button
            onClick={() => executeAction('ESCALATE')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-600/20 border border-purple-500/40 hover:bg-purple-600/30 text-purple-300 text-xs font-mono transition-colors"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Escalate</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div className="p-2.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-xs font-mono text-cyan-300 flex items-center gap-2 animate-in fade-in">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>{feedback}</span>
        </div>
      )}

      {/* Case-Specific Response Log */}
      {caseResponses.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-slate-800/80">
          <div className="text-xs font-mono font-bold text-slate-300">
            Recorded Mitigation Actions for {caseId}
          </div>
          <div className="space-y-1.5">
            {caseResponses.map((res, idx) => (
              <div
                key={res.id || idx}
                className="p-2.5 rounded bg-slate-900/90 border border-slate-800 text-xs font-mono flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="font-bold text-cyan-400">{res.actionType}</span>
                  <span className="text-slate-400">•</span>
                  <span className="text-slate-300">{res.target}</span>
                </div>
                <div className="text-[11px] text-slate-500">
                  {new Date(res.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
