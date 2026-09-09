import React from 'react';
import {
  ShieldAlert,
  Ban,
  FileText,
  Fingerprint,
  Copy,
  Clock,
  Check
} from 'lucide-react';
import { InvestigationCase } from '../../types/investigation';
import { Badge } from '../common/Badge';
import { useInvestigation } from '../../context/InvestigationContext';
import { safeStr } from '../../lib/utils';

interface CaseHeaderProps {
  investigationCase: InvestigationCase;
  onOpenReport: () => void;
  onOpenEvidence: () => void;
}

export const CaseHeader: React.FC<CaseHeaderProps> = ({
  investigationCase,
  onOpenReport,
  onOpenEvidence
}) => {
  const { addResponseAction, updateCaseStatus } = useInvestigation();
  const [copied, setCopied] = React.useState(false);

  const caseId = safeStr(investigationCase.id || 'CASE-UNKNOWN');
  const recipient = safeStr(investigationCase.recipient || 'soc-target@enterprise.com');
  const sender = safeStr(investigationCase.sender || 'unknown@domain.com');
  const subject = safeStr(investigationCase.subject || 'Forensic Analyzed Message');
  const status = safeStr(investigationCase.status || 'INVESTIGATING');
  const severity = safeStr(investigationCase.verdict?.severity || 'HIGH').toUpperCase();
  const primaryThreat = safeStr(investigationCase.verdict?.primaryThreat || 'THREAT');

  let dateDisplay = 'Timestamp Recorded';
  try {
    dateDisplay = new Date(investigationCase.timestamp || Date.now()).toUTCString();
  } catch {
    dateDisplay = safeStr(investigationCase.timestamp || 'Timestamp Recorded');
  }

  const handleQuarantine = () => {
    addResponseAction({
      caseId: caseId,
      actionType: 'QUARANTINE',
      target: recipient,
      status: 'EXECUTED',
      executedBy: 'SOC Analyst Manual Action',
      reason: `Manual quarantine applied to ${caseId} due to ${primaryThreat}`,
      impactScore: 85
    });
    updateCaseStatus(caseId, 'CONTAINED');
  };

  const handleBlockDomain = () => {
    const domain = sender.includes('@') ? sender.split('@')[1] : 'sender-domain';
    addResponseAction({
      caseId: caseId,
      actionType: 'BLOCK_DOMAIN',
      target: domain,
      status: 'EXECUTED',
      executedBy: 'SOC Analyst Manual Action',
      reason: `Domain ${domain} blocked across all perimeter security gateways`,
      impactScore: 95
    });
  };

  const handleCopyId = () => {
    navigator.clipboard.writeText(caseId);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              onClick={handleCopyId}
              className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/60 text-cyan-300 font-mono text-xs font-bold hover:bg-cyan-900/80 transition-colors"
            >
              <span>{caseId}</span>
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>

            <Badge variant="severity" severity={severity as any}>
              {severity}
            </Badge>

            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
              Status: <span className="text-amber-400 font-bold">{status}</span>
            </span>

            <div className="flex items-center gap-1 text-xs font-mono text-slate-400">
              <Clock className="w-3.5 h-3.5" />
              <span>{dateDisplay}</span>
            </div>
          </div>

          <h2 className="text-lg font-bold text-slate-100 mt-2 font-sans">
            {subject}
          </h2>

          <div className="flex flex-wrap items-center gap-4 mt-1.5 text-xs font-mono text-slate-400">
            <div>
              From: <span className="text-slate-200 font-semibold">{sender}</span>
            </div>
            <span>•</span>
            <div>
              To: <span className="text-slate-200">{recipient}</span>
            </div>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2 self-start lg:self-center">
          <button
            onClick={handleQuarantine}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600/20 border border-red-500/40 text-red-300 hover:bg-red-600/30 text-xs font-mono font-bold transition-all shadow-glow-critical"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Quarantine Message</span>
          </button>

          <button
            onClick={handleBlockDomain}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-orange-600/20 border border-orange-500/40 text-orange-300 hover:bg-orange-600/30 text-xs font-mono font-medium transition-colors"
          >
            <Ban className="w-3.5 h-3.5" />
            <span>Block Domain</span>
          </button>

          <button
            onClick={onOpenEvidence}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-200 hover:border-cyan-500/40 text-xs font-mono transition-colors"
          >
            <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
            <span>Evidence Chain</span>
          </button>

          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500/20 border border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/30 text-xs font-mono font-bold transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Forensic Report</span>
          </button>
        </div>
      </div>
    </div>
  );
};
