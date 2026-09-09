import React, { useState } from 'react';
import { ShieldAlert, ArrowRight, Eye, Paperclip, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react';
import { EmailMetadata } from '../../types/email';
import { InvestigationCase } from '../../types/investigation';
import { Badge } from '../common/Badge';
import { RiskGauge } from '../common/RiskGauge';

interface MailboxTableProps {
  emails: EmailMetadata[];
  cases: InvestigationCase[];
  onSelectEmail: (email: EmailMetadata) => void;
  onInvestigate: (caseId: string) => void;
}

export const MailboxTable: React.FC<MailboxTableProps> = ({
  emails,
  cases,
  onSelectEmail,
  onInvestigate
}) => {
  return (
    <div className="bg-cyber-panel border border-slate-800 rounded-lg overflow-hidden">
      <div className="overflow-x-auto cyber-scrollbar">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-cyber-slate/40 border-b border-slate-800 text-[11px] font-mono font-semibold text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Risk & Severity</th>
              <th className="py-3 px-4">Sender & Target</th>
              <th className="py-3 px-4">Subject & Threat Indicators</th>
              <th className="py-3 px-4">Auth Status</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-xs font-mono">
            {emails.map(email => {
              const matchedCase = cases.find(c => c.id === email.caseId || c.emailId === email.id);
              const severity = matchedCase?.verdict.severity || 'LOW';
              const riskScore = matchedCase?.verdict.overallRiskScore || 10;

              return (
                <tr
                  key={email.id}
                  className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                  onClick={() => onSelectEmail(email)}
                >
                  {/* Risk Score Gauge & Badge */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-2.5">
                      <RiskGauge score={riskScore} size="sm" />
                      <div>
                        <Badge variant="severity" severity={severity} size="xs">
                          {severity}
                        </Badge>
                        <div className="text-[10px] text-slate-400 mt-0.5">{email.id}</div>
                      </div>
                    </div>
                  </td>

                  {/* Sender & Recipient */}
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-slate-200 truncate max-w-[200px]">
                      {email.headers.from}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate max-w-[200px] mt-0.5">
                      To: {email.headers.to}
                    </div>
                  </td>

                  {/* Subject & IOC summary */}
                  <td className="py-3.5 px-4">
                    <div className="font-medium text-slate-200 truncate max-w-sm">
                      {email.subject}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      {email.extractedUrls.length > 0 && (
                        <span className="inline-flex items-center gap-1 text-[10px] text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/50">
                          <ExternalLink className="w-2.5 h-2.5" />
                          <span>{email.extractedUrls.length} URL</span>
                        </span>
                      )}
                      {email.attachments.length > 0 && (
                        <span className="inline-flex items-center gap-1 text-[10px] text-amber-400 bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-800/50">
                          <Paperclip className="w-2.5 h-2.5" />
                          <span>{email.attachments.length} Attach</span>
                        </span>
                      )}
                      {matchedCase && (
                        <span className="text-[10px] text-slate-400 truncate max-w-[180px]">
                          {matchedCase.verdict.primaryThreat}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Auth Status */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      <span
                        className={`text-[10px] px-1 py-0.5 rounded font-mono ${
                          email.authenticationResults.spf.status === 'PASS'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        SPF:{email.authenticationResults.spf.status}
                      </span>
                      <span
                        className={`text-[10px] px-1 py-0.5 rounded font-mono ${
                          email.authenticationResults.dmarc.status === 'PASS'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        DMARC:{email.authenticationResults.dmarc.status}
                      </span>
                    </div>
                  </td>

                  {/* Timestamp */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-xs">
                    {new Date(email.headers.date).toLocaleDateString([], {
                      month: 'short',
                      day: 'numeric'
                    })}{' '}
                    {new Date(email.headers.date).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-2" onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectEmail(email)}
                        className="p-1.5 rounded bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition-colors"
                        title="Preview Email"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      {matchedCase && (
                        <button
                          onClick={() => onInvestigate(matchedCase.id)}
                          className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 font-bold transition-all text-xs"
                        >
                          <span>Investigate</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
