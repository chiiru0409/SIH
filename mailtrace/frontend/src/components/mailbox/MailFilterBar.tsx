import React from 'react';
import { Filter, AlertOctagon, CheckCircle2, ShieldAlert } from 'lucide-react';
import { ThreatSeverity } from '../../types/email';

interface MailFilterBarProps {
  selectedSeverity: string;
  onSelectSeverity: (sev: string) => void;
  selectedCategory: string;
  onSelectCategory: (cat: string) => void;
  totalCount: number;
}

export const MailFilterBar: React.FC<MailFilterBarProps> = ({
  selectedSeverity,
  onSelectSeverity,
  selectedCategory,
  onSelectCategory,
  totalCount
}) => {
  const severities = [
    { id: 'ALL', label: 'All Severities' },
    { id: 'CRITICAL', label: 'Critical' },
    { id: 'HIGH', label: 'High' },
    { id: 'MEDIUM', label: 'Medium' },
    { id: 'BENIGN', label: 'Benign' }
  ];

  const categories = [
    { id: 'ALL', label: 'All Threat Types' },
    { id: 'CREDENTIAL_HARVESTING', label: 'Phishing' },
    { id: 'BEC_WIRE_FRAUD', label: 'BEC Fraud' },
    { id: 'MALWARE_DROPPER', label: 'Malware' },
    { id: 'QUISHING_QR', label: 'Quishing' },
    { id: 'BENIGN_NOTIFICATION', label: 'Benign Clean' }
  ];

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-cyber-panel border border-slate-800 rounded-lg">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 mr-2">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Filter:</span>
        </div>

        {severities.map(sev => (
          <button
            key={sev.id}
            onClick={() => onSelectSeverity(sev.id)}
            className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
              selectedSeverity === sev.id
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {sev.label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <select
          value={selectedCategory}
          onChange={e => onSelectCategory(e.target.value)}
          className="bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300 px-2.5 py-1 rounded outline-none focus:border-cyan-500"
        >
          {categories.map(cat => (
            <option key={cat.id} value={cat.id}>
              {cat.label}
            </option>
          ))}
        </select>
        <span className="text-xs font-mono text-slate-400">
          Showing <span className="text-cyan-400 font-bold">{totalCount}</span> cases
        </span>
      </div>
    </div>
  );
};
