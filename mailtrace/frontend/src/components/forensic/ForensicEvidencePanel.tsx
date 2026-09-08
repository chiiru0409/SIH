import React, { useState } from 'react';
import { 
  FileSearch, 
  CheckCircle, 
  HelpCircle, 
  Filter, 
  ShieldCheck, 
  FileText, 
  AlertCircle 
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Tabs } from '../ui/Tabs';
import type { ForensicAnalysisResult, ForensicFinding } from '../../types/api';

export interface ForensicEvidencePanelProps {
  forensics?: ForensicAnalysisResult | null;
  className?: string;
}

export const ForensicEvidencePanel: React.FC<ForensicEvidencePanelProps> = ({
  forensics,
  className,
}) => {
  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const [filterType, setFilterType] = useState<'ALL' | 'FACT' | 'INFERENCE'>('ALL');

  const findings = Array.isArray(forensics?.findings) ? forensics.findings : [];

  if (findings.length === 0) {
    return (
      <Card title="FORENSIC EVIDENCE & FINDINGS" className={className}>
        <div className="py-8 text-center text-xs font-mono text-slate-500">
          NO FORENSIC ANOMALIES IDENTIFIED
        </div>
      </Card>
    );
  }

  const factsCount = forensics?.summary?.facts_count ?? findings.filter(f => f?.type === 'FACT').length;
  const inferencesCount = forensics?.summary?.inferences_count ?? findings.filter(f => f?.type === 'INFERENCE').length;

  // Extract unique valid categories
  const categories = ['ALL', ...Array.from(new Set(findings.map(f => f?.category).filter(Boolean)))];

  const filteredFindings = findings.filter(f => {
    if (!f) return false;
    const matchesCategory = activeCategory === 'ALL' || f.category === activeCategory;
    const matchesType = filterType === 'ALL' || f.type === filterType;
    return matchesCategory && matchesType;
  });

  return (
    <Card
      title="FORENSIC EVIDENCE FINDINGS"
      subtitle="Empirical observations (FACTS) vs. heuristic deductions (INFERENCES)"
      icon={<FileSearch className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-4">
        
        {/* Facts vs Inferences Summary Bar */}
        <div className="p-3 bg-cyber-surface rounded-lg border border-cyber-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-1.5">
              <Badge variant="fact" size="sm" />
              <span className="font-mono text-slate-200 font-bold">{factsCount} Facts</span>
            </div>
            <span className="text-slate-600">|</span>
            <div className="flex items-center space-x-1.5">
              <Badge variant="inference" size="sm" />
              <span className="font-mono text-purple-300 font-bold">{inferencesCount} Inferences</span>
            </div>
          </div>

          {/* Filter Type Toggle */}
          <div className="flex items-center space-x-1 font-mono text-[11px]">
            <span className="text-slate-500 mr-1.5">SHOW:</span>
            {(['ALL', 'FACT', 'INFERENCE'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2 py-0.5 rounded transition ${
                  filterType === t
                    ? 'bg-cyber-border text-cyber-cyan font-bold border border-cyber-cyan/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        {/* Category Pills */}
        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`px-3 py-1 rounded-md text-[11px] font-mono whitespace-nowrap transition uppercase ${
                activeCategory === cat
                  ? 'bg-cyber-card text-cyber-cyan border border-cyber-cyan/40 font-bold shadow-[0_0_8px_rgba(0,240,255,0.2)]'
                  : 'bg-slate-900/40 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Findings List */}
        <div className="space-y-3">
          {filteredFindings.length === 0 ? (
            <div className="py-6 text-center text-xs font-mono text-slate-500">
              No findings matching the selected filters.
            </div>
          ) : (
            filteredFindings.map((finding, idx) => {
              const isFact = finding.type === 'FACT';

              return (
                <div
                  key={`${finding.title || 'finding'}-${idx}`}
                  className={`p-4 rounded-lg border transition-all ${
                    isFact
                      ? 'bg-cyber-surface/70 border-emerald-500/20 hover:border-emerald-500/40'
                      : 'bg-purple-950/10 border-purple-500/20 hover:border-purple-500/40'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-cyber-border/40">
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                      <span className="font-mono text-xs font-bold text-slate-100">
                        {finding.title || 'Unspecified Observation'}
                      </span>
                      {isFact ? (
                        <Badge variant="fact" size="sm" />
                      ) : (
                        <Badge variant="inference" size="sm" />
                      )}
                      <Badge variant="severity" severity={finding.severity || 'LOW'} size="sm" />
                    </div>

                    <div className="flex items-center space-x-2 text-[10px] font-mono text-slate-400">
                      <span className="bg-slate-800 px-2 py-0.5 rounded border border-slate-700 uppercase">
                        {finding.category || 'GENERAL'}
                      </span>
                      {typeof finding.confidence === 'number' && (
                        <span className="text-cyan-400">
                          {Math.round(finding.confidence * 100)}% CONF
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 leading-relaxed font-sans">
                    {finding.description || '(No description provided)'}
                  </p>

                  {finding.evidence && (
                    <div className="mt-2.5 p-2 rounded bg-cyber-bg/80 border border-cyber-border text-xs font-mono text-cyan-300 break-all">
                      <span className="text-slate-500 text-[10px] block uppercase">Extracted Evidence:</span>
                      {finding.evidence}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

      </div>
    </Card>
  );
};
