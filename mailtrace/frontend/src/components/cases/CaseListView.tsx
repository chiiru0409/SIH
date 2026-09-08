import React, { useState, useMemo } from 'react';
import { 
  FolderLock, 
  Search, 
  Filter, 
  ArrowUpDown, 
  Calendar, 
  FileText, 
  ShieldAlert, 
  ArrowRight,
  RefreshCw
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { formatDate } from '../../lib/utils';
import type { CaseSummary } from '../../types/api';

export interface CaseListViewProps {
  cases: CaseSummary[];
  isLoading?: boolean;
  onRefresh?: () => void;
  onSelectCase: (caseId: string) => void;
  className?: string;
}

export const CaseListView: React.FC<CaseListViewProps> = ({
  cases = [],
  isLoading = false,
  onRefresh,
  onSelectCase,
  className,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'NEWEST' | 'OLDEST' | 'RISK_DESC' | 'RISK_ASC'>('NEWEST');

  const filteredCases = useMemo(() => {
    return cases
      .filter((c) => {
        const matchesQuery = 
          !searchQuery ||
          c.case_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
          c.original_filename.toLowerCase().includes(searchQuery.toLowerCase());
        
        const matchesSeverity =
          severityFilter === 'ALL' ||
          (c.risk_label || 'LOW').toUpperCase() === severityFilter;

        return matchesQuery && matchesSeverity;
      })
      .sort((a, b) => {
        if (sortOrder === 'NEWEST') {
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        }
        if (sortOrder === 'OLDEST') {
          return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
        }
        if (sortOrder === 'RISK_DESC') {
          return (b.risk_score || 0) - (a.risk_score || 0);
        }
        if (sortOrder === 'RISK_ASC') {
          return (a.risk_score || 0) - (b.risk_score || 0);
        }
        return 0;
      });
  }, [cases, searchQuery, severityFilter, sortOrder]);

  return (
    <Card
      title="INVESTIGATION CASE REPOSITORY"
      subtitle={`Forensic database registry (${cases.length} total cases stored)`}
      icon={<FolderLock className="w-4 h-4 text-cyber-cyan" />}
      headerActions={
        onRefresh ? (
          <button
            onClick={onRefresh}
            className="flex items-center space-x-1 text-slate-400 hover:text-cyber-cyan font-mono text-xs transition"
            title="Refresh cases from API"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>REFRESH</span>
          </button>
        ) : null
      }
      className={className}
    >
      <div className="space-y-4">
        
        {/* Filters Toolbar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-cyber-surface rounded-lg border border-cyber-border">
          
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by case ID or filename…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-cyber-bg border border-cyber-border rounded text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan"
            />
          </div>

          {/* Severity & Sort Selects */}
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1 font-mono text-xs text-slate-400">
              <span className="text-[11px] text-slate-500">SEVERITY:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyber-cyan"
              >
                <option value="ALL">ALL SEVERITIES</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            <div className="flex items-center space-x-1 font-mono text-xs text-slate-400">
              <span className="text-[11px] text-slate-500">SORT:</span>
              <select
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value as any)}
                className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyber-cyan"
              >
                <option value="NEWEST">Newest First</option>
                <option value="OLDEST">Oldest First</option>
                <option value="RISK_DESC">Highest Risk</option>
                <option value="RISK_ASC">Lowest Risk</option>
              </select>
            </div>
          </div>

        </div>

        {/* Case Table / List */}
        {filteredCases.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-slate-500 space-y-2">
            <FileText className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="font-bold text-slate-300">NO CASES FOUND</div>
            <p className="text-[11px] text-slate-500">
              {searchQuery || severityFilter !== 'ALL'
                ? 'Try adjusting your search criteria or filter options.'
                : 'Upload an .eml email file to record the first investigation case.'}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredCases.map((c) => {
              const score = Math.round(c.risk_score ?? 0);
              const severity = (c.risk_label || 'LOW').toUpperCase();

              return (
                <div
                  key={c.case_id}
                  onClick={() => onSelectCase(c.case_id)}
                  className="p-4 rounded-lg bg-cyber-surface/80 border border-cyber-border hover:border-cyber-cyan/50 hover:bg-cyber-card transition-all cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 group"
                >
                  <div className="flex items-start space-x-3 overflow-hidden">
                    <div className="w-9 h-9 rounded bg-cyber-bg border border-cyber-border flex items-center justify-center text-cyber-cyan group-hover:border-cyber-cyan/40 transition shrink-0">
                      <FileText className="w-4 h-4" />
                    </div>

                    <div className="overflow-hidden space-y-1">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="font-mono text-xs font-bold text-slate-100 group-hover:text-cyber-cyan transition">
                          {c.original_filename}
                        </span>
                        <Badge variant="severity" severity={severity} size="sm" />
                      </div>

                      <div className="flex items-center space-x-3 text-[11px] font-mono text-slate-400">
                        <span>ID: <strong className="text-slate-300">{c.case_id.slice(0, 8)}…</strong></span>
                        <span>•</span>
                        <span>{formatDate(c.created_at)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end w-full sm:w-auto space-x-4 shrink-0 pl-12 sm:pl-0">
                    <div className="text-right font-mono">
                      <div className="text-sm font-bold text-slate-100">
                        {score} <span className="text-[10px] text-slate-500">/ 100</span>
                      </div>
                      <div className="text-[9px] text-slate-500 uppercase">
                        RISK SCORE
                      </div>
                    </div>

                    <Button
                      variant="outline"
                      size="sm"
                      icon={<ArrowRight className="w-3.5 h-3.5" />}
                    >
                      Inspect
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

      </div>
    </Card>
  );
};
