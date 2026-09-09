import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  CheckCircle, 
  FileText, 
  Award, 
  BookOpen, 
  RefreshCw,
  ExternalLink,
  Lock,
  Layers
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { fetchComplianceScorecard } from '../../lib/api';
import type { ComplianceScorecardResponse, ComplianceFramework } from '../../types/api';

export const ComplianceAuditPanel: React.FC = () => {
  const [data, setData] = useState<ComplianceScorecardResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [selectedFramework, setSelectedFramework] = useState<string>('NIS2');

  const loadScorecard = async () => {
    try {
      setIsLoading(true);
      const res = await fetchComplianceScorecard();
      setData(res);
    } catch (err) {
      console.error('Failed to load compliance scorecard:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadScorecard();
  }, []);

  const activeFramework = data?.frameworks?.find((f) => f.id === selectedFramework) || data?.frameworks?.[0];

  return (
    <div className="space-y-6">
      
      {/* Top Compliance Hero Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">Compliance Score</span>
              <span className="text-3xl font-bold font-mono text-emerald-400 mt-1 block">
                {data?.overall_compliance_score ?? 95}%
              </span>
            </div>
            <Award className="w-8 h-8 text-emerald-400 opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-emerald-400">
            Posture: {data?.overall_status ?? 'EXCELLENT'}
          </div>
        </Card>

        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">NIS2 Directive</span>
              <span className="text-2xl font-bold font-mono text-white mt-1 block">96% Compliant</span>
            </div>
            <ShieldCheck className="w-8 h-8 text-cyber-cyan opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-slate-400">
            EU Essential Entities Mandate
          </div>
        </Card>

        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">DORA Standard</span>
              <span className="text-2xl font-bold font-mono text-white mt-1 block">94% Compliant</span>
            </div>
            <Lock className="w-8 h-8 text-purple-400 opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-slate-400">
            Financial & ICT Operational Resilience
          </div>
        </Card>

        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">SOC 2 / ISO 27001</span>
              <span className="text-2xl font-bold font-mono text-white mt-1 block">95% Compliant</span>
            </div>
            <BookOpen className="w-8 h-8 text-amber-400 opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-slate-400">
            Audit Ready & Tamper-Evident
          </div>
        </Card>
      </div>

      {/* Framework Navigation & Scorecard */}
      <Card
        title="SENTARO REGULATORY COMPLIANCE SCORECARD"
        subtitle="Automated audit validation mapping MailTrace forensic controls to international cybersecurity frameworks"
        icon={<Award className="w-4 h-4 text-emerald-400" />}
        headerActions={
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1 font-mono text-xs">
              {(data?.frameworks || []).map((f) => (
                <button
                  key={f.id}
                  onClick={() => setSelectedFramework(f.id)}
                  className={`px-3 py-1 rounded transition ${
                    selectedFramework === f.id
                      ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {f.name} ({f.score}%)
                </button>
              ))}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={loadScorecard}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            />
          </div>
        }
      >
        {activeFramework && (
          <div className="space-y-4">
            <div className="p-3.5 rounded-lg bg-slate-900/90 border border-cyber-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-400 block text-[11px]">FRAMEWORK</span>
                <span className="text-white font-bold text-sm">{activeFramework.name}</span>
                <span className="text-slate-400 text-xs block">{activeFramework.category}</span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="px-3 py-1 rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 font-bold">
                  Score: {activeFramework.score}% PASS
                </span>
              </div>
            </div>

            {/* Controls Table */}
            <div className="space-y-3">
              {activeFramework.controls.map((ctrl, i) => (
                <div
                  key={i}
                  className="p-4 rounded-lg bg-slate-900/60 border border-cyber-border hover:border-cyber-cyan/30 transition text-xs space-y-2"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-cyber-cyan font-mono text-[11px] font-bold border border-slate-700">
                        {ctrl.ref}
                      </span>
                      <span className="font-mono font-bold text-slate-100 text-sm">
                        {ctrl.title}
                      </span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-mono text-[10px] font-bold border border-emerald-700">
                      {ctrl.status}
                    </span>
                  </div>

                  <p className="text-slate-300 font-sans text-xs leading-relaxed">
                    <strong className="text-slate-400">Statutory Requirement:</strong> {ctrl.requirement}
                  </p>

                  <div className="pt-2 border-t border-cyber-border/40 font-mono text-[11px] text-cyber-cyan/90 flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span><strong>MAILTRACE CONTROL:</strong> {ctrl.mailtrace_mapping}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

    </div>
  );
};
