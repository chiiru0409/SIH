import React, { useState, useEffect } from 'react';
import { 
  Cloud, 
  Activity, 
  ShieldCheck, 
  ShieldAlert, 
  RefreshCw, 
  CheckCircle, 
  Radio,
  Server,
  Zap,
  Mail,
  ArrowUpRight,
  Filter,
  Layers
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { formatDate } from '../../lib/utils';
import { fetchTenants, fetchTenantStream } from '../../lib/api';
import type { CloudTenantItem, LiveTenantStreamEvent } from '../../types/api';

export const TenantLiveMonitor: React.FC = () => {
  const [tenants, setTenants] = useState<CloudTenantItem[]>([]);
  const [events, setEvents] = useState<LiveTenantStreamEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  const loadData = async () => {
    try {
      setIsLoading(true);
      const [tenantsRes, streamRes] = await Promise.all([
        fetchTenants().catch(() => ({ tenants: [] })),
        fetchTenantStream().catch(() => ({ events: [] })),
      ]);
      setTenants(tenantsRes.tenants || []);
      setEvents(streamRes.events || []);
    } catch (err) {
      console.error('Failed to load tenant stream:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateAttack = () => {
    const newEvent: LiveTenantStreamEvent = {
      event_id: `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      tenant_id: 'tenant-m365-corp',
      tenant_name: 'Microsoft 365 Corp',
      sender: 'cfo-wire-auth@lookalike-holding.net',
      display_name: 'Satya Nadella (Executive)',
      recipient: 'treasury@enterprise-defense.org',
      subject: 'URGENT: Approved Settlement Wire Instruction for M&A Closing',
      risk_score: 95,
      severity: 'CRITICAL',
      intent: 'Executive BEC / Wire Fraud',
      policy_action: 'QUARANTINED',
    };
    setEvents((prev) => [newEvent, ...prev]);
  };

  const filteredEvents = events.filter((evt) => {
    if (filterSeverity === 'ALL') return true;
    return evt.severity === filterSeverity;
  });

  const totalMailboxes = tenants.reduce((acc, t) => acc + (t.mailboxes_monitored || 0), 0);
  const totalInterceptedToday = tenants.reduce((acc, t) => acc + (t.threats_intercepted_today || 0), 0);

  return (
    <div className="space-y-6">
      
      {/* Top Banner & Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">Connected Cloud Tenants</span>
              <span className="text-2xl font-bold font-mono text-white mt-1 block">{tenants.length} Active</span>
            </div>
            <Cloud className="w-8 h-8 text-cyber-cyan opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-emerald-400 flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>M365 & G-Suite Webhooks Live</span>
          </div>
        </Card>

        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">Mailboxes Monitored</span>
              <span className="text-2xl font-bold font-mono text-white mt-1 block">{totalMailboxes.toLocaleString()}</span>
            </div>
            <Mail className="w-8 h-8 text-purple-400 opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-slate-400">
            Across 3 Corporate Ingestion Domains
          </div>
        </Card>

        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">Threats Intercepted (24h)</span>
              <span className="text-2xl font-bold font-mono text-red-400 mt-1 block">{totalInterceptedToday + (events.length > 4 ? events.length - 4 : 0)} Attacks</span>
            </div>
            <ShieldAlert className="w-8 h-8 text-red-400 opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-red-400">
            Auto-Quarantined by Policy Engine
          </div>
        </Card>

        <Card className="border-cyber-borderLight">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase block">Stream Health</span>
              <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">100% OK</span>
            </div>
            <Activity className="w-8 h-8 text-emerald-400 opacity-80" />
          </div>
          <div className="mt-2 text-[11px] font-mono text-slate-400">
            Zero Ingestion Latency (&lt; 150ms)
          </div>
        </Card>
      </div>

      {/* Connected Cloud Tenants Grid */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyber-cyan" />
            <h2 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wide">
              SENTARO / GREATHORN CLOUD TENANT INTEGRATION
            </h2>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={loadData}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            className="font-mono text-xs"
          >
            Sync Tenants
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {tenants.map((tenant) => (
            <Card key={tenant.id} className="border-cyber-border/70 bg-slate-900/60">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-mono font-bold text-sm text-white flex items-center gap-1.5">
                    <span>{tenant.name}</span>
                  </div>
                  <span className="text-xs font-mono text-slate-400">{tenant.domain}</span>
                </div>
                <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 font-mono text-[10px] font-bold flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" />
                  {tenant.status}
                </span>
              </div>

              <div className="mt-4 pt-3 border-t border-cyber-border/40 grid grid-cols-2 gap-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">SYNC METHOD</span>
                  <span className="text-cyber-cyan truncate block">{tenant.sync_mode}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">MAILBOXES</span>
                  <span className="text-slate-200">{tenant.mailboxes_monitored.toLocaleString()}</span>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* Live Threat Activity Stream */}
      <Card
        title="REAL-TIME TENANT THREAT ACTIVITY STREAM"
        subtitle="Live event telemetry intercepted via Microsoft Graph API and Google Workspace PubSub"
        icon={<Activity className="w-4 h-4 text-cyber-cyan" />}
        headerActions={
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1 font-mono text-xs">
              {(['ALL', 'CRITICAL', 'HIGH', 'LOW'] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setFilterSeverity(s)}
                  className={`px-2 py-0.5 rounded transition ${
                    filterSeverity === s
                      ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
            <Button
              variant="primary"
              size="sm"
              icon={<Zap className="w-3.5 h-3.5 text-amber-300" />}
              onClick={handleSimulateAttack}
              className="font-mono text-xs"
            >
              Simulate Attack
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          {filteredEvents.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-slate-500">
              NO STREAM EVENTS MATCHING FILTER
            </div>
          ) : (
            filteredEvents.map((evt) => (
              <div
                key={evt.event_id}
                className="p-3.5 rounded-lg bg-slate-900/80 border border-cyber-border hover:border-cyber-cyan/40 transition flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center space-x-2 flex-wrap">
                    <span className="font-mono text-slate-500 text-[11px]">{evt.event_id}</span>
                    <span className="text-slate-600">•</span>
                    <span className="font-mono text-purple-300 text-[11px] font-bold">{evt.tenant_name}</span>
                    <span className="text-slate-600">•</span>
                    <Badge variant="severity" severity={evt.severity} size="sm" />
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] border border-slate-700">
                      {evt.intent}
                    </span>
                  </div>

                  <div className="font-mono text-slate-200 font-bold truncate">
                    {evt.subject}
                  </div>

                  <div className="flex items-center space-x-2 font-mono text-[11px] text-slate-400 truncate">
                    <span>FROM: <strong className="text-slate-300">{evt.display_name ? `"${evt.display_name}" ` : ''}&lt;{evt.sender}&gt;</strong></span>
                    <span>→</span>
                    <span>TO: <strong className="text-slate-300">{evt.recipient}</strong></span>
                  </div>
                </div>

                <div className="flex items-center space-x-3 shrink-0 self-end md:self-center font-mono">
                  <div className="text-right">
                    <div className="text-xs font-bold text-slate-200">
                      Score: <span className={evt.risk_score >= 80 ? 'text-red-400 font-extrabold' : 'text-emerald-400'}>{evt.risk_score}/100</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">
                      ACTION: <strong className={evt.policy_action === 'QUARANTINED' ? 'text-red-400' : 'text-cyber-cyan'}>{evt.policy_action}</strong>
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </Card>

    </div>
  );
};
