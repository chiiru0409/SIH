import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Lock, 
  Trash2, 
  CheckCircle, 
  Ban, 
  Plus, 
  RefreshCw, 
  Sliders, 
  ListFilter, 
  AlertOctagon,
  FileCheck
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { 
  fetchQuarantineVault, 
  remediateQuarantine, 
  fetchPolicyRules, 
  fetchBlocklist, 
  addToBlocklist 
} from '../../lib/api';
import type { QuarantinedItem, PolicyRuleItem, BlocklistEntry } from '../../types/api';

export const QuarantinePolicyHub: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'quarantine' | 'policies' | 'blocklist'>('quarantine');
  const [quarantinedItems, setQuarantinedItems] = useState<QuarantinedItem[]>([]);
  const [policies, setPolicies] = useState<PolicyRuleItem[]>([]);
  const [blocklist, setBlocklist] = useState<BlocklistEntry[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // New Blocklist Modal/Form state
  const [newBlockType, setNewBlockType] = useState<string>('DOMAIN');
  const [newBlockValue, setNewBlockValue] = useState<string>('');
  const [newBlockReason, setNewBlockReason] = useState<string>('');

  const loadData = async () => {
    try {
      setIsLoading(true);
      const [qRes, pRes, bRes] = await Promise.all([
        fetchQuarantineVault().catch(() => ({ quarantined_items: [] })),
        fetchPolicyRules().catch(() => ({ policies: [] })),
        fetchBlocklist().catch(() => ({ blocklist: [] })),
      ]);
      setQuarantinedItems(qRes.quarantined_items || []);
      setPolicies(pRes.policies || []);
      setBlocklist(bRes.blocklist || []);
    } catch (err) {
      console.error('Failed to load policy data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRemediate = async (caseId: string, action: string) => {
    try {
      await remediateQuarantine(caseId, action, `Action ${action} executed by SOC analyst`);
      setActionSuccess(`Case ${caseId.slice(0, 8)} successfully updated with action: ${action}`);
      setTimeout(() => setActionSuccess(null), 4000);
      await loadData();
    } catch (err: any) {
      alert(`Remediation failed: ${err.message}`);
    }
  };

  const handleAddBlocklist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBlockValue.trim()) return;
    try {
      await addToBlocklist(newBlockType, newBlockValue.trim(), newBlockReason.trim() || 'Manual SOC Policy Block');
      setNewBlockValue('');
      setNewBlockReason('');
      setActionSuccess(`Added ${newBlockValue} to blocklist.`);
      setTimeout(() => setActionSuccess(null), 4000);
      await loadData();
    } catch (err: any) {
      alert(`Failed to add blocklist entry: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Header Card */}
      <Card className="border-cyber-borderLight">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Lock className="w-5 h-5 text-cyber-cyan" />
              <h1 className="text-lg sm:text-xl font-mono font-bold text-white">
                MIMECAST-GRADE SOC POLICY & QUARANTINE VAULT
              </h1>
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1">
              Targeted Threat Protection: Automated Quarantine, Link Defanging & Domain Blocklists
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1 p-1 rounded-lg bg-cyber-bg border border-cyber-border font-mono text-xs">
              <button
                onClick={() => setActiveSubTab('quarantine')}
                className={`px-3 py-1.5 rounded transition ${
                  activeSubTab === 'quarantine'
                    ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Quarantine Vault ({quarantinedItems.filter(i => i.status === 'QUARANTINED').length})
              </button>
              <button
                onClick={() => setActiveSubTab('policies')}
                className={`px-3 py-1.5 rounded transition ${
                  activeSubTab === 'policies'
                    ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Policy Rules ({policies.length})
              </button>
              <button
                onClick={() => setActiveSubTab('blocklist')}
                className={`px-3 py-1.5 rounded transition ${
                  activeSubTab === 'blocklist'
                    ? 'bg-cyber-card text-cyber-cyan font-bold border border-cyber-cyan/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Enterprise Blocklist ({blocklist.length})
              </button>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={loadData}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            />
          </div>
        </div>
      </Card>

      {/* Action Success Toast */}
      {actionSuccess && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-500/50 rounded-lg text-xs font-mono text-emerald-300 flex items-center space-x-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* SUB-TAB 1: QUARANTINE VAULT */}
      {activeSubTab === 'quarantine' && (
        <Card
          title="ACTIVE QUARANTINE VAULT"
          subtitle="Threats automatically isolated prior to delivery to prevent recipient exposure"
          icon={<ShieldAlert className="w-4 h-4 text-red-400" />}
        >
          {quarantinedItems.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-slate-500">
              NO EMAILS CURRENTLY IN QUARANTINE VAULT
            </div>
          ) : (
            <div className="space-y-3">
              {quarantinedItems.map((item) => (
                <div
                  key={item.case_id}
                  className="p-4 rounded-lg bg-slate-900/90 border border-cyber-border hover:border-cyber-cyan/40 transition flex flex-col lg:flex-row lg:items-center justify-between gap-4 text-xs font-mono"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center space-x-2 flex-wrap">
                      <span className="text-slate-400 text-[11px]">CASE: {item.case_id.slice(0, 8)}…</span>
                      <span className="text-slate-600">•</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.status === 'QUARANTINED' ? 'bg-red-950 text-red-400 border border-red-700' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {item.status}
                      </span>
                      <span className="text-slate-600">•</span>
                      <span className="text-red-400 font-bold">Risk: {item.risk_score}/100</span>
                    </div>

                    <div className="text-white font-bold truncate text-sm">
                      {item.subject}
                    </div>

                    <div className="text-slate-400 text-[11px] truncate">
                      <span>FROM: <strong className="text-slate-200">{item.sender_display ? `"${item.sender_display}" ` : ''}&lt;{item.sender_email || item.sender_domain || 'unknown'}&gt;</strong></span>
                    </div>

                    <div className="text-amber-300 text-[11px]">
                      TRIGGER: {item.reason}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-2 shrink-0 self-end lg:self-center">
                    {item.status === 'QUARANTINED' ? (
                      <>
                        <Button
                          variant="secondary"
                          size="sm"
                          icon={<CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
                          onClick={() => handleRemediate(item.case_id, 'RELEASE')}
                          className="text-[11px]"
                        >
                          Release
                        </Button>
                        <Button
                          variant="secondary"
                          size="sm"
                          icon={<Ban className="w-3.5 h-3.5 text-amber-400" />}
                          onClick={() => handleRemediate(item.case_id, 'BLOCK_SENDER')}
                          className="text-[11px]"
                        >
                          Block Sender
                        </Button>
                        <Button
                          variant="danger"
                          size="sm"
                          icon={<Trash2 className="w-3.5 h-3.5" />}
                          onClick={() => handleRemediate(item.case_id, 'PURGE')}
                          className="text-[11px]"
                        >
                          Purge
                        </Button>
                      </>
                    ) : (
                      <span className="text-slate-500 text-[11px]">
                        Remediated: {item.status}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* SUB-TAB 2: POLICY RULES */}
      {activeSubTab === 'policies' && (
        <Card
          title="AUTOMATED SOC POLICY RULES"
          subtitle="Real-time enforcement triggers executed across incoming email traffic"
          icon={<Sliders className="w-4 h-4 text-cyber-cyan" />}
        >
          <div className="space-y-3">
            {policies.map((pol) => (
              <div
                key={pol.id}
                className="p-4 rounded-lg bg-slate-900/80 border border-cyber-border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-cyber-cyan font-bold">{pol.id}</span>
                    <span className="text-white font-bold">{pol.name}</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-bold border border-emerald-700">
                      ACTIVE
                    </span>
                  </div>
                  <p className="text-slate-300 font-sans text-xs">
                    {pol.description}
                  </p>
                  <div className="text-[11px] text-slate-400">
                    CONDITION: <code className="text-cyber-cyan bg-slate-950 px-1.5 py-0.5 rounded">{pol.condition}</code>
                  </div>
                </div>

                <div className="shrink-0 text-right">
                  <span className="text-[10px] text-slate-500 block mb-1">ENFORCED ACTION</span>
                  <span className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-amber-300 font-bold text-xs">
                    {pol.action}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* SUB-TAB 3: ENTERPRISE BLOCKLIST */}
      {activeSubTab === 'blocklist' && (
        <div className="space-y-6">
          {/* Add Block Form */}
          <Card title="ADD NEW BLOCKLIST ENTRY" icon={<Plus className="w-4 h-4 text-cyber-cyan" />}>
            <form onSubmit={handleAddBlocklist} className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">TYPE</label>
                <select
                  value={newBlockType}
                  onChange={(e) => setNewBlockType(e.target.value)}
                  className="w-full bg-slate-950 border border-cyber-border rounded px-3 py-2 text-slate-200 focus:border-cyber-cyan outline-none"
                >
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="SENDER">SENDER EMAIL</option>
                  <option value="IP">IP ADDRESS</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">TARGET VALUE</label>
                <input
                  type="text"
                  placeholder="e.g. evil-phish.com"
                  value={newBlockValue}
                  onChange={(e) => setNewBlockValue(e.target.value)}
                  className="w-full bg-slate-950 border border-cyber-border rounded px-3 py-2 text-slate-200 focus:border-cyber-cyan outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">REASON / CAMPAIGN REF</label>
                <input
                  type="text"
                  placeholder="e.g. Credential harvesting campaign"
                  value={newBlockReason}
                  onChange={(e) => setNewBlockReason(e.target.value)}
                  className="w-full bg-slate-950 border border-cyber-border rounded px-3 py-2 text-slate-200 focus:border-cyber-cyan outline-none"
                />
              </div>
              <div className="flex items-end">
                <Button type="submit" variant="primary" className="w-full">
                  Add Block
                </Button>
              </div>
            </form>
          </Card>

          {/* Blocklist Table */}
          <Card title="ACTIVE ENTERPRISE BLOCKLIST ENTRIES" icon={<Ban className="w-4 h-4 text-red-400" />}>
            <div className="space-y-2 font-mono text-xs">
              {blocklist.map((b) => (
                <div
                  key={b.id}
                  className="p-3 bg-slate-900/80 rounded border border-cyber-border flex items-center justify-between"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-400 font-bold border border-red-700 text-[10px]">
                        {b.type}
                      </span>
                      <span className="text-white font-bold">{b.value}</span>
                    </div>
                    <div className="text-[11px] text-slate-400">{b.reason}</div>
                  </div>
                  <div className="text-right text-[10px] text-slate-500">
                    <div>BY: {b.added_by}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

    </div>
  );
};
