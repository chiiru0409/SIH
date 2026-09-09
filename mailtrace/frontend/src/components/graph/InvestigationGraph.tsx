import React, { useState } from 'react';
import { Network, ShieldAlert, Globe, Link2, Server, Flame, Users, CheckCircle2, Info, X } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

interface GraphNode {
  id: string;
  label: string;
  type: 'CASE' | 'SENDER' | 'DOMAIN' | 'IP' | 'URL' | 'CAMPAIGN' | 'RECIPIENT';
  x: number;
  y: number;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'BENIGN';
  details: string;
  correlationExplanation: string;
}

interface GraphLink {
  source: string;
  target: string;
  label: string;
}

export const InvestigationGraph: React.FC = () => {
  const { activeCaseId, setActiveCaseId, setActiveTab } = useInvestigation();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');

  // Interactive Graph nodes centered on active case scenario
  const nodes: GraphNode[] = [
    {
      id: 'CASE-2026-0842',
      label: 'CASE-0842 (CFO Phish)',
      type: 'CASE',
      x: 450,
      y: 220,
      threatLevel: 'CRITICAL',
      details: 'Microsoft 365 Password Expiration & MFA Reset Fraud',
      correlationExplanation: 'Central investigated incident targeting Chief Financial Officer.'
    },
    {
      id: 'NODE-SENDER',
      label: 'alert@micros0ft.com (Spoofed)',
      type: 'SENDER',
      x: 250,
      y: 120,
      threatLevel: 'CRITICAL',
      details: 'Header-From spoofed display name with mismatched return-path.',
      correlationExplanation: 'Shares display name spoofing pattern across 12 targeted emails.'
    },
    {
      id: 'NODE-DOMAIN',
      label: 'micros0ft-security-auth.com',
      type: 'DOMAIN',
      x: 220,
      y: 320,
      threatLevel: 'CRITICAL',
      details: 'Newly registered lookalike domain (1 day old, NameCheap).',
      correlationExplanation: 'Registered simultaneously with 2 other campaign domains.'
    },
    {
      id: 'NODE-IP',
      label: '185.220.101.42 (Tor Relay)',
      type: 'IP',
      x: 450,
      y: 420,
      threatLevel: 'CRITICAL',
      details: 'HostRoyale Ltd (AS49505) bulletproof proxy server in Amsterdam.',
      correlationExplanation: 'Shared sending infrastructure linked to CAMPAIGN-0042 (142 emails).'
    },
    {
      id: 'NODE-URL',
      label: 'hxxps://login[.]micros0ft...',
      type: 'URL',
      x: 150,
      y: 220,
      threatLevel: 'CRITICAL',
      details: 'ADFS cloned credential harvester landing page.',
      correlationExplanation: 'Direct link extracted from email body text.'
    },
    {
      id: 'NODE-CAMPAIGN',
      label: 'CAMPAIGN-0042 (O365-BLITZ)',
      type: 'CAMPAIGN',
      x: 720,
      y: 420,
      threatLevel: 'CRITICAL',
      details: 'Multi-target active credential harvest blitz targeting leadership.',
      correlationExplanation: 'Correlated via shared IP 185.220.101.42 and ADFS login kit hashes.'
    },
    {
      id: 'NODE-RECIPIENT',
      label: 'cfo@enterprise.com (Target)',
      type: 'RECIPIENT',
      x: 680,
      y: 120,
      threatLevel: 'HIGH',
      details: 'Chief Financial Officer / High-Value Target.',
      correlationExplanation: 'Targeted directly in high-severity BEC/harvest wave.'
    },
    {
      id: 'CASE-2026-0845',
      label: 'CASE-0845 (VP Eng Harvest)',
      type: 'CASE',
      x: 720,
      y: 260,
      threatLevel: 'CRITICAL',
      details: 'Correlated Microsoft Credential harvesting incident.',
      correlationExplanation: 'Originated from the exact same reverse proxy IP (185.220.101.42).'
    }
  ];

  const links: GraphLink[] = [
    { source: 'CASE-2026-0842', target: 'NODE-SENDER', label: 'SENT_BY' },
    { source: 'CASE-2026-0842', target: 'NODE-DOMAIN', label: 'USES_DOMAIN' },
    { source: 'CASE-2026-0842', target: 'NODE-IP', label: 'ROUTED_THROUGH' },
    { source: 'CASE-2026-0842', target: 'NODE-URL', label: 'EMBEDS_URL' },
    { source: 'CASE-2026-0842', target: 'NODE-RECIPIENT', label: 'TARGETS' },
    { source: 'NODE-IP', target: 'NODE-CAMPAIGN', label: 'ATTRIBUTED_TO' },
    { source: 'NODE-IP', target: 'CASE-2026-0845', label: 'SHARED_RELAY' },
    { source: 'CASE-2026-0845', target: 'NODE-CAMPAIGN', label: 'CAMPAIGN_MEMBER' }
  ];

  const getNodeColor = (node: GraphNode) => {
    switch (node.type) {
      case 'CASE':
        return { bg: 'fill-red-500/20', stroke: 'stroke-red-500', text: 'text-red-400' };
      case 'IP':
        return { bg: 'fill-cyan-500/20', stroke: 'stroke-cyan-500', text: 'text-cyan-400' };
      case 'DOMAIN':
        return { bg: 'fill-amber-500/20', stroke: 'stroke-amber-500', text: 'text-amber-400' };
      case 'URL':
        return { bg: 'fill-purple-500/20', stroke: 'stroke-purple-500', text: 'text-purple-400' };
      case 'CAMPAIGN':
        return { bg: 'fill-orange-500/30', stroke: 'stroke-orange-500', text: 'text-orange-400' };
      default:
        return { bg: 'fill-slate-700/40', stroke: 'stroke-slate-500', text: 'text-slate-300' };
    }
  };

  const filteredNodes = filterType === 'ALL'
    ? nodes
    : nodes.filter(n => n.type === filterType || n.type === 'CASE');

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-cyber-panel border border-slate-800 rounded-lg">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold font-mono text-slate-200">
            Multi-Incident Forensic Correlation Graph
          </h2>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Filter Node:</span>
          {['ALL', 'IP', 'DOMAIN', 'URL', 'CAMPAIGN'].map(f => (
            <button
              key={f}
              onClick={() => setFilterType(f)}
              className={`px-2 py-0.5 rounded ${
                filterType === f
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                  : 'bg-slate-900 text-slate-400 border border-slate-800'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Graph Canvas & Side Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 p-2 rounded-lg bg-slate-950 border border-slate-800 relative min-h-[500px] overflow-hidden flex items-center justify-center">
          <svg viewBox="0 0 900 520" className="w-full h-full select-none">
            {/* Draw Links */}
            {links.map((link, idx) => {
              const src = nodes.find(n => n.id === link.source);
              const tgt = nodes.find(n => n.id === link.target);
              if (!src || !tgt) return null;

              const isSrcVisible = filteredNodes.some(n => n.id === src.id);
              const isTgtVisible = filteredNodes.some(n => n.id === tgt.id);
              if (!isSrcVisible || !isTgtVisible) return null;

              const isConnectedToSelected =
                selectedNode && (selectedNode.id === src.id || selectedNode.id === tgt.id);

              return (
                <g key={idx}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    className={`transition-all ${
                      isConnectedToSelected
                        ? 'stroke-cyan-400 stroke-2'
                        : 'stroke-slate-700 stroke-1 stroke-dasharray-[4,4]'
                    }`}
                  />
                  {/* Link Label */}
                  <text
                    x={(src.x + tgt.x) / 2}
                    y={(src.y + tgt.y) / 2 - 4}
                    className="text-[9px] font-mono fill-slate-400"
                    textAnchor="middle"
                  >
                    {link.label}
                  </text>
                </g>
              );
            })}

            {/* Draw Nodes */}
            {filteredNodes.map(node => {
              const color = getNodeColor(node);
              const isSelected = selectedNode?.id === node.id;
              const isCenterCase = node.id === activeCaseId;

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  className="cursor-pointer group"
                  onClick={() => setSelectedNode(node)}
                >
                  <circle
                    r={isCenterCase ? 24 : isSelected ? 22 : 18}
                    className={`${color.bg} ${color.stroke} stroke-2 transition-all group-hover:scale-110 ${
                      isSelected ? 'ring-4 ring-cyan-400/50' : ''
                    }`}
                  />
                  <text
                    y={32}
                    className="text-[10px] font-mono font-bold fill-slate-200"
                    textAnchor="middle"
                  >
                    {node.label}
                  </text>
                  <text
                    y={44}
                    className="text-[9px] font-mono fill-slate-400"
                    textAnchor="middle"
                  >
                    [{node.type}]
                  </text>
                </g>
              );
            })}
          </svg>

          <div className="absolute bottom-3 left-3 text-[10px] font-mono text-slate-400 bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
            Click any node to inspect multi-hop forensic relationship
          </div>
        </div>

        {/* Right: "Why Related" Inspector Drawer */}
        <div className="lg:col-span-4 p-5 rounded-lg bg-cyber-panel border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold font-mono text-slate-200">
                  Relationship Inspector
                </h3>
              </div>
              {selectedNode && (
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 rounded text-slate-400 hover:text-slate-100"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>

            {selectedNode ? (
              <div className="mt-4 space-y-3 font-mono text-xs">
                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase">Selected Entity</div>
                  <div className="text-sm font-bold text-cyan-300">{selectedNode.label}</div>
                  <div className="text-[11px] text-slate-400">Type: {selectedNode.type}</div>
                </div>

                <div className="p-3 rounded bg-cyan-950/30 border border-cyan-500/30 space-y-1">
                  <div className="text-[10px] text-cyan-400 font-bold uppercase">
                    Why Is This Related?
                  </div>
                  <p className="text-slate-200 leading-relaxed">
                    {selectedNode.correlationExplanation}
                  </p>
                </div>

                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase">Technical Telemetry</div>
                  <p className="text-slate-300">{selectedNode.details}</p>
                </div>

                {selectedNode.type === 'CASE' && selectedNode.id !== activeCaseId && (
                  <button
                    onClick={() => {
                      setActiveCaseId(selectedNode.id);
                      setActiveTab('investigation');
                    }}
                    className="w-full py-2 rounded bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400 transition-colors"
                  >
                    Switch Investigation to {selectedNode.id}
                  </button>
                )}
              </div>
            ) : (
              <div className="mt-12 text-center text-xs font-mono text-slate-400 space-y-2">
                <Network className="w-8 h-8 text-slate-700 mx-auto animate-pulse" />
                <p>Select any entity node in the correlation graph to view multi-hop evidence rationale.</p>
              </div>
            )}
          </div>

          <div className="mt-6 pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <span>Graph Engine: GraphViz / Force-Directed</span>
            <span className="text-emerald-400">8 Nodes Aligned</span>
          </div>
        </div>
      </div>
    </div>
  );
};
