import React, { useState, useRef, useMemo, useId } from 'react';
import { 
  Network, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Search, 
  X, 
  Layers, 
  Radio,
  Copy,
  Check,
  Radar,
  ArrowRight,
  ShieldAlert,
  Compass,
  Cpu,
  ExternalLink
} from 'lucide-react';
import type { InvestigationGraph, GraphNode, GraphEdge, NodeType } from '../../types/api';

export interface InvestigationGraphViewProps {
  graph?: InvestigationGraph | null;
  selectedCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
  className?: string;
}

// ------------------------------------------------------------------ //
//  Cytoscape Visual Stylesheet Specification                         //
// ------------------------------------------------------------------ //
export const CYTOSCAPE_STYLESHEET = [
  {
    selector: 'node',
    style: {
      'background-color': '#0f172a',
      'border-width': 2,
      'border-color': '#38bdf8',
      'label': 'data(label)',
      'color': '#cbd5e1',
      'font-family': 'ui-monospace, monospace',
      'font-size': '10px',
      'text-valign': 'bottom',
      'text-margin-y': 6,
    },
  },
  {
    selector: 'node[type = "IP"]',
    style: { 'border-color': '#00f0ff', 'background-color': '#0f172a' },
  },
  {
    selector: 'node[type = "URL"]',
    style: { 'border-color': '#f43f5e', 'background-color': '#0f172a' },
  },
  {
    selector: 'node[type = "DOMAIN"]',
    style: { 'border-color': '#38bdf8', 'background-color': '#0f172a' },
  },
  {
    selector: 'node[type = "SENDER"]',
    style: { 'border-color': '#fbbf24', 'background-color': '#0f172a' },
  },
  {
    selector: 'node[type = "EMAIL"]',
    style: { 'border-color': '#22d3ee', 'background-color': '#0f172a' },
  },
  {
    selector: 'node[type = "CASE"]',
    style: { 'border-color': '#818cf8', 'background-color': '#0f172a', 'width': 34, 'height': 34 },
  },
  {
    selector: 'node[type = "ASN"]',
    style: { 'border-color': '#34d399', 'background-color': '#0f172a' },
  },
  {
    selector: 'node[type = "CAMPAIGN"]',
    style: { 'border-color': '#ef4444', 'background-color': '#0f172a', 'width': 38, 'height': 38 },
  },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': '#38bdf8',
      'opacity': 0.6,
      'target-arrow-color': '#38bdf8',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
    },
  },
  {
    selector: 'node:selected',
    style: {
      'border-width': 3,
      'border-color': '#00f0ff',
      'shadow-blur': 16,
      'shadow-color': '#00f0ff',
    },
  },
];

// Node Type Visual & SOC Taxonomy Mapping
const NODE_CONFIG: Record<string, { color: string; glow: string; label: string; bg: string }> = {
  CASE: { color: '#818cf8', glow: 'rgba(129, 140, 248, 0.7)', label: 'Case', bg: 'bg-indigo-950/70 border-indigo-500/40 text-indigo-300' },
  EMAIL: { color: '#22d3ee', glow: 'rgba(34, 211, 238, 0.7)', label: 'Email', bg: 'bg-cyan-950/70 border-cyan-500/40 text-cyan-300' },
  SENDER: { color: '#fbbf24', glow: 'rgba(251, 191, 36, 0.7)', label: 'Sender', bg: 'bg-amber-950/70 border-amber-500/40 text-amber-300' },
  DOMAIN: { color: '#38bdf8', glow: 'rgba(56, 189, 248, 0.7)', label: 'Domain', bg: 'bg-sky-950/70 border-sky-500/40 text-sky-300' },
  URL: { color: '#f43f5e', glow: 'rgba(244, 63, 94, 0.8)', label: 'URL / Malicious Link', bg: 'bg-rose-950/70 border-rose-500/40 text-rose-300' },
  IP: { color: '#00f0ff', glow: 'rgba(0, 240, 255, 0.8)', label: 'IP Address', bg: 'bg-cyan-950/70 border-cyan-500/40 text-cyan-300' },
  ASN: { color: '#34d399', glow: 'rgba(52, 211, 153, 0.7)', label: 'ASN / BGP Routing', bg: 'bg-emerald-950/70 border-emerald-500/40 text-emerald-300' },
  CAMPAIGN: { color: '#ef4444', glow: 'rgba(239, 68, 68, 0.8)', label: 'Cluster Campaign', bg: 'bg-red-950/70 border-red-500/40 text-red-300' },
};

const DEFAULT_NODE_CONFIG = {
  color: '#38bdf8',
  glow: 'rgba(56, 189, 248, 0.7)',
  label: 'Entity',
  bg: 'bg-sky-950/70 border-sky-500/40 text-sky-300'
};

const getNodeConfig = (type?: string) => {
  if (!type) return DEFAULT_NODE_CONFIG;
  const upper = String(type).toUpperCase();
  return NODE_CONFIG[upper] || DEFAULT_NODE_CONFIG;
};

export const InvestigationGraphView: React.FC<InvestigationGraphViewProps> = ({
  graph,
  selectedCaseId,
  onSelectCase,
  className = '',
}) => {
  const [activeFilter, setActiveFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [radarSweeping, setRadarSweeping] = useState<boolean>(true);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const arrowMarkerId = useId();
  const arrowSelectedId = useId();

  const rawNodes = Array.isArray(graph?.nodes) ? graph.nodes.filter(Boolean) : [];
  const rawEdges = Array.isArray(graph?.edges) ? graph.edges.filter(Boolean) : [];

  // Filter nodes by type & search criteria
  const filteredNodes = useMemo(() => {
    return rawNodes.filter((node) => {
      if (!node || !node.id) return false;
      const matchesType = activeFilter === 'ALL' || node.type === activeFilter;
      const label = String(node.label || node.id || '');
      const id = String(node.id || '');
      const matchesSearch = !searchQuery || 
        label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [rawNodes, activeFilter, searchQuery]);

  const activeNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id).filter(Boolean)), [filteredNodes]);

  const visibleEdges = useMemo(() => {
    return rawEdges.filter(
      (edge) => edge && edge.source && edge.target && activeNodeIds.has(edge.source) && activeNodeIds.has(edge.target)
    );
  }, [rawEdges, activeNodeIds]);

  // Dynamic layout positioning in tactical concentric cluster
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const total = filteredNodes.length;
    if (total === 0) return positions;

    const width = 860;
    const height = 540;
    const centerX = width / 2;
    const centerY = height / 2;

    if (total === 1) {
      positions[filteredNodes[0].id] = { x: centerX, y: centerY };
      return positions;
    }

    // Group nodes by entity type for organized tactical rings
    const typeGroups: Record<string, GraphNode[]> = {};
    filteredNodes.forEach(node => {
      if (!node) return;
      typeGroups[node.type] = typeGroups[node.type] || [];
      typeGroups[node.type].push(node);
    });

    const types = Object.keys(typeGroups);
    types.forEach((type, typeIdx) => {
      const groupNodes = typeGroups[type] || [];
      if (groupNodes.length === 0) return;
      
      // Radius rings from 110px outwards
      const radius = 110 + typeIdx * 48;
      const angleStep = groupNodes.length > 0 ? (2 * Math.PI) / groupNodes.length : 0;

      groupNodes.forEach((node, nodeIdx) => {
        if (!node) return;
        const angle = nodeIdx * angleStep + (typeIdx * 0.45);
        positions[node.id] = {
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle),
        };
      });
    });

    return positions;
  }, [filteredNodes]);

  // Pan & Zoom controls
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(text);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  if (!graph || rawNodes.length === 0) {
    return (
      <div className={`relative overflow-hidden rounded-xl border border-slate-800 bg-slate-950/90 p-6 backdrop-blur-md shadow-2xl ${className}`}>
        <div className="flex items-center space-x-2 border-b border-slate-800/80 pb-3 font-mono text-xs text-slate-400">
          <Network className="h-4 w-4 text-cyan-400" />
          <span className="font-bold tracking-wider text-slate-200 uppercase">INVESTIGATION RELATIONSHIP GRAPH</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-500">Multi-Case NetworkX Relationship Topology</span>
        </div>
        <div className="py-16 text-center font-mono text-xs text-slate-500 space-y-3">
          <Radar className="h-10 w-10 text-slate-700 mx-auto animate-pulse" />
          <div className="text-slate-400 font-bold uppercase tracking-widest">
            NO GRAPH RELATIONSHIPS AVAILABLE
          </div>
          <p className="text-[11px] text-slate-600 max-w-sm mx-auto">
            Upload email cases into the forensic engine to construct cross-entity correlation graphs.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={`relative overflow-hidden rounded-xl border border-slate-800 bg-slate-950/95 shadow-2xl backdrop-blur-md transition-all ${className}`}>
      
      {/* Top Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 bg-slate-900/60 px-5 py-3 font-mono text-xs">
        <div className="flex items-center space-x-2.5">
          <Network className="h-4 w-4 text-cyan-400 animate-pulse" />
          <span className="font-bold tracking-wider text-slate-100 uppercase">INVESTIGATION RELATIONSHIP GRAPH</span>
          <span className="text-slate-600">|</span>
          <span className="text-[11px] text-slate-400">Multi-case NetworkX relationship topology ({rawNodes.length} entities, {rawEdges.length} connections)</span>
        </div>
        
        <div className="flex items-center space-x-3 text-[11px]">
          <button
            onClick={() => setRadarSweeping(!radarSweeping)}
            className={`flex items-center space-x-1.5 px-2.5 py-1 rounded border transition ${
              radarSweeping 
                ? 'border-cyan-500/40 bg-cyan-950/50 text-cyan-300 shadow-[0_0_10px_rgba(0,240,255,0.2)]' 
                : 'border-slate-700 bg-slate-900 text-slate-400'
            }`}
          >
            <Radar className={`h-3 w-3 ${radarSweeping ? 'text-cyan-400 animate-spin' : 'text-slate-500'}`} />
            <span>RADAR SWEEP // {radarSweeping ? 'ACTIVE' : 'PAUSED'}</span>
          </button>
          
          <span className="rounded border border-slate-700 bg-slate-900/90 px-2 py-1 font-bold text-slate-300">
            NETWORKX_ENGINE_V2
          </span>
        </div>
      </div>

      {/* Main Interactive Tactical Radar Canvas */}
      <div className="p-4">
        <div
          ref={containerRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          className="relative h-[560px] w-full rounded-xl border border-slate-800 bg-slate-950 overflow-hidden select-none cursor-grab active:cursor-grabbing shadow-inner"
        >
          {/* Military Cyber Grid Backdrop */}
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:24px_24px] opacity-70" />
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(6,182,212,0.06)_0%,transparent_70%)]" />

          {/* Active Radar Sweep Beam (Rotating Conic Gradient) */}
          {radarSweeping && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden">
              <div 
                className="h-[800px] w-[800px] rounded-full animate-[spin_8s_linear_infinite]"
                style={{
                  background: 'conic-gradient(from 0deg at 50% 50%, rgba(0, 240, 255, 0.15) 0deg, rgba(0, 240, 255, 0) 60deg, transparent 360deg)',
                }}
              />
            </div>
          )}

          {/* SVG Canvas for Radar Reticles, Edges, and Nodes */}
          <svg className="h-full w-full relative z-10" viewBox="0 0 860 540">
            <defs>
              {/* Directed Edge Arrowhead Markers */}
              <marker
                id={arrowMarkerId}
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" fillOpacity="0.8" />
              </marker>

              <marker
                id={arrowSelectedId}
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="8"
                markerHeight="8"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#00f0ff" />
              </marker>

              {/* Node Drop Shadow Laser Glow */}
              <filter id="nodeGlow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Static Tactical Radar Range Rings & Crosshairs */}
            <g className="pointer-events-none opacity-40">
              <circle cx="430" cy="270" r="110" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
              <circle cx="430" cy="270" r="170" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
              <circle cx="430" cy="270" r="230" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
              
              {/* Center Crosshair Lines */}
              <line x1="430" y1="20" x2="430" y2="520" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 6" />
              <line x1="20" y1="270" x2="840" y2="270" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 6" />
              
              {/* Tactical Heading Indicators */}
              <text x="430" y="32" fill="#475569" fontSize="9" fontFamily="monospace" textAnchor="middle">000° [N]</text>
              <text x="830" y="273" fill="#475569" fontSize="9" fontFamily="monospace" textAnchor="end">090° [E]</text>
              <text x="430" y="525" fill="#475569" fontSize="9" fontFamily="monospace" textAnchor="middle">180° [S]</text>
              <text x="30" y="273" fill="#475569" fontSize="9" fontFamily="monospace" textAnchor="start">270° [W]</text>
            </g>

            {/* Dynamic Graph Group with Pan & Zoom */}
            <g
              transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}
              className="transition-transform duration-75"
            >
              {/* 1. Render Directed Edges */}
              {visibleEdges.map((edge, idx) => {
                const srcPos = nodePositions[edge.source];
                const tgtPos = nodePositions[edge.target];
                if (!srcPos || !tgtPos) return null;

                const isConnected = selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);

                return (
                  <g key={`edge-${edge.source}-${edge.target}-${idx}`}>
                    <line
                      x1={srcPos.x}
                      y1={srcPos.y}
                      x2={tgtPos.x}
                      y2={tgtPos.y}
                      stroke={isConnected ? '#00f0ff' : '#38bdf8'}
                      strokeWidth={isConnected ? 2.5 : 1.2}
                      strokeOpacity={isConnected ? 1 : selectedNode ? 0.15 : 0.55}
                      strokeDasharray={edge.relationship === 'CORRELATED_WITH' ? '4 3' : undefined}
                      markerEnd={`url(#${isConnected ? arrowSelectedId : arrowMarkerId})`}
                      className="transition-all duration-300"
                    />
                    
                    {/* Relationship floating text */}
                    {isConnected && (
                      <text
                        x={(srcPos.x + tgtPos.x) / 2}
                        y={(srcPos.y + tgtPos.y) / 2 - 6}
                        fill="#00f0ff"
                        fontSize="8.5"
                        fontFamily="monospace"
                        fontWeight="bold"
                        textAnchor="middle"
                        className="pointer-events-none drop-shadow-[0_0_6px_rgba(0,240,255,0.8)]"
                      >
                        {edge.relationship}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* 2. Render Graph Nodes */}
              {filteredNodes.map((node) => {
                const pos = nodePositions[node.id];
                if (!pos) return null;

                const config = getNodeConfig(node.type);
                const isSelected = selectedNode?.id === node.id;
                const nodeIdStr = String(node.id || '');
                const isCaseMatch = selectedCaseId && nodeIdStr.includes(selectedCaseId);
                const nodeTypeUpper = String(node.type || '').toUpperCase();
                const isHubNode = nodeTypeUpper === 'CASE' || nodeTypeUpper === 'CAMPAIGN';
                const labelText = String(node.label || node.id || '');

                return (
                  <g
                    key={`node-${node.id}`}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode(node);
                      if (nodeTypeUpper === 'CASE' && onSelectCase) {
                        onSelectCase(nodeIdStr.replace('case:', ''));
                      }
                    }}
                    className="cursor-pointer group"
                  >
                    {/* Active Target Lock Ping */}
                    {(isSelected || isCaseMatch) && (
                      <circle
                        r="22"
                        fill="none"
                        stroke="#00f0ff"
                        strokeWidth="2"
                        className="animate-ping opacity-75"
                      />
                    )}

                    {/* Outer Glow Halo Ring */}
                    <circle
                      r={isHubNode ? 16 : 11}
                      fill="#0f172a"
                      stroke={config.color}
                      strokeWidth={isSelected ? 3 : 2}
                      filter={isSelected ? 'url(#nodeGlow)' : undefined}
                      style={{
                        boxShadow: `0 0 12px ${config.glow}`,
                      }}
                      className="transition-transform duration-200 group-hover:scale-125"
                    />

                    {/* Dark Center Core with Type-Colored Dot */}
                    <circle
                      r={isHubNode ? 7 : 4.5}
                      fill={config.color}
                      className="transition-all"
                    />

                    {/* Monospace Node Label */}
                    <text
                      y={isHubNode ? 26 : 22}
                      fill={isSelected ? '#00f0ff' : '#e2e8f0'}
                      fontSize="9"
                      fontFamily="ui-monospace, monospace"
                      fontWeight={isSelected ? 'bold' : 'normal'}
                      textAnchor="middle"
                      className="pointer-events-none drop-shadow-[0_1px_4px_rgba(0,0,0,0.9)]"
                    >
                      {labelText.length > 22 ? `${labelText.slice(0, 20)}…` : labelText}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* ========================================================= */}
          {/* FLOATING HUD OVERLAYS (Glassmorphic SOC Controllers)       */}
          {/* ========================================================= */}

          {/* TOP LEFT: Mission Status & Search Pod */}
          <div className="absolute top-3 left-3 p-3 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md shadow-2xl font-mono text-xs space-y-2 z-20 max-w-sm">
            <div className="flex items-center space-x-2 text-cyan-400 text-[11px] font-bold">
              <Radio className="h-3.5 w-3.5 animate-pulse" />
              <span>RADAR.CORRELATION // LIVE</span>
            </div>
            
            <div className="relative">
              <Search className="h-3.5 w-3.5 text-slate-500 absolute left-2.5 top-2" />
              <input
                type="text"
                placeholder="Search nodes or IPs…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1 bg-slate-950/90 border border-slate-700/80 rounded text-xs font-mono text-slate-200 placeholder:text-slate-500 w-48 focus:w-60 transition-all focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>

          {/* TOP RIGHT: Tactical Zoom & Pan Control Pod */}
          <div className="absolute top-3 right-3 flex items-center space-x-1.5 p-1.5 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md shadow-2xl z-20">
            <button
              onClick={() => setZoom(z => Math.min(2.8, z + 0.2))}
              className="p-1.5 rounded-lg bg-slate-800/80 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition"
              title="Zoom In"
            >
              <ZoomIn className="h-4 w-4" />
            </button>
            <button
              onClick={() => setZoom(z => Math.max(0.3, z - 0.2))}
              className="p-1.5 rounded-lg bg-slate-800/80 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition"
              title="Zoom Out"
            >
              <ZoomOut className="h-4 w-4" />
            </button>
            <button
              onClick={handleResetView}
              className="p-1.5 rounded-lg bg-slate-800/80 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition"
              title="Reset View"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
          </div>

          {/* BOTTOM LEFT: Entity Legend & Type Filter Strip */}
          <div className="absolute bottom-3 left-3 p-3 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md shadow-2xl font-mono text-[10px] space-y-2 z-20 max-w-md">
            <div className="flex items-center justify-between text-slate-400 font-bold uppercase tracking-wider">
              <span>ENTITY CLASSIFIERS</span>
              <button
                onClick={() => setActiveFilter('ALL')}
                className={`px-1.5 py-0.5 rounded transition ${
                  activeFilter === 'ALL' ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                SHOW ALL ({rawNodes.length})
              </button>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
              {(Object.keys(NODE_CONFIG) as string[]).map((type) => {
                const count = rawNodes.filter(n => n && String(n.type).toUpperCase() === type).length;
                if (count === 0) return null;
                const isSelected = activeFilter.toUpperCase() === type;
                const cfg = getNodeConfig(type);
                return (
                  <button
                    key={type}
                    onClick={() => setActiveFilter(isSelected ? 'ALL' : type)}
                    className={`flex items-center space-x-1.5 px-2 py-1 rounded border text-left transition ${
                      isSelected 
                        ? 'border-cyan-400 bg-slate-800 text-white font-bold' 
                        : 'border-slate-800/80 bg-slate-950/60 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <span
                      className="h-2 w-2 rounded-full shrink-0"
                      style={{ backgroundColor: cfg.color }}
                    />
                    <span className="truncate">{cfg.label}</span>
                    <span className="text-slate-500 text-[9px]">({count})</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* BOTTOM RIGHT: Graph Telemetry Pod */}
          <div className="absolute bottom-3 right-3 px-3 py-2 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md shadow-2xl font-mono text-[11px] text-slate-400 flex items-center space-x-3 z-20">
            <div>NODES: <span className="text-cyan-400 font-bold">{filteredNodes.length}</span></div>
            <div className="text-slate-700">|</div>
            <div>EDGES: <span className="text-sky-400 font-bold">{visibleEdges.length}</span></div>
            <div className="text-slate-700">|</div>
            <div>ZOOM: <span className="text-slate-200 font-bold">{Math.round(zoom * 100)}%</span></div>
          </div>

          {/* INTERACTIVE NODE INSPECTOR FLYOUT */}
          {selectedNode && (
            <div className="absolute top-16 right-3 w-80 p-4.5 rounded-xl bg-slate-900/95 border border-cyan-500/50 shadow-2xl backdrop-blur-md text-xs font-mono space-y-3.5 z-30 animate-in fade-in slide-in-from-right-4 duration-200">
              <div className="flex items-start justify-between border-b border-slate-800 pb-2.5">
                <div className="flex items-center space-x-2">
                  <span
                    className="h-3 w-3 rounded-full"
                    style={{ backgroundColor: getNodeConfig(selectedNode.type).color }}
                  />
                  <span className="font-bold text-slate-100 uppercase tracking-wider">
                    {getNodeConfig(selectedNode.type).label}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="space-y-1.5">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold block">Entity Value</span>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-bold break-all text-[11px]">
                  <span>{String(selectedNode.label || selectedNode.id || '')}</span>
                  <button
                    onClick={() => copyToClipboard(String(selectedNode.label || selectedNode.id || ''))}
                    className="text-cyan-400 hover:text-cyan-300 ml-2 shrink-0"
                    title="Copy Value"
                  >
                    {copiedValue === String(selectedNode.label || selectedNode.id || '') ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold block">Identifier</span>
                <span className="text-slate-400 text-[10px] break-all bg-slate-950/60 p-1.5 rounded block border border-slate-800/60">
                  {String(selectedNode.id || '')}
                </span>
              </div>

              {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold block">Forensic Attributes</span>
                  <div className="space-y-1 text-[10px]">
                    {Object.entries(selectedNode.metadata).map(([k, v]) => (
                      <div key={k} className="flex justify-between items-center py-0.5 text-slate-400 border-b border-slate-800/40">
                        <span className="text-slate-500">{k}:</span>
                        <span className="text-slate-200 font-bold truncate max-w-[140px]">
                          {typeof v === 'object' ? JSON.stringify(v) : String(v ?? '')}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {String(selectedNode.type || '').toUpperCase() === 'CASE' && onSelectCase && (
                <div className="pt-2">
                  <button
                    onClick={() => onSelectCase(String(selectedNode.id || '').replace('case:', ''))}
                    className="w-full flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/50 text-cyan-300 font-bold hover:bg-cyan-500/30 transition text-xs"
                  >
                    <span>Load Case Detail Workspace</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </div>
          )}

        </div>
      </div>

    </div>
  );
};
