import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Network, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  Filter, 
  Search, 
  Info, 
  X, 
  Layers, 
  RotateCcw,
  Sparkles
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import type { InvestigationGraph, GraphNode, GraphEdge, NodeType } from '../../types/api';

export interface InvestigationGraphViewProps {
  graph?: InvestigationGraph | null;
  selectedCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
  className?: string;
}

// Node Type Styling Configuration
const NODE_CONFIG: Record<NodeType, { color: string; stroke: string; label: string; bg: string }> = {
  CASE: { color: '#6366f1', stroke: '#818cf8', label: 'Case', bg: 'bg-indigo-950/60' },
  EMAIL: { color: '#06b6d4', stroke: '#22d3ee', label: 'Email', bg: 'bg-cyan-950/60' },
  SENDER: { color: '#f59e0b', stroke: '#fbbf24', label: 'Sender', bg: 'bg-amber-950/60' },
  DOMAIN: { color: '#3b82f6', stroke: '#60a5fa', label: 'Domain', bg: 'bg-blue-950/60' },
  URL: { color: '#f43f5e', stroke: '#fb7185', label: 'URL', bg: 'bg-rose-950/60' },
  IP: { color: '#a855f7', stroke: '#c084fc', label: 'IP Address', bg: 'bg-purple-950/60' },
  ASN: { color: '#10b981', stroke: '#34d399', label: 'ASN', bg: 'bg-emerald-950/60' },
  CAMPAIGN: { color: '#ef4444', stroke: '#f87171', label: 'Campaign', bg: 'bg-red-950/60' },
};

export const InvestigationGraphView: React.FC<InvestigationGraphViewProps> = ({
  graph,
  selectedCaseId,
  onSelectCase,
  className,
}) => {
  const [activeFilter, setActiveFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const containerRef = useRef<HTMLDivElement>(null);

  const rawNodes = graph?.nodes || [];
  const rawEdges = graph?.edges || [];

  // Filter nodes by type
  const filteredNodes = useMemo(() => {
    return rawNodes.filter((node) => {
      const matchesType = activeFilter === 'ALL' || node.type === activeFilter;
      const matchesSearch = !searchQuery || 
        node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [rawNodes, activeFilter, searchQuery]);

  const activeNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const visibleEdges = useMemo(() => {
    return rawEdges.filter(
      (edge) => activeNodeIds.has(edge.source) && activeNodeIds.has(edge.target)
    );
  }, [rawEdges, activeNodeIds]);

  // Layout node positions in circular / layered grid
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const total = filteredNodes.length;
    if (total === 0) return positions;

    const width = 800;
    const height = 500;
    const centerX = width / 2;
    const centerY = height / 2;

    // Group nodes by type for organized clustering
    const typeGroups: Record<string, GraphNode[]> = {};
    filteredNodes.forEach(node => {
      typeGroups[node.type] = typeGroups[node.type] || [];
      typeGroups[node.type].push(node);
    });

    const types = Object.keys(typeGroups);
    types.forEach((type, typeIdx) => {
      const groupNodes = typeGroups[type];
      const radius = 100 + typeIdx * 45;
      const angleStep = (2 * Math.PI) / groupNodes.length;

      groupNodes.forEach((node, nodeIdx) => {
        const angle = nodeIdx * angleStep + (typeIdx * 0.4);
        positions[node.id] = {
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle),
        };
      });
    });

    return positions;
  }, [filteredNodes]);

  // Pan handlers
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

  if (!graph || rawNodes.length === 0) {
    return (
      <Card title="INVESTIGATION RELATIONSHIP GRAPH" className={className}>
        <div className="py-12 text-center text-xs font-mono text-slate-500 space-y-2">
          <Network className="w-8 h-8 text-slate-600 mx-auto" />
          <div>NO GRAPH RELATIONSHIPS AVAILABLE</div>
          <p className="text-[11px] text-slate-600">
            Upload email cases to build and correlate entity relationship graphs.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <Card
      title="INVESTIGATION RELATIONSHIP GRAPH"
      subtitle={`Multi-case NetworkX relationship topology (${rawNodes.length} entities, ${rawEdges.length} connections)`}
      icon={<Network className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-4">
        
        {/* Controls Toolbar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 bg-cyber-surface rounded-lg border border-cyber-border">
          
          {/* Node Type Filters */}
          <div className="flex items-center space-x-1 overflow-x-auto max-w-full pb-1 sm:pb-0">
            <button
              onClick={() => setActiveFilter('ALL')}
              className={`px-2.5 py-1 rounded text-[10px] font-mono whitespace-nowrap transition ${
                activeFilter === 'ALL'
                  ? 'bg-cyber-card text-cyber-cyan border border-cyber-cyan/40 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              ALL ({rawNodes.length})
            </button>
            {(Object.keys(NODE_CONFIG) as NodeType[]).map((t) => {
              const count = rawNodes.filter(n => n.type === t).length;
              if (count === 0) return null;
              return (
                <button
                  key={t}
                  onClick={() => setActiveFilter(t)}
                  className={`px-2 py-1 rounded text-[10px] font-mono whitespace-nowrap flex items-center space-x-1 transition ${
                    activeFilter === t
                      ? 'bg-cyber-card text-white border border-cyber-cyan/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: NODE_CONFIG[t].color }}
                  />
                  <span>{t}</span>
                  <span className="text-[9px] text-slate-500">({count})</span>
                </button>
              );
            })}
          </div>

          {/* Search & Zoom Controls */}
          <div className="flex items-center space-x-2 w-full sm:w-auto justify-between sm:justify-end">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
              <input
                type="text"
                placeholder="Search nodes…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1 bg-cyber-bg border border-cyber-border rounded text-xs font-mono text-slate-200 placeholder:text-slate-500 w-36 focus:w-48 transition-all focus:outline-none focus:border-cyber-cyan"
              />
            </div>

            <div className="flex items-center space-x-1 border-l border-cyber-border pl-2">
              <button
                onClick={() => setZoom(z => Math.min(2.5, z + 0.2))}
                className="p-1 rounded bg-slate-800 text-slate-300 hover:text-white"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setZoom(z => Math.max(0.4, z - 0.2))}
                className="p-1 rounded bg-slate-800 text-slate-300 hover:text-white"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleResetView}
                className="p-1 rounded bg-slate-800 text-slate-300 hover:text-white"
                title="Reset View"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

        </div>

        {/* Interactive Graph Canvas Area */}
        <div
          ref={containerRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          className="relative w-full h-[500px] rounded-xl bg-cyber-bg border border-cyber-border overflow-hidden select-none cursor-grab active:cursor-grabbing"
        >
          {/* Subtle Grid Background */}
          <div className="absolute inset-0 bg-cyber-grid bg-[size:20px_20px] opacity-30 pointer-events-none" />

          {/* SVG Graph Viewport */}
          <svg
            className="w-full h-full"
            viewBox="0 0 800 500"
          >
            <g
              transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}
              className="transition-transform duration-75"
            >
              {/* Render Edges */}
              {visibleEdges.map((edge, idx) => {
                const srcPos = nodePositions[edge.source];
                const tgtPos = nodePositions[edge.target];
                if (!srcPos || !tgtPos) return null;

                const isConnectedToSelected = selectedNode && 
                  (selectedNode.id === edge.source || selectedNode.id === edge.target);

                return (
                  <g key={`edge-${edge.source}-${edge.target}-${idx}`}>
                    <line
                      x1={srcPos.x}
                      y1={srcPos.y}
                      x2={tgtPos.x}
                      y2={tgtPos.y}
                      stroke={isConnectedToSelected ? '#00f0ff' : '#1e2d4a'}
                      strokeWidth={isConnectedToSelected ? 2 : 1}
                      strokeDasharray={edge.relationship === 'CORRELATED_WITH' ? '4 3' : undefined}
                      opacity={selectedNode && !isConnectedToSelected ? 0.2 : 0.8}
                    />
                    {/* Relationship label */}
                    {isConnectedToSelected && (
                      <text
                        x={(srcPos.x + tgtPos.x) / 2}
                        y={(srcPos.y + tgtPos.y) / 2 - 4}
                        fill="#00f0ff"
                        fontSize="8"
                        fontFamily="monospace"
                        textAnchor="middle"
                        className="pointer-events-none"
                      >
                        {edge.relationship}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Render Nodes */}
              {filteredNodes.map((node) => {
                const pos = nodePositions[node.id];
                if (!pos) return null;

                const config = NODE_CONFIG[node.type] || NODE_CONFIG.CASE;
                const isSelected = selectedNode?.id === node.id;
                const isCaseMatch = selectedCaseId && node.id.includes(selectedCaseId);

                return (
                  <g
                    key={`node-${node.id}`}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode(node);
                      if (node.type === 'CASE' && onSelectCase) {
                        onSelectCase(node.id.replace('case:', ''));
                      }
                    }}
                    className="cursor-pointer group"
                  >
                    {/* Selection Ring */}
                    {(isSelected || isCaseMatch) && (
                      <circle
                        r="20"
                        fill="none"
                        stroke="#00f0ff"
                        strokeWidth="2"
                        className="animate-ping opacity-60"
                      />
                    )}

                    {/* Node Circle */}
                    <circle
                      r={node.type === 'CASE' || node.type === 'CAMPAIGN' ? 14 : 10}
                      fill="#0d131f"
                      stroke={config.color}
                      strokeWidth={isSelected ? 3 : 2}
                      className="transition-all hover:scale-125"
                      style={{
                        filter: isSelected ? `drop-shadow(0 0 8px ${config.color})` : undefined,
                      }}
                    />

                    {/* Inner Type Indicator */}
                    <circle
                      r={node.type === 'CASE' || node.type === 'CAMPAIGN' ? 6 : 4}
                      fill={config.color}
                    />

                    {/* Node Label Text */}
                    <text
                      y={node.type === 'CASE' || node.type === 'CAMPAIGN' ? 24 : 20}
                      fill={isSelected ? '#00f0ff' : '#cbd5e1'}
                      fontSize="9"
                      fontFamily="monospace"
                      fontWeight={isSelected ? 'bold' : 'normal'}
                      textAnchor="middle"
                      className="pointer-events-none drop-shadow"
                    >
                      {node.label.length > 20 ? `${node.label.slice(0, 18)}…` : node.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Legend Overlay */}
          <div className="absolute bottom-3 left-3 p-2.5 rounded-lg bg-cyber-surface/90 border border-cyber-border text-[10px] font-mono space-y-1.5 backdrop-blur-md">
            <span className="text-slate-500 uppercase font-bold block">ENTITY LEGEND</span>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1">
              {(Object.keys(NODE_CONFIG) as NodeType[]).map((type) => (
                <div key={type} className="flex items-center space-x-1.5">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: NODE_CONFIG[type].color }}
                  />
                  <span className="text-slate-300">{NODE_CONFIG[type].label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Node Inspector Drawer */}
          {selectedNode && (
            <div className="absolute top-3 right-3 w-72 p-4 rounded-xl bg-slate-900/95 border border-cyber-cyan/50 shadow-2xl backdrop-blur-md text-xs font-mono space-y-3 animate-fadeIn z-30">
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-1.5">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: NODE_CONFIG[selectedNode.type]?.color }}
                  />
                  <span className="font-bold text-slate-100 uppercase">
                    {NODE_CONFIG[selectedNode.type]?.label || selectedNode.type}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white p-0.5 rounded"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block">Entity Value:</span>
                <div className="text-slate-200 font-bold break-all bg-cyber-bg p-2 rounded border border-cyber-border text-[11px]">
                  {selectedNode.label}
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block">Identifier:</span>
                <span className="text-slate-400 text-[10px] break-all">{selectedNode.id}</span>
              </div>

              {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                <div className="space-y-1 pt-2 border-t border-cyber-border/40">
                  <span className="text-[10px] text-slate-500 uppercase block">Attributes:</span>
                  <div className="space-y-1 text-[10px]">
                    {Object.entries(selectedNode.metadata).map(([k, v]) => (
                      <div key={k} className="flex justify-between text-slate-400">
                        <span className="text-slate-500">{k}:</span>
                        <span className="text-slate-300 font-bold truncate max-w-[120px]">
                          {String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedNode.type === 'CASE' && onSelectCase && (
                <div className="pt-2">
                  <Button
                    variant="primary"
                    size="sm"
                    className="w-full"
                    onClick={() => onSelectCase(selectedNode.id.replace('case:', ''))}
                  >
                    Load Case Detail
                  </Button>
                </div>
              )}
            </div>
          )}

        </div>

      </div>
    </Card>
  );
};
