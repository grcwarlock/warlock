import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Network, Loader2, Shield, AlertTriangle, Server, Users,
  ArrowRight, X, ChevronRight, Terminal, ExternalLink, CheckCircle
} from 'lucide-react';
import api from '../lib/api';

interface GraphNode {
  id: string;
  type: string;
  label: string;
  category?: string;
  risk_level?: string;
  criticality?: string;
  impact_mode?: number;
  frequency_mode?: number;
  family?: string;
  status?: string;
  effectiveness?: number;
  asset_type?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  strength: number;
}

interface GraphCluster {
  id: string;
  label: string;
  node_ids: string[];
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  clusters: GraphCluster[];
  summary: {
    total_nodes: number;
    total_edges: number;
    threat_count: number;
    control_count: number;
    asset_count: number;
    vendor_count: number;
  };
}

interface ControlRemediation {
  control_id: string;
  control_name: string;
  nist_id: string;
  effectiveness: number;
  status: string;
  cost_annual: number;
  cli?: Record<string, string[]>;
  terraform?: string[];
  manual_steps?: string[];
  vendor_links?: { label: string; url: string }[];
}

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  threat: { bg: 'bg-red-500/15', border: 'border-red-500/30', text: 'text-red-400' },
  control: { bg: 'bg-blue-500/15', border: 'border-blue-500/30', text: 'text-blue-400' },
  asset: { bg: 'bg-emerald-500/15', border: 'border-emerald-500/30', text: 'text-emerald-400' },
  vendor: { bg: 'bg-violet-500/15', border: 'border-violet-500/30', text: 'text-violet-400' },
};

const NODE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  threat: AlertTriangle,
  control: Shield,
  asset: Server,
  vendor: Users,
};

const REL_COLORS: Record<string, string> = {
  mitigates: 'text-blue-500',
  targets: 'text-red-500',
  provides: 'text-violet-500',
  supports: 'text-emerald-500',
};

export default function RiskGraphPage() {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [remTab, setRemTab] = useState<'aws' | 'azure' | 'gcp'>('aws');
  const [typeFilter, setTypeFilter] = useState<string | null>(null);

  const { data: graph, isLoading } = useQuery<GraphData>({
    queryKey: ['risk', 'graph'],
    queryFn: async () => (await api.get('/risk/graph')).data,
  });

  // Fetch remediation when a control is selected
  const selectedNodeData = useMemo(() => graph?.nodes.find(n => n.id === selectedNode), [graph, selectedNode]);

  const { data: controlRemediation } = useQuery<ControlRemediation>({
    queryKey: ['risk', 'control-remediation', selectedNode],
    queryFn: async () => (await api.get(`/risk/controls/${selectedNode}/remediation`)).data,
    enabled: !!selectedNode && selectedNodeData?.type === 'control',
  });

  const edgesBySource = useMemo(() => {
    if (!graph) return {};
    const map: Record<string, GraphEdge[]> = {};
    for (const edge of graph.edges) {
      if (!map[edge.source]) map[edge.source] = [];
      map[edge.source].push(edge);
    }
    return map;
  }, [graph]);

  const edgesByTarget = useMemo(() => {
    if (!graph) return {};
    const map: Record<string, GraphEdge[]> = {};
    for (const edge of graph.edges) {
      if (!map[edge.target]) map[edge.target] = [];
      map[edge.target].push(edge);
    }
    return map;
  }, [graph]);

  // Get connected nodes for the selected node
  const connectedInfo = useMemo(() => {
    if (!graph || !selectedNode) return null;
    const outEdges = edgesBySource[selectedNode] || [];
    const inEdges = edgesByTarget[selectedNode] || [];

    const related = new Map<string, { node: GraphNode; relationship: string; direction: string }>();
    for (const e of outEdges) {
      const n = graph.nodes.find(nd => nd.id === e.target);
      if (n) related.set(n.id, { node: n, relationship: e.relationship, direction: 'outgoing' });
    }
    for (const e of inEdges) {
      const n = graph.nodes.find(nd => nd.id === e.source);
      if (n) related.set(n.id, { node: n, relationship: e.relationship, direction: 'incoming' });
    }

    return {
      outEdges,
      inEdges,
      related: Array.from(related.values()),
      threats: Array.from(related.values()).filter(r => r.node.type === 'threat'),
      controls: Array.from(related.values()).filter(r => r.node.type === 'control'),
      assets: Array.from(related.values()).filter(r => r.node.type === 'asset'),
      vendors: Array.from(related.values()).filter(r => r.node.type === 'vendor'),
    };
  }, [graph, selectedNode, edgesBySource, edgesByTarget]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-32 text-slate-500">
        <Loader2 className="w-8 h-8 animate-spin mb-3" />
        <p className="text-sm">Loading risk graph...</p>
      </div>
    );
  }

  if (!graph) return null;

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
          <Network className="w-5 h-5 text-blue-400" /> Risk Relationship Graph
        </h2>
        <p className="text-slate-400 text-sm mt-0.5">Click any node to explore connections, controls, and remediation details</p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { key: 'threat', label: 'Threats', value: graph.summary.threat_count, cls: 'text-red-400 border-red-500/20', icon: AlertTriangle },
          { key: 'control', label: 'Controls', value: graph.summary.control_count, cls: 'text-blue-400 border-blue-500/20', icon: Shield },
          { key: 'asset', label: 'Assets', value: graph.summary.asset_count, cls: 'text-emerald-400 border-emerald-500/20', icon: Server },
          { key: 'vendor', label: 'Vendors', value: graph.summary.vendor_count, cls: 'text-violet-400 border-violet-500/20', icon: Users },
        ].map(c => {
          const Icon = c.icon;
          const isActive = typeFilter === c.key;
          return (
            <button key={c.label} onClick={() => setTypeFilter(isActive ? null : c.key)} className={`bg-[var(--bg-surface)] border ${c.cls} rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all ${isActive ? 'ring-1 ring-[var(--border-color-hover)] scale-[1.02]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls.split(' ')[0]}`} />
              </div>
              <p className={`text-3xl font-extrabold ${c.cls.split(' ')[0]}`}>{c.value}</p>
            </button>
          );
        })}
      </div>

      {/* Main content: graph + detail panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Graph clusters (left 2/3) */}
        <div className={`${selectedNode ? 'lg:col-span-2' : 'lg:col-span-3'} space-y-5`}>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {graph.clusters.map((cluster) => {
              const clusterNodes = graph.nodes.filter((n) => cluster.node_ids.includes(n.id));
              return (
                <div key={cluster.id} className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
                  <h3 className="text-sm font-bold text-[var(--text-heading)] mb-4">{cluster.label}</h3>
                  <div className="space-y-2">
                    {clusterNodes.map((node) => {
                      const colors = NODE_COLORS[node.type] || NODE_COLORS.asset;
                      const Icon = NODE_ICONS[node.type] || Server;
                      const nodeEdges = edgesBySource[node.id] || [];
                      const isSelected = selectedNode === node.id;
                      return (
                        <button
                          key={node.id}
                          onClick={() => setSelectedNode(isSelected ? null : node.id)}
                          className={`w-full text-left ${colors.bg} border ${isSelected ? 'border-[var(--border-color-hover)] ring-1 ring-[var(--border-color-hover)]' : colors.border} rounded-xl p-3 transition-all hover:border-[var(--border-color-hover)]`}
                        >
                          <div className="flex items-center gap-2 mb-1">
                            <Icon className={`w-4 h-4 ${colors.text}`} />
                            <span className={`text-sm font-semibold ${colors.text}`}>{node.label}</span>
                            {node.risk_level && (
                              <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded capitalize ${
                                node.risk_level === 'high' ? 'bg-red-500/15 text-red-400' :
                                node.risk_level === 'medium' ? 'bg-amber-500/15 text-amber-400' : 'bg-blue-500/15 text-blue-400'
                              }`}>{node.risk_level}</span>
                            )}
                            {node.criticality && (
                              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400">{node.criticality}</span>
                            )}
                            {node.status && (
                              <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${node.status === 'implemented' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-amber-500/15 text-amber-400'}`}>
                                {node.status.replace(/_/g, ' ')}
                              </span>
                            )}
                          </div>
                          {node.category && <p className="text-[10px] text-slate-500 ml-6 capitalize">{node.category}</p>}
                          {node.impact_mode && <p className="text-[10px] text-slate-500 ml-6">Impact: ${(node.impact_mode / 1000).toFixed(0)}K | Freq: {node.frequency_mode}/yr</p>}
                          {node.effectiveness !== undefined && <p className="text-[10px] text-slate-500 ml-6">Effectiveness: {(node.effectiveness * 100).toFixed(0)}%</p>}
                          {nodeEdges.length > 0 && (
                            <div className="mt-2 ml-6 space-y-0.5">
                              {nodeEdges.slice(0, 3).map((edge, i) => {
                                const targetNode = graph.nodes.find((n) => n.id === edge.target);
                                return (
                                  <div key={i} className="flex items-center gap-1.5 text-[10px]">
                                    <ArrowRight className={`w-3 h-3 ${REL_COLORS[edge.relationship] || 'text-slate-500'}`} />
                                    <span className={`${REL_COLORS[edge.relationship] || 'text-slate-500'} font-semibold capitalize`}>{edge.relationship}</span>
                                    <span className="text-slate-400">{targetNode?.label || edge.target}</span>
                                  </div>
                                );
                              })}
                              {nodeEdges.length > 3 && <p className="text-[10px] text-slate-500 ml-4.5">+{nodeEdges.length - 3} more connections</p>}
                            </div>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Connection matrix */}
          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
            <h3 className="text-sm font-bold text-[var(--text-heading)] mb-4">Relationship Matrix ({graph.edges.length} connections)</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {graph.edges.map((edge, i) => {
                const sourceNode = graph.nodes.find((n) => n.id === edge.source);
                const targetNode = graph.nodes.find((n) => n.id === edge.target);
                return (
                  <button key={i} onClick={() => setSelectedNode(edge.source)} className="flex items-center gap-2 bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-lg px-3 py-2 cursor-pointer hover:bg-[var(--bg-interactive)] hover:border-[var(--border-color)] transition-all text-left">
                    <span className={`text-[10px] font-semibold ${NODE_COLORS[sourceNode?.type ?? 'asset']?.text || 'text-slate-400'}`}>{sourceNode?.label}</span>
                    <ArrowRight className={`w-3 h-3 ${REL_COLORS[edge.relationship] || 'text-slate-500'} flex-shrink-0`} />
                    <span className={`text-[10px] font-semibold ${NODE_COLORS[targetNode?.type ?? 'asset']?.text || 'text-slate-400'}`}>{targetNode?.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Detail panel (right 1/3) */}
        {selectedNode && selectedNodeData && connectedInfo && (
          <div className="lg:col-span-1">
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 sticky top-5 space-y-4 max-h-[calc(100vh-120px)] overflow-y-auto">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {(() => { const Icon = NODE_ICONS[selectedNodeData.type] || Server; return <Icon className={`w-5 h-5 ${NODE_COLORS[selectedNodeData.type]?.text}`} />; })()}
                  <h3 className="text-sm font-bold text-[var(--text-heading)]">{selectedNodeData.label}</h3>
                </div>
                <button onClick={() => setSelectedNode(null)} className="text-slate-500 hover:text-[var(--text-heading)] transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Node metadata */}
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-500">Type:</span>
                  <span className={`capitalize font-semibold ${NODE_COLORS[selectedNodeData.type]?.text}`}>{selectedNodeData.type}</span>
                </div>
                {selectedNodeData.category && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-500">Category:</span>
                    <span className="text-slate-300 capitalize">{selectedNodeData.category}</span>
                  </div>
                )}
                {selectedNodeData.risk_level && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-500">Risk Level:</span>
                    <span className={`font-bold capitalize ${selectedNodeData.risk_level === 'high' ? 'text-red-400' : selectedNodeData.risk_level === 'medium' ? 'text-amber-400' : 'text-blue-400'}`}>{selectedNodeData.risk_level}</span>
                  </div>
                )}
                {selectedNodeData.impact_mode && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-500">Impact:</span>
                    <span className="text-slate-300">${(selectedNodeData.impact_mode / 1000).toFixed(0)}K per event</span>
                  </div>
                )}
                {selectedNodeData.effectiveness !== undefined && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-500">Effectiveness:</span>
                    <div className="flex items-center gap-1.5">
                      <div className="w-16 h-1.5 bg-[var(--bg-interactive-hover)] rounded-full overflow-hidden">
                        <div className="h-full bg-blue-500 rounded-full" style={{ width: `${selectedNodeData.effectiveness * 100}%` }} />
                      </div>
                      <span className="text-blue-400">{(selectedNodeData.effectiveness * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Connected nodes grouped by type */}
              {connectedInfo.threats.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-1.5">Related Threats</h4>
                  <div className="space-y-1">
                    {connectedInfo.threats.map(r => (
                      <button key={r.node.id} onClick={() => setSelectedNode(r.node.id)} className="w-full flex items-center gap-2 text-xs bg-red-500/5 border border-red-500/10 rounded-lg px-2.5 py-1.5 hover:bg-red-500/10 transition-colors text-left">
                        <ChevronRight className="w-3 h-3 text-red-400" />
                        <span className="text-red-400 font-semibold">{r.node.label}</span>
                        <span className="text-slate-500 text-[10px] capitalize ml-auto">{r.relationship}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {connectedInfo.controls.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-1.5">Related Controls</h4>
                  <div className="space-y-1">
                    {connectedInfo.controls.map(r => (
                      <button key={r.node.id} onClick={() => setSelectedNode(r.node.id)} className="w-full flex items-center gap-2 text-xs bg-blue-500/5 border border-blue-500/10 rounded-lg px-2.5 py-1.5 hover:bg-blue-500/10 transition-colors text-left">
                        <ChevronRight className="w-3 h-3 text-blue-400" />
                        <span className="text-blue-400 font-semibold">{r.node.label}</span>
                        <span className="text-slate-500 text-[10px] capitalize ml-auto">{r.relationship}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {connectedInfo.assets.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-1.5">Related Assets</h4>
                  <div className="space-y-1">
                    {connectedInfo.assets.map(r => (
                      <button key={r.node.id} onClick={() => setSelectedNode(r.node.id)} className="w-full flex items-center gap-2 text-xs bg-emerald-500/5 border border-emerald-500/10 rounded-lg px-2.5 py-1.5 hover:bg-emerald-500/10 transition-colors text-left">
                        <ChevronRight className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400 font-semibold">{r.node.label}</span>
                        <span className="text-slate-500 text-[10px] capitalize ml-auto">{r.relationship}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {connectedInfo.vendors.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-1.5">Related Vendors</h4>
                  <div className="space-y-1">
                    {connectedInfo.vendors.map(r => (
                      <button key={r.node.id} onClick={() => setSelectedNode(r.node.id)} className="w-full flex items-center gap-2 text-xs bg-violet-500/5 border border-violet-500/10 rounded-lg px-2.5 py-1.5 hover:bg-violet-500/10 transition-colors text-left">
                        <ChevronRight className="w-3 h-3 text-violet-400" />
                        <span className="text-violet-400 font-semibold">{r.node.label}</span>
                        <span className="text-slate-500 text-[10px] capitalize ml-auto">{r.relationship}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Control-specific: Remediation */}
              {selectedNodeData.type === 'control' && controlRemediation && (
                <div className="border-t border-[var(--border-subtle)] pt-3">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Remediation</h4>
                  {controlRemediation.cli && Object.keys(controlRemediation.cli).length > 0 && (
                    <div>
                      <div className="flex gap-1 mb-1.5">
                        {(['aws', 'azure', 'gcp'] as const).filter(p => controlRemediation.cli?.[p]).map(p => (
                          <button key={p} onClick={() => setRemTab(p)} className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${remTab === p ? 'bg-[var(--bg-interactive-hover)] text-[var(--text-heading)]' : 'text-slate-500 hover:text-slate-300'}`}>{p}</button>
                        ))}
                      </div>
                      <pre className="bg-black/40 border border-[var(--border-subtle)] rounded-lg p-2 text-[10px] text-emerald-400 font-mono overflow-x-auto max-h-48 whitespace-pre-wrap">
                        {(controlRemediation.cli[remTab] ?? []).slice(0, 8).join('\n')}
                      </pre>
                    </div>
                  )}
                  {controlRemediation.manual_steps && controlRemediation.manual_steps.length > 0 && (
                    <div className="mt-2">
                      <h5 className="text-[10px] font-bold text-slate-500 mb-1">Manual Steps</h5>
                      <div className="space-y-0.5">
                        {controlRemediation.manual_steps.slice(0, 4).map((step, i) => (
                          <div key={i} className="flex items-start gap-1.5 text-[10px] text-slate-400">
                            <CheckCircle className="w-3 h-3 text-emerald-500 mt-0.5 flex-shrink-0" />
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {controlRemediation.vendor_links && controlRemediation.vendor_links.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {controlRemediation.vendor_links.map((link, i) => (
                        <a key={i} href={link.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300">
                          <ExternalLink className="w-2.5 h-2.5" /> {link.label}
                        </a>
                      ))}
                    </div>
                  )}
                  <div className="mt-2 text-[10px] text-slate-500">
                    <Terminal className="w-3 h-3 inline mr-1" />
                    Annual cost: ${controlRemediation.cost_annual?.toLocaleString() ?? 'N/A'}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
