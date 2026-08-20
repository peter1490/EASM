"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { getAssetPath, type Asset } from "@/app/api";
import { Icon, assetIcon, EmptyState, ErrorState, LoadingBlock } from "@/components/kit";
import { pct } from "@/lib/format";
import { confidenceColor } from "./shared";

/**
 * How an asset came to be known: the chain from the seed that started it down
 * to this asset, laid out by dagre and drawn by @xyflow/react.
 *
 * Moved here from `components/AssetDiscoveryGraph` and restyled onto the design
 * tokens — the graph itself is unchanged, but the nodes were hard-coded white
 * with emoji glyphs, so it was the one part of the app that ignored dark mode.
 */

interface CustomNodeData extends Record<string, unknown> {
  label: string;
  type: string;
  confidence?: number;
  isTarget: boolean;
  assetId: string;
  onNodeClick: (assetId: string) => void;
}

const NODE_WIDTH = 216;
const NODE_HEIGHT = 76;

function AssetNode({ data }: NodeProps<Node<CustomNodeData>>) {
  const { label, type, confidence, isTarget, assetId, onNodeClick } = data;

  return (
    <div
      role={isTarget ? undefined : "button"}
      tabIndex={isTarget ? undefined : 0}
      onClick={() => !isTarget && onNodeClick(assetId)}
      onKeyDown={(event) => {
        if (isTarget) return;
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onNodeClick(assetId);
        }
      }}
      className="px-3 py-2.5 rounded-lg border bg-surface transition-colors duration-100"
      style={{
        width: NODE_WIDTH,
        borderColor: isTarget ? "var(--accent)" : "var(--rule-2)",
        boxShadow: isTarget ? "0 0 0 3px var(--accent-wash)" : undefined,
        cursor: isTarget ? "default" : "pointer",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: "var(--rule-2)", border: "none" }} />

      <div className="flex items-start gap-2">
        <span className="grid place-items-center w-5 h-5 rounded bg-surface-2 text-ink-2 shrink-0">
          <Icon name={assetIcon(type)} size={12} />
        </span>
        <div className="flex-1 min-w-0">
          <div className="lbl leading-none">{type}</div>
          <div className="mono text-[12px] text-ink truncate mt-1" title={label}>
            {label}
          </div>
        </div>
        {!isTarget && <Icon name="arrowRight" size={11} className="text-ink-3 mt-0.5" />}
      </div>

      {confidence != null && (
        <div className="flex items-center gap-2 mt-2">
          <span className="flex-1 block h-1 rounded-sm bg-surface-2 overflow-hidden">
            <span
              className="block h-full rounded-sm"
              style={{ width: `${Math.min(100, confidence * 100)}%`, background: confidenceColor(confidence) }}
            />
          </span>
          <span className="mono text-[10.5px] text-ink-3">{pct(confidence)}</span>
        </div>
      )}

      <Handle type="source" position={Position.Bottom} style={{ background: "var(--rule-2)", border: "none" }} />
    </div>
  );
}

const nodeTypes = { assetNode: AssetNode };

function layout(nodes: Node[], edges: Edge[], direction: "TB" | "LR" = "TB") {
  const graph = new dagre.graphlib.Graph();
  graph.setDefaultEdgeLabel(() => ({}));
  graph.setGraph({ rankdir: direction, nodesep: 28, ranksep: 44 });

  nodes.forEach((node) => graph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach((edge) => graph.setEdge(edge.source, edge.target));
  dagre.layout(graph);

  const horizontal = direction === "LR";
  return {
    nodes: nodes.map((node) => {
      const position = graph.node(node.id);
      return {
        ...node,
        targetPosition: horizontal ? Position.Left : Position.Top,
        sourcePosition: horizontal ? Position.Right : Position.Bottom,
        position: { x: position.x - NODE_WIDTH / 2, y: position.y - NODE_HEIGHT / 2 },
      };
    }),
    edges,
  };
}

function edgeStyle(id: string, source: string, target: string): Edge {
  return {
    id,
    source,
    target,
    type: "smoothstep",
    markerEnd: { type: MarkerType.ArrowClosed, color: "var(--rule-2)" },
    style: { stroke: "var(--rule-2)", strokeWidth: 1.5 },
  };
}

export function AssetDiscoveryGraph({ assetId, height = 380 }: { assetId: string; height?: number }) {
  const router = useRouter();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const onConnect = useCallback((params: Connection) => setEdges((eds) => addEdge(params, eds)), [setEdges]);

  const goToAsset = useCallback(
    (targetId: string) => {
      router.push(`/surface/${targetId}`);
    },
    [router],
  );

  useEffect(() => {
    if (!assetId) return;
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const assets: Asset[] = await getAssetPath(assetId);
        if (cancelled) return;

        if (assets.length === 0) {
          setNodes([]);
          setEdges([]);
          return;
        }

        const graphNodes: Node[] = assets.map((asset) => ({
          id: asset.id,
          type: "assetNode",
          data: {
            label: asset.value,
            type: asset.asset_type,
            confidence: asset.ownership_confidence,
            isTarget: asset.id === assetId,
            assetId: asset.id,
            onNodeClick: goToAsset,
          } satisfies CustomNodeData,
          position: { x: 0, y: 0 },
        }));

        // Prefer the real parent links…
        const graphEdges: Edge[] = [];
        assets.forEach((asset) => {
          if (!asset.parent_id) return;
          if (!assets.some((candidate) => candidate.id === asset.parent_id)) return;
          graphEdges.push(edgeStyle(`e${asset.parent_id}-${asset.id}`, asset.parent_id, asset.id));
        });

        // …and fall back to chaining the path in order when the endpoint returns
        // a linear ancestry without parent_id set on each hop.
        if (graphEdges.length === 0 && assets.length > 1) {
          for (let i = 0; i < assets.length - 1; i += 1) {
            graphEdges.push(edgeStyle(`e${assets[i].id}-${assets[i + 1].id}`, assets[i].id, assets[i + 1].id));
          }
        }

        const laidOut = layout(graphNodes, graphEdges);
        setNodes(laidOut.nodes);
        setEdges(laidOut.edges);
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [assetId, reloadKey, setNodes, setEdges, goToAsset]);

  const frame = useMemo(() => ({ height }), [height]);

  if (loading) return <LoadingBlock label="Tracing discovery path" />;
  if (error) return <ErrorState error={error} onRetry={() => setReloadKey((key) => key + 1)} />;
  if (nodes.length === 0) {
    return (
      <EmptyState
        icon="seed"
        title="No discovery path"
        description="This asset has no recorded lineage — it was either a seed itself or imported directly."
      />
    );
  }

  return (
    <div className="rounded-lg border border-rule bg-surface-2 overflow-hidden" style={frame}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        fitView
        proOptions={{ hideAttribution: true }}
        minZoom={0.2}
      >
        <Controls showInteractive={false} className="!shadow-none" />
        <Background color="var(--rule-2)" gap={16} size={1} />
      </ReactFlow>
    </div>
  );
}

export default AssetDiscoveryGraph;
