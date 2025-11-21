"use client";

import React, { useCallback, useEffect, useState } from 'react';
import {
    ReactFlow,
    MiniMap,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    addEdge,
    Position,
    Node,
    Edge,
    Connection,
    Handle,
    NodeProps,
    MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';

interface Asset {
    id: string;
    asset_type: string;
    value: string;
    parent_id?: string;
    seed_id?: string;
    confidence: number;
    sources?: string[];
    metadata?: Record<string, unknown>;
}

interface AssetDiscoveryGraphProps {
    assetId: string;
}

interface CustomNodeData extends Record<string, unknown> {
    label: string;
    type: string;
    confidence?: number;
    isTarget: boolean;
}

const nodeWidth = 220;
const nodeHeight = 80;

// Custom Node Component
const CustomAssetNode = ({ data }: NodeProps<Node<CustomNodeData>>) => {
    const { label, type, confidence, isTarget } = data;

    let icon = "📄";
    const bgColor = "bg-white";
    let borderColor = "border-gray-200";
    
    if (isTarget) {
        borderColor = "border-blue-500 ring-2 ring-blue-200";
    }

    switch (type) {
        case 'domain':
            icon = "🌐";
            break;
        case 'ip':
            icon = "🖥️";
            break;
        case 'organization':
            icon = "🏢";
            break;
        case 'certificate':
            icon = "🔒";
            break;
        case 'asn':
            icon = "🔌";
            break;
    }

    return (
        <div className={`px-4 py-3 shadow-md rounded-lg border-2 ${borderColor} ${bgColor} min-w-[200px]`}>
            <Handle type="target" position={Position.Top} className="!bg-gray-400" />
            
            <div className="flex items-start gap-3">
                <div className="text-2xl">{icon}</div>
                <div className="flex-1 overflow-hidden">
                    <div className="text-xs font-bold uppercase text-gray-500 tracking-wider mb-0.5">{type}</div>
                    <div className="text-sm font-medium text-gray-900 truncate" title={label as string}>
                        {label}
                    </div>
                </div>
            </div>
            
            {confidence !== undefined && (
                <div className="mt-2 flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div 
                            className={`h-full rounded-full ${confidence >= 0.8 ? 'bg-green-500' : confidence >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'}`}
                            style={{ width: `${confidence * 100}%` }}
                        />
                    </div>
                    <span className="text-xs text-gray-500 font-mono">{(confidence * 100).toFixed(0)}%</span>
                </div>
            )}

            <Handle type="source" position={Position.Bottom} className="!bg-gray-400" />
        </div>
    );
};

const nodeTypes = {
    assetNode: CustomAssetNode,
};

const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'TB') => {
    const dagreGraph = new dagre.graphlib.Graph();
    dagreGraph.setDefaultEdgeLabel(() => ({}));

    const isHorizontal = direction === 'LR';
    dagreGraph.setGraph({ rankdir: direction });

    nodes.forEach((node) => {
        dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
    });

    edges.forEach((edge) => {
        dagreGraph.setEdge(edge.source, edge.target);
    });

    dagre.layout(dagreGraph);

    const newNodes = nodes.map((node) => {
        const nodeWithPosition = dagreGraph.node(node.id);
        const newNode = {
            ...node,
            targetPosition: isHorizontal ? Position.Left : Position.Top,
            sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
            position: {
                x: nodeWithPosition.x - nodeWidth / 2,
                y: nodeWithPosition.y - nodeHeight / 2,
            },
        };

        return newNode;
    });

    return { nodes: newNodes, edges };
};

export default function AssetDiscoveryGraph({ assetId }: AssetDiscoveryGraphProps) {
    const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const onConnect = useCallback(
        (params: Connection) => setEdges((eds) => addEdge(params, eds)),
        [setEdges],
    );

    useEffect(() => {
        if (!assetId) return;

        const fetchPath = async () => {
            setLoading(true);
            setError(null);
            try {
                const response = await fetch(`http://localhost:8000/api/assets/${assetId}/path`);
                if (!response.ok) {
                    throw new Error('Failed to fetch asset path');
                }
                const assets: Asset[] = await response.json();

                if (assets.length === 0) {
                    setNodes([]);
                    setEdges([]);
                    return;
                }

                // Map assets to nodes
                const initialNodes: Node[] = assets.map((asset) => ({
                    id: asset.id,
                    type: 'assetNode',
                    data: { 
                        label: asset.value,
                        type: asset.asset_type,
                        confidence: asset.confidence,
                        isTarget: asset.id === assetId,
                        metadata: asset.metadata
                    },
                    position: { x: 0, y: 0 },
                }));

                // Create edges based on parent_id
                // Since the list is a path (linear or tree up to root), we can just link parent -> child
                const initialEdges: Edge[] = [];
                
                assets.forEach((asset) => {
                    if (asset.parent_id) {
                        // Check if parent exists in the list (it should)
                        const parentExists = assets.some(a => a.id === asset.parent_id);
                        if (parentExists) {
                            initialEdges.push({
                                id: `e${asset.parent_id}-${asset.id}`,
                                source: asset.parent_id,
                                target: asset.id,
                                type: 'smoothstep',
                                animated: true,
                                markerEnd: {
                                    type: MarkerType.ArrowClosed,
                                },
                                style: { stroke: '#9ca3af', strokeWidth: 2 },
                            });
                        }
                    }
                });

                // If strictly linear list without explicit parent_id links working (fallback):
                if (initialEdges.length === 0 && assets.length > 1) {
                     for (let i = 0; i < assets.length - 1; i++) {
                        initialEdges.push({
                            id: `e${assets[i].id}-${assets[i+1].id}`,
                            source: assets[i].id,
                            target: assets[i+1].id,
                            type: 'smoothstep',
                            animated: true,
                            markerEnd: {
                                type: MarkerType.ArrowClosed,
                            },
                            style: { stroke: '#9ca3af', strokeWidth: 2 },
                        });
                     }
                }

                const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
                    initialNodes,
                    initialEdges,
                    'TB' // Top to Bottom layout
                );

                setNodes(layoutedNodes);
                setEdges(layoutedEdges);
            } catch (error) {
                console.error('Error fetching asset path:', error);
                setError('Failed to load discovery path.');
            } finally {
                setLoading(false);
            }
        };

        fetchPath();
    }, [assetId, setNodes, setEdges]);

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center h-[400px] bg-gray-50 rounded-lg border border-dashed border-gray-300">
                <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mb-4"></div>
                <p className="text-sm text-gray-500">Tracing discovery path...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex items-center justify-center h-[400px] bg-red-50 rounded-lg border border-red-100 text-red-500">
                {error}
            </div>
        );
    }

    if (nodes.length === 0) {
        return (
            <div className="flex items-center justify-center h-[400px] bg-gray-50 rounded-lg border border-dashed border-gray-300 text-gray-400">
                No discovery path information available
            </div>
        );
    }

    return (
        <div className="w-full h-[500px] bg-gray-50 rounded-lg border border-gray-200 shadow-inner overflow-hidden">
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                nodeTypes={nodeTypes}
                fitView
                attributionPosition="bottom-right"
            >
                <Controls className="!bg-white !border-gray-200 !shadow-sm" />
                <MiniMap 
                    className="!bg-white !border-gray-200 !shadow-sm" 
                    nodeColor={() => '#e2e8f0'}
                    maskColor="rgba(248, 250, 252, 0.6)"
                />
                <Background color="#94a3b8" gap={16} size={1} />
            </ReactFlow>
        </div>
    );
}
