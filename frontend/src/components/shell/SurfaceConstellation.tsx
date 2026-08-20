"use client";

import { useMemo } from "react";

/**
 * Decorative sign-in visual: one seed expanding outward into a discovered
 * surface, with a few nodes at risk. Deterministic — no randomness, so it looks
 * identical on the server and the client.
 */
export function SurfaceConstellation() {
  const paths = useMemo(build, []);

  return (
    <svg
      viewBox="0 0 840 640"
      className="absolute left-5 top-10 w-[840px] h-[640px] opacity-90 pointer-events-none"
      fill="none"
      aria-hidden="true"
    >
      <path d={paths.edges} stroke="oklch(0.33 0.015 265)" strokeWidth={1} />
      <path d={paths.hotEdges} stroke="oklch(0.45 0.12 22)" strokeWidth={1} />
      <path d={paths.nodes} fill="oklch(0.30 0.02 265)" stroke="oklch(0.42 0.02 265)" strokeWidth={1.4} />
      <path d={paths.hotNodes} fill="oklch(0.55 0.19 22)" stroke="oklch(0.70 0.17 22)" strokeWidth={1.4} />
      <circle cx={96} cy={300} r={8} fill="oklch(0.505 0.152 264)" stroke="oklch(0.66 0.14 264)" strokeWidth={1.4} />
    </svg>
  );
}

const SEED = { x: 96, y: 300 };
const RINGS = [
  { r: 150, n: 5, size: 5 },
  { r: 280, n: 9, size: 4 },
  { r: 400, n: 13, size: 3 },
];
const HOT: Record<number, number[]> = { 1: [2, 6], 2: [4, 9] };

function circle(x: number, y: number, r: number) {
  return `M${(x - r).toFixed(1)} ${y.toFixed(1)}a${r} ${r} 0 1 0 ${r * 2} 0a${r} ${r} 0 1 0 ${-r * 2} 0`;
}

function build() {
  const out = { edges: "", hotEdges: "", nodes: "", hotNodes: "" };
  let previous: Array<{ x: number; y: number }> = [SEED];

  RINGS.forEach((ring, ringIndex) => {
    const layer: Array<{ x: number; y: number }> = [];
    for (let i = 0; i < ring.n; i += 1) {
      const spread = 1.05;
      const angle = -spread / 2 + (i / (ring.n - 1)) * spread + Math.sin(i * 1.7 + ringIndex) * 0.035;
      const node = {
        x: SEED.x + Math.cos(angle) * ring.r,
        y: SEED.y + Math.sin(angle) * ring.r * 1.45,
      };
      const hot = (HOT[ringIndex] ?? []).includes(i);
      layer.push(node);

      const from = previous[Math.min(previous.length - 1, Math.floor((i / ring.n) * previous.length))];
      out[hot ? "hotEdges" : "edges"] +=
        `M${from.x.toFixed(1)} ${from.y.toFixed(1)}L${node.x.toFixed(1)} ${node.y.toFixed(1)}`;
      out[hot ? "hotNodes" : "nodes"] += circle(node.x, node.y, ring.size);
    }
    previous = layer;
  });

  return out;
}
