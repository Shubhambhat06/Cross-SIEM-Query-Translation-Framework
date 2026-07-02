import ReactFlow, { Background, BackgroundVariant } from "reactflow";
import "reactflow/dist/style.css";

const nodeStyle = {
  background: "rgba(15, 23, 42, 0.9)",
  color: "#e2e8f0",
  border: "1px solid rgba(34, 211, 238, 0.35)",
  borderRadius: 12,
  padding: "10px 16px",
  fontSize: 13,
  fontWeight: 600,
  boxShadow: "0 0 20px rgba(6,182,212,0.12)",
};

const nodes = [
  {
    id: "1",
    position: { x: 0, y: 100 },
    data: { label: "Natural Language Query" },
    style: nodeStyle,
  },
  {
    id: "2",
    position: { x: 260, y: 100 },
    data: { label: "Parser Agent" },
    style: { ...nodeStyle, border: "1px solid rgba(52, 211, 153, 0.4)" },
  },
  {
    id: "3",
    position: { x: 520, y: 100 },
    data: { label: "Intermediate Representation" },
    style: { ...nodeStyle, border: "1px solid rgba(167, 139, 250, 0.4)" },
  },
  {
    id: "4",
    position: { x: 820, y: 100 },
    data: { label: "Platform Translators" },
    style: { ...nodeStyle, border: "1px solid rgba(251, 191, 36, 0.4)" },
  },
];

const edges = [
  { id: "e1", source: "1", target: "2", animated: true, style: { stroke: "#22d3ee" } },
  { id: "e2", source: "2", target: "3", animated: true, style: { stroke: "#22d3ee" } },
  { id: "e3", source: "3", target: "4", animated: true, style: { stroke: "#22d3ee" } },
];

export default function PipelineGraph() {
  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <p className="text-xs font-semibold tracking-widest text-cyan-500/70 uppercase mb-1">
        Architecture
      </p>
      <h2 className="text-2xl font-bold text-slate-100 mb-4">
        Translation Pipeline
      </h2>

      <div
        style={{ height: 300 }}
        className="rounded-xl overflow-hidden border border-slate-800"
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          zoomOnScroll={false}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={20}
            size={1}
            color="#1e293b"
            style={{ background: "#020617" }}
          />
        </ReactFlow>
      </div>
    </div>
  );
}