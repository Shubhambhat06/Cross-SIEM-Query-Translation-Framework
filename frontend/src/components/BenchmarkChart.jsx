import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  Cell,
} from "recharts";

const data = [
  { name: "Splunk", accuracy: 88, color: "#22d3ee" },
  { name: "Elastic", accuracy: 85, color: "#34d399" },
  { name: "Sentinel", accuracy: 82, color: "#a78bfa" },
  { name: "Wazuh", accuracy: 90, color: "#fbbf24" },
];

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;

  return (
    <div className="bg-slate-900 border border-cyan-500/30 rounded-lg px-3 py-2 shadow-lg">
      <p className="text-slate-300 text-xs font-semibold mb-0.5">{label}</p>
      <p className="text-cyan-400 font-mono text-sm">
        {payload[0].value}% accuracy
      </p>
    </div>
  );
}

export default function BenchmarkChart() {
  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <p className="text-xs font-semibold tracking-widest text-cyan-500/70 uppercase mb-1">
        Benchmarks
      </p>
      <h2 className="text-2xl font-bold text-slate-100 mb-6">
        Translation Accuracy by Platform
      </h2>

      <div style={{ height: 300 }}>
        <ResponsiveContainer>
          <BarChart data={data} barSize={48}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#1e293b"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              tick={{ fill: "#94a3b8", fontSize: 13 }}
              axisLine={{ stroke: "#334155" }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "#64748b", fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              domain={[0, 100]}
              unit="%"
            />
            <Tooltip
              cursor={{ fill: "rgba(6,182,212,0.06)" }}
              content={<CustomTooltip />}
            />
            <Bar dataKey="accuracy" radius={[6, 6, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}