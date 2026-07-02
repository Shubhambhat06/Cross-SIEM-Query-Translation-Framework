const accentMap = {
  cyan: { bar: "bg-cyan-400", text: "text-cyan-400", ring: "border-cyan-500/20" },
  emerald: { bar: "bg-emerald-400", text: "text-emerald-400", ring: "border-emerald-500/20" },
  violet: { bar: "bg-violet-400", text: "text-violet-400", ring: "border-violet-500/20" },
  amber: { bar: "bg-amber-400", text: "text-amber-400", ring: "border-amber-500/20" },
};

export default function BenchmarkCard({
  platform,
  accuracy = 0,
  latencyMs = 0,
  queries = 0,
  accent = "cyan",
}) {
  const colors = accentMap[accent] || accentMap.cyan;

  return (
    <div
      className={`bg-slate-900/70 backdrop-blur-xl border ${colors.ring} rounded-2xl p-5 shadow-[0_0_20px_rgba(6,182,212,0.08)]`}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-bold text-slate-100">{platform}</h3>
        <span className={`text-sm font-mono ${colors.text}`}>
          {accuracy}%
        </span>
      </div>

      <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden mb-5">
        <div
          className={`h-full ${colors.bar} rounded-full transition-all duration-500`}
          style={{ width: `${Math.min(accuracy, 100)}%` }}
        />
      </div>

      <div className="flex items-center justify-between text-xs">
        <div>
          <p className="text-slate-500 mb-0.5">Avg. latency</p>
          <p className="font-mono text-slate-300">{latencyMs}ms</p>
        </div>
        <div className="text-right">
          <p className="text-slate-500 mb-0.5">Queries run</p>
          <p className="font-mono text-slate-300">{queries.toLocaleString()}</p>
        </div>
      </div>
    </div>
  );
}