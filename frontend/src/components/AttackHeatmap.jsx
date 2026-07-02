const tactics = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

const slugify = (label) => label.toLowerCase().replace(/\s+/g, "-");

export default function AttackHeatmap({ currentTactic }) {
  const currentIndex = tactics.findIndex(
    (tactic) => slugify(tactic) === currentTactic?.toLowerCase()
  );

  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <p className="text-xs font-semibold tracking-widest text-cyan-500/70 uppercase mb-1">
            MITRE ATT&amp;CK
          </p>
          <h2 className="text-2xl font-bold text-slate-100">
            Kill Chain Heatmap
          </h2>
        </div>

        {currentIndex >= 0 && (
          <div className="text-right">
            <p className="text-xs text-slate-500">Stage</p>
            <p className="text-sm font-mono text-cyan-400">
              {String(currentIndex + 1).padStart(2, "0")} / {String(tactics.length).padStart(2, "0")}
            </p>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {tactics.map((tactic, index) => {
          const isActive = index === currentIndex;
          const isVisited = currentIndex >= 0 && index < currentIndex;

          return (
            <div
              key={tactic}
              className={`relative rounded-xl p-4 text-center border transition-all duration-300 ${
                isActive
                  ? "bg-cyan-600/90 border-cyan-400 shadow-lg shadow-cyan-500/30 scale-[1.03]"
                  : isVisited
                  ? "bg-emerald-950/40 border-emerald-500/30"
                  : "bg-slate-950/60 border-slate-800 hover:border-slate-600"
              }`}
            >
              {isActive && (
                <span className="absolute -top-1.5 -right-1.5 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-400" />
                </span>
              )}

              <div
                className={`text-[10px] font-mono mb-1.5 ${
                  isActive
                    ? "text-cyan-100/80"
                    : isVisited
                    ? "text-emerald-400/70"
                    : "text-slate-600"
                }`}
              >
                {String(index + 1).padStart(2, "0")}
              </div>

              <div
                className={`text-sm font-semibold leading-tight ${
                  isActive
                    ? "text-white"
                    : isVisited
                    ? "text-emerald-300"
                    : "text-slate-400"
                }`}
              >
                {tactic}
              </div>
            </div>
          );
        })}
      </div>

      {currentIndex === -1 && (
        <p className="mt-5 text-sm text-slate-500">
          No tactic mapped yet — run a translation to see it plotted on the chain.
        </p>
      )}
    </div>
  );
}