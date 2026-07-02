import { FaCrosshairs, FaFingerprint, FaLayerGroup } from "react-icons/fa";

export default function AttackMapping({ attck }) {
  if (!attck) return null;

  const fields = [
    {
      label: "Tactic",
      value: attck.tactic || "Unknown",
      icon: <FaCrosshairs />,
      accent: "text-cyan-400",
    },
    {
      label: "Technique",
      value: attck.technique_id || "Unknown",
      icon: <FaFingerprint />,
      accent: "text-emerald-400",
      mono: true,
    },
    {
      label: "Event Type",
      value: attck.event_type || "Unknown",
      icon: <FaLayerGroup />,
      accent: "text-violet-400",
    },
  ];

  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <p className="text-xs font-semibold tracking-widest text-cyan-500/70 uppercase mb-1">
        MITRE ATT&amp;CK
      </p>
      <h2 className="text-2xl font-bold text-slate-100 mb-6">
        Technique Mapping
      </h2>

      <div className="grid md:grid-cols-3 gap-4">
        {fields.map((field) => (
          <div
            key={field.label}
            className="bg-slate-950/60 border border-slate-800 p-5 rounded-xl"
          >
            <div className="flex items-center gap-2 text-slate-500 mb-3">
              <span className={field.accent}>{field.icon}</span>
              <p className="text-xs uppercase tracking-wide">{field.label}</p>
            </div>

            <p
              className={`text-xl font-bold ${field.accent} ${
                field.mono ? "font-mono" : ""
              }`}
            >
              {field.value}
            </p>
          </div>
        ))}
      </div>

      <div className="mt-4 bg-slate-950/60 border border-slate-800 p-5 rounded-xl">
        <p className="text-xs uppercase tracking-wide text-slate-500 mb-2">
          Original Query
        </p>

        <p className="text-slate-200 font-mono text-sm leading-relaxed">
          {attck.nl_query}
        </p>
      </div>
    </div>
  );
}