import {
  FaExchangeAlt,
  FaLayerGroup,
  FaBullseye,
  FaDatabase,
} from "react-icons/fa";

const cards = [
  {
    title: "Translations",
    value: "1,284",
    icon: <FaExchangeAlt />,
    accent: "text-cyan-400 bg-cyan-500/10",
  },
  {
    title: "Platforms",
    value: "5",
    icon: <FaLayerGroup />,
    accent: "text-violet-400 bg-violet-500/10",
  },
  {
    title: "Coverage",
    value: "87%",
    icon: <FaBullseye />,
    accent: "text-emerald-400 bg-emerald-500/10",
  },
  {
    title: "Connectors",
    value: "2/5",
    icon: <FaDatabase />,
    accent: "text-amber-400 bg-amber-500/10",
  },
];

export default function StatCards() {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
      {cards.map((c) => (
        <div
          key={c.title}
          className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 hover:border-cyan-500/30 transition-colors"
        >
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center mb-4 ${c.accent}`}
          >
            {c.icon}
          </div>

          <h3 className="text-slate-500 text-sm">{c.title}</h3>
          <p className="text-3xl font-bold text-slate-100 mt-1 font-mono">
            {c.value}
          </p>
        </div>
      ))}
    </div>
  );
}