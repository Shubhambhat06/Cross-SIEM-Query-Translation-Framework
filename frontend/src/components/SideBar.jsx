import {
  FaShieldAlt,
  FaBug,
  FaChartBar,
  FaDatabase,
  FaUpload,
  FaExchangeAlt,
  FaTerminal,
} from "react-icons/fa";

const menu = [
  { icon: <FaShieldAlt />, name: "Dashboard" },
  { icon: <FaExchangeAlt />, name: "Translator" },
  { icon: <FaBug />, name: "ATT&CK Mapping" },
  { icon: <FaChartBar />, name: "Benchmarks" },
  { icon: <FaDatabase />, name: "Connectors" },
  { icon: <FaUpload />, name: "Upload" },
  { icon: <FaTerminal />, name: "Executions" },
];

export default function Sidebar({ active = "Dashboard", onSelect }) {
  return (
    <div className="w-72 h-screen bg-slate-950 border-r border-slate-800 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-slate-800">
        <h1 className="text-3xl font-bold text-cyan-400">NL-SIEM</h1>
        <p className="text-slate-400 text-sm mt-2">
          Multi-Agent SIEM Translator
        </p>
      </div>

      {/* Menu */}
      <nav className="flex-1 p-4 space-y-1">
        {menu.map((item) => {
          const isActive = item.name === active;

          return (
            <button
              key={item.name}
              type="button"
              onClick={() => onSelect?.(item.name)}
              aria-current={isActive ? "page" : undefined}
              className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                  : "text-slate-300 hover:bg-slate-800 hover:text-cyan-400"
              }`}
            >
              <span
                className={`text-lg ${
                  isActive ? "text-cyan-400" : "text-slate-500"
                }`}
              >
                {item.icon}
              </span>
              <span className="font-medium">{item.name}</span>

              {isActive && (
                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-5 border-t border-slate-800">
        <div className="bg-slate-900 rounded-xl p-4">
          <p className="text-sm text-slate-400">System Status</p>

          <div className="flex items-center gap-2 mt-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
            </span>
            <span className="text-emerald-400 text-sm">Backend Online</span>
          </div>
        </div>
      </div>
    </div>
  );
}