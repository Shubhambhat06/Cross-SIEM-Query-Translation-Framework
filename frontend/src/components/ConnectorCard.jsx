import { FaDatabase } from "react-icons/fa";

export default function ConnectorCard({ name, connected, lastSync }) {
  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 hover:border-cyan-500/30 rounded-xl p-5 transition-colors">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              connected
                ? "bg-cyan-500/10 text-cyan-400"
                : "bg-slate-800 text-slate-500"
            }`}
          >
            <FaDatabase />
          </div>

          <div>
            <h3 className="font-semibold text-slate-100 capitalize">
              {name}
            </h3>
            <p className="text-xs text-slate-500">
              {lastSync ? `Synced ${lastSync}` : "No sync recorded"}
            </p>
          </div>
        </div>

        <span className="relative flex h-2.5 w-2.5 mt-1.5">
          {connected && (
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          )}
          <span
            className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
              connected ? "bg-emerald-400" : "bg-rose-500"
            }`}
          />
        </span>
      </div>

      <div
        className={`mt-4 text-xs font-medium inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full ${
          connected
            ? "bg-emerald-500/10 text-emerald-400"
            : "bg-rose-500/10 text-rose-400"
        }`}
      >
        {connected ? "Connected" : "Disconnected"}
      </div>
    </div>
  );
}