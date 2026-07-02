import { useState } from "react";
import ConnectorCard from "./ConnectorCard";

export default function ConnectorStatus() {
  const [connectors] = useState([
    { name: "elastic", connected: true, lastSync: "2m ago" },
    { name: "splunk", connected: false, lastSync: "3h ago" },
    { name: "wazuh", connected: true, lastSync: "just now" },
  ]);

  const connectedCount = connectors.filter((c) => c.connected).length;

  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <p className="text-xs font-semibold tracking-widest text-cyan-500/70 uppercase mb-1">
            Data Sources
          </p>
          <h2 className="text-2xl font-bold text-slate-100">Connectors</h2>
        </div>

        <span className="text-sm font-mono text-slate-400">
          {connectedCount}/{connectors.length} online
        </span>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        {connectors.map((connector) => (
          <ConnectorCard key={connector.name} {...connector} />
        ))}
      </div>
    </div>
  );
}