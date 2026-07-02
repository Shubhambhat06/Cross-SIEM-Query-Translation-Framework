import StatCards from "../components/StatCards";
import Sidebar from "../components/SideBar";
import QueryTranslator from "../components/QueryTranslator";
import AttackMapping from "../components/AttackMapping";
import ConnectorStatus from "../components/ConnectorStatus";
import PipelineGraph from "../components/PipelineGraph";
import BenchmarkChart from "../components/BenchmarkChart";
export default function Dashboard() {
  return (
    <div className="flex min-h-screen bg-slate-900 text-white">
      <Sidebar />

      <main className="flex-1 p-8 overflow-y-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-4xl font-bold text-cyan-400">
              NL-SIEM Dashboard
            </h1>

            <p className="text-slate-400 mt-2">
              Multi-Agent SIEM Query Translation Platform
            </p>
          </div>

          {/* Stats */}
          <StatCards />

          {/* Connector Status */}
          <div className="mt-8">
            <ConnectorStatus />
          </div>

          {/* Translator */}
          <div className="mt-8">
            <QueryTranslator />
          </div>
        <div className="mt-8">
             < PipelineGraph />
        </div>
          <div className="mt-8">
  <BenchmarkChart />
</div>
          
        </div>
      </main>
    </div>
  );
}