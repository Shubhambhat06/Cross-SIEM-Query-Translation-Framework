import { FaExclamationTriangle } from "react-icons/fa";
import QueryCard from "./QueryCard";

export default function TranslationResults({ result }) {
  if (!result) return null;

  if (!result.success) {
    return (
      <div className="bg-rose-950/30 border border-rose-500/30 rounded-2xl p-6">
        <div className="flex items-center gap-2 text-rose-400 mb-2">
          <FaExclamationTriangle />
          <h3 className="font-bold">Translation failed</h3>
        </div>
        <pre className="text-rose-300/90 text-sm font-mono whitespace-pre-wrap">
          {result.error || "An unknown error occurred."}
        </pre>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-slate-100">
          Translation Results
        </h2>
        {result.run_id && (
          <span className="text-xs font-mono text-slate-500">
            run · {result.run_id}
          </span>
        )}
      </div>

      {result.ir && (
        <div className="mb-6">
          <p className="text-xs uppercase tracking-wide text-slate-500 mb-2">
            Intermediate Representation
          </p>
          <pre className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(result.ir, null, 2)}
          </pre>
        </div>
      )}

      <div>
        <p className="text-xs uppercase tracking-wide text-slate-500 mb-3">
          Platform Translations
        </p>

        <div className="grid md:grid-cols-2 gap-4">
          {Object.entries(result.translations || {}).map(
            ([platform, query]) => (
              <QueryCard key={platform} platform={platform} query={query} />
            )
          )}
        </div>
      </div>
    </div>
  );
}