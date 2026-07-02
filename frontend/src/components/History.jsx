import { useState } from "react";
import { FaHistory, FaChevronDown, FaChevronRight } from "react-icons/fa";

export default function History({ history = [], onSelect }) {
  const [openIndex, setOpenIndex] = useState(null);

  if (history.length === 0) {
    return (
      <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
        <div className="flex items-center gap-2 text-slate-500 mb-1">
          <FaHistory />
          <h2 className="text-lg font-bold text-slate-300">
            Recent Translations
          </h2>
        </div>
        <p className="text-sm text-slate-500 mt-2">
          Your translated queries will show up here.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
      <div className="flex items-center gap-2 mb-5">
        <FaHistory className="text-cyan-400" />
        <h2 className="text-lg font-bold text-slate-100">
          Recent Translations
        </h2>
        <span className="text-xs font-mono text-slate-500 ml-auto">
          {history.length}
        </span>
      </div>

      <div className="space-y-2">
        {history.map((entry, index) => {
          const isOpen = openIndex === index;
          const succeeded = entry.result?.success !== false;

          return (
            <div
              key={entry.timestamp ?? index}
              className="border border-slate-800 rounded-xl overflow-hidden"
            >
              <button
                type="button"
                onClick={() => setOpenIndex(isOpen ? null : index)}
                className="w-full flex items-center gap-3 px-4 py-3 bg-slate-950/60 hover:bg-slate-950 transition-colors text-left focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              >
                {isOpen ? (
                  <FaChevronDown className="text-slate-500 shrink-0" />
                ) : (
                  <FaChevronRight className="text-slate-500 shrink-0" />
                )}

                <span
                  className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                    succeeded ? "bg-emerald-400" : "bg-rose-500"
                  }`}
                />

                <span className="text-sm text-slate-300 truncate flex-1">
                  {entry.query}
                </span>

                {entry.timestamp && (
                  <span className="text-xs font-mono text-slate-600 shrink-0">
                    {entry.timestamp}
                  </span>
                )}
              </button>

              {isOpen && (
                <div className="px-4 py-3 bg-slate-900/40 border-t border-slate-800 flex items-center justify-between gap-3">
                  <p className="text-xs text-slate-500 font-mono">
                    {succeeded
                      ? `run · ${entry.result?.run_id ?? "n/a"}`
                      : entry.result?.error ?? "Translation failed"}
                  </p>

                  {onSelect && (
                    <button
                      type="button"
                      onClick={() => onSelect(entry)}
                      className="text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors shrink-0"
                    >
                      View again
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}