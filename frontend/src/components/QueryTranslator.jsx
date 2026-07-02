import { useState } from "react";
import { FaTerminal, FaSpinner, FaExclamationCircle } from "react-icons/fa";
import api from "../services/api";
import TranslationResults from "./TranslationResults";
import AttackMapping from "./AttackMapping";
import AttackHeatmap from "./AttackHeatmap";
import History from "./History";

export default function QueryTranslator() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const translate = async () => {
    if (!query.trim() || loading) return;

    setLoading(true);
    setError(null);

    try {
      const res = await api.post("/translate", { query });
      setResult(res.data);
      setHistory((prev) => [
        {
          query,
          result: res.data,
          timestamp: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          }),
        },
        ...prev,
      ]);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          "Couldn't reach the translation service. Try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") translate();
  };

  const revisit = (entry) => {
    setQuery(entry.query);
    setResult(entry.result);
    setError(null);
  };

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs font-semibold tracking-widest text-cyan-500/70 uppercase mb-1">
          Translator
        </p>
        <h2 className="text-2xl font-bold text-slate-100">
          Translate a Query
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Describe what you're looking for in plain language — it'll be
          mapped to ATT&amp;CK and translated across every connected
          platform.
        </p>
      </div>

      <div className="bg-slate-900/70 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(6,182,212,0.12)]">
        <div className="flex items-center gap-2 text-slate-500 text-xs font-mono mb-2">
          <FaTerminal className="text-cyan-500" />
          <span>nl-query</span>
        </div>

        <textarea
          rows={4}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="e.g. show failed logins followed by privilege escalation on domain controllers in the last 24 hours"
          className="w-full bg-slate-950/60 border border-slate-800 rounded-xl p-4 text-slate-200 font-mono text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 resize-none"
        />

        <div className="flex items-center justify-between mt-4">
          <span className="text-xs text-slate-600">⌘ / Ctrl + Enter to run</span>

          <button
            type="button"
            onClick={translate}
            disabled={loading || !query.trim()}
            className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-white font-semibold px-5 py-2.5 rounded-xl transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            {loading ? (
              <>
                <FaSpinner className="animate-spin" /> Translating…
              </>
            ) : (
              "Translate"
            )}
          </button>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-rose-400 text-sm mt-4 bg-rose-950/30 border border-rose-500/30 rounded-lg px-4 py-3">
            <FaExclamationCircle />
            {error}
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-6">
          <TranslationResults result={result} />
          <AttackMapping attck={result.ir} />
          <AttackHeatmap currentTactic={result.ir?.tactic} />
        </div>
      )}

      <History history={history} onSelect={revisit} />
    </div>
  );
}