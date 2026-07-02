import { Prism as SyntaxHighlighter }
from "react-syntax-highlighter";

export default function QueryCard({
  platform,
  query,
}) {
  return (
    <div className="bg-slate-800 rounded-xl p-4">
      <h3 className="text-cyan-400 mb-4">
        {platform.toUpperCase()}
      </h3>

      <SyntaxHighlighter language="sql">
        {query}
      </SyntaxHighlighter>
    </div>
  );
}