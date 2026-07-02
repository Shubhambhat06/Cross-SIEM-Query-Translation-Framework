import { FaBell, FaUserCircle } from "react-icons/fa";

export default function Navbar({ title = "Dashboard", subtitle }) {
  return (
    <header className="sticky top-0 z-10 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800 px-8 py-4 flex items-center justify-between">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{title}</h1>
        {subtitle && (
          <p className="text-sm text-slate-500 mt-0.5">{subtitle}</p>
        )}
      </div>

      <div className="flex items-center gap-5">
        <div className="hidden sm:flex items-center gap-2 text-xs font-medium text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-full">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
          </span>
          Backend Online
        </div>

        <button
          type="button"
          aria-label="Notifications"
          className="text-slate-400 hover:text-cyan-400 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500/50 rounded-lg p-1.5"
        >
          <FaBell className="text-lg" />
        </button>

        <button
          type="button"
          aria-label="Account"
          className="text-slate-400 hover:text-cyan-400 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500/50 rounded-full"
        >
          <FaUserCircle className="text-2xl" />
        </button>
      </div>
    </header>
  );
}