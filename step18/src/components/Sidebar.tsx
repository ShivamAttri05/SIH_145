import { NavLink } from "react-router-dom";

const navigation = [
  { name: "Overview", path: "/", icon: "▣" },
  { name: "Alerts", path: "/alerts", icon: "⚠" },
  { name: "Analytics", path: "/analytics", icon: "📊" },
  { name: "Flows", path: "/flows", icon: "⇄" },
  { name: "Topology", path: "/topology", icon: "⌘" },
  { name: "System Health", path: "/health", icon: "⚙" },
];

export default function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-[#2a3038] bg-[#111418]">
      {/* Brand */}

      <div className="border-b border-[#2a3038] px-6 py-5">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-red-500/20 bg-red-500/10 text-lg">
            🛡
          </div>

          <div>
            <h1 className="font-bold tracking-wide text-[#f1f5f9]">
              SIH CYBER SOC
            </h1>

            <p className="mt-0.5 text-[11px] tracking-wide text-[#64748b]">
              THREAT DETECTION PLATFORM
            </p>
          </div>
        </div>
      </div>

      {/* Navigation */}

      <nav className="flex-1 space-y-1 px-3 py-5">
        <p className="mb-3 px-4 text-[10px] font-semibold uppercase tracking-[0.15em] text-[#4f5864]">
          Monitoring
        </p>

        {navigation.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            className={({ isActive }) =>
              `group relative flex items-center gap-3 rounded-lg px-4 py-3 text-sm font-medium transition ${
                isActive
                  ? "bg-red-500/10 text-red-400"
                  : "text-[#8b95a3] hover:bg-[#1b1f26] hover:text-[#f1f5f9]"
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span className="absolute left-0 top-2 h-8 w-0.5 rounded-r-full bg-red-500" />
                )}

                <span
                  className={`flex w-5 justify-center text-sm transition ${
                    isActive
                      ? "text-red-400"
                      : "text-[#64748b] group-hover:text-[#94a3b8]"
                  }`}
                >
                  {item.icon}
                </span>

                <span>{item.name}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Engine Status */}

      <div className="border-t border-[#2a3038] p-4">
        <div className="rounded-lg border border-[#252b33] bg-[#181c21] p-4">
          <div className="flex items-center gap-3">
            <div className="relative flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/10">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />

              <span className="absolute h-2.5 w-2.5 animate-ping rounded-full bg-emerald-400 opacity-20" />
            </div>

            <div>
              <p className="text-xs font-semibold text-[#d7dde5]">
                Detection Engine
              </p>

              <p className="mt-0.5 text-[11px] text-emerald-400">
                Operational
              </p>
            </div>
          </div>

          <div className="mt-3 border-t border-[#252b33] pt-3">
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-[#64748b]">
                Mode
              </span>

              <span className="font-medium text-[#94a3b8]">
                Passive
              </span>
            </div>

            <div className="mt-1.5 flex items-center justify-between text-[10px]">
              <span className="text-[#64748b]">
                Pipeline
              </span>

              <span className="font-medium text-[#94a3b8]">
                PCAP Replay
              </span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}