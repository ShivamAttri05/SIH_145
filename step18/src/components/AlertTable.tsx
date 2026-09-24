import type { DetectionEvent } from "../types/detection";

interface AlertTableProps {
  events?: DetectionEvent[];
  onSelectAlert?: (event: DetectionEvent) => void;
}

export default function AlertTable({
  events = [],
  onSelectAlert,
}: AlertTableProps) {
  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return {
          badge: "border-red-500/20 bg-red-500/10 text-red-400",
          dot: "bg-red-400",
        };

      case "HIGH":
        return {
          badge: "border-orange-500/20 bg-orange-500/10 text-orange-400",
          dot: "bg-orange-400",
        };

      case "MEDIUM":
        return {
          badge: "border-yellow-500/20 bg-yellow-500/10 text-yellow-400",
          dot: "bg-yellow-400",
        };

      default:
        return {
          badge: "border-emerald-500/20 bg-emerald-500/10 text-emerald-400",
          dot: "bg-emerald-400",
        };
    }
  };

  const getRiskStyle = (risk: number) => {
    if (risk >= 80) {
      return "text-red-400";
    }

    if (risk >= 60) {
      return "text-orange-400";
    }

    if (risk >= 30) {
      return "text-yellow-400";
    }

    return "text-emerald-400";
  };

  return (
    <div className="overflow-hidden rounded-xl border border-[#2a3038] bg-[#15181d]">
      {/* Header */}

      <div className="border-b border-[#2a3038] px-5 py-4">
        <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
          <div>
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-red-400" />

              <h2 className="text-lg font-semibold text-[#f1f5f9]">
                Live Threat Events
              </h2>
            </div>

            <p className="mt-1 text-sm text-[#64748b]">
              Real-time events received from the detection engine
            </p>
          </div>

          <div className="rounded-md border border-[#2a3038] bg-[#111418] px-3 py-1.5">
            <span className="text-xs font-medium text-[#94a3b8]">
              {events.length} events
            </span>
          </div>
        </div>
      </div>

      {/* Table */}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-[#252b33] bg-[#111418] text-[10px] uppercase tracking-[0.12em] text-[#64748b]">
            <tr>
              <th className="px-5 py-3.5 font-semibold">
                Source
              </th>

              <th className="px-5 py-3.5 font-semibold">
                Threat
              </th>

              <th className="px-5 py-3.5 font-semibold">
                Confidence
              </th>

              <th className="px-5 py-3.5 font-semibold">
                Risk
              </th>

              <th className="px-5 py-3.5 font-semibold">
                Severity
              </th>
            </tr>
          </thead>

          <tbody>
            {events.map((event, index) => {
              const severityStyle = getSeverityStyle(
                event.severity,
              );

              return (
                <tr
                  key={`${event.id ?? event.alert_id ?? event.flow_id}-${index}`}
                  onClick={() => onSelectAlert?.(event)}
                  className="group cursor-pointer border-t border-[#20252c] transition hover:bg-[#1b1f26]"
                >
                  {/* Source */}

                  <td className="px-5 py-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-md border border-[#2a3038] bg-[#111418] text-xs text-[#64748b]">
                        ⇢
                      </div>

                      <div>
                        <p className="font-mono text-xs font-medium text-[#d7dde5]">
                          {event.source_ip}
                        </p>

                        <p className="mt-0.5 font-mono text-[10px] text-[#4f5864]">
                          → {event.destination_ip}
                        </p>
                      </div>
                    </div>
                  </td>

                  {/* Threat */}

                  <td className="px-5 py-4">
                    <span className="font-medium text-[#d7dde5]">
                      {event.threat_class}
                    </span>
                  </td>

                  {/* Confidence */}

                  <td className="px-5 py-4">
                    <div className="flex items-center gap-3">
                      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[#2a3038]">
                        <div
                          className="h-full rounded-full bg-cyan-400"
                          style={{
                            width: `${Math.min(
                              event.confidence * 100,
                              100,
                            )}%`,
                          }}
                        />
                      </div>

                      <span className="text-xs font-medium text-[#94a3b8]">
                        {(event.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>

                  {/* Risk */}

                  <td className="px-5 py-4">
                    <span
                      className={`font-mono text-sm font-semibold ${getRiskStyle(
                        event.risk_score,
                      )}`}
                    >
                      {event.risk_score.toFixed(1)}
                    </span>
                  </td>

                  {/* Severity */}

                  <td className="px-5 py-4">
                    <span
                      className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-bold tracking-wide ${severityStyle.badge}`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${severityStyle.dot}`}
                      />

                      {event.severity}
                    </span>
                  </td>
                </tr>
              );
            })}

            {/* Empty State */}

            {events.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="px-5 py-16 text-center"
                >
                  <div className="flex flex-col items-center">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full border border-[#2a3038] bg-[#111418] text-xl text-[#4f5864]">
                      ✓
                    </div>

                    <p className="mt-4 text-sm font-medium text-[#94a3b8]">
                      No active threat events
                    </p>

                    <p className="mt-1 text-xs text-[#4f5864]">
                      Waiting for detection events...
                    </p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}