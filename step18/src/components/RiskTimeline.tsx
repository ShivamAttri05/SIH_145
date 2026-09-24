import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { DetectionEvent } from "../types/detection";

interface RiskTimelineProps {
  events?: DetectionEvent[];
}

export default function RiskTimeline({
  events = [],
}: RiskTimelineProps) {
  const data = [...events]
    .reverse()
    .map((event, index) => ({
      index: index + 1,
      risk: Number(event.risk_score.toFixed(1)),
      threat: event.threat_class,
      source: event.source_ip,
      time: new Date(event.timestamp).toLocaleTimeString(),
    }));

  return (
    <section className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
      {/* Header */}

      <div className="mb-5">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-red-400" />

          <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-red-400">
            Risk Monitoring
          </span>
        </div>

        <h2 className="mt-2 text-lg font-semibold text-[#f1f5f9]">
          Risk Activity
        </h2>

        <p className="mt-1 text-sm text-[#64748b]">
          Risk score across detected security events
        </p>
      </div>

      {/* Chart */}

      <div className="h-80">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={data}
              margin={{
                top: 5,
                right: 10,
                left: -15,
                bottom: 5,
              }}
            >
              <CartesianGrid
                stroke="#252b33"
                strokeDasharray="3 3"
                vertical={false}
              />

              <XAxis
                dataKey="index"
                tick={{
                  fill: "#64748b",
                  fontSize: 10,
                }}
                axisLine={false}
                tickLine={false}
              />

              <YAxis
                domain={[0, 100]}
                allowDecimals={false}
                tick={{
                  fill: "#64748b",
                  fontSize: 10,
                }}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip
                contentStyle={{
                  backgroundColor: "#111418",
                  border: "1px solid #2a3038",
                  borderRadius: "8px",
                  color: "#f1f5f9",
                }}
                labelStyle={{
                  color: "#94a3b8",
                  marginBottom: "4px",
                }}
                formatter={(value) => [
                  `${Number(value).toFixed(1)}`,
                  "Risk Score",
                ]}
                labelFormatter={(label) => {
                  const point = data[Number(label) - 1];

                  return point
                    ? `${point.time} — ${point.threat}`
                    : `Event ${label}`;
                }}
              />

              <Line
                type="monotone"
                dataKey="risk"
                stroke="#ef4444"
                strokeWidth={2.5}
                dot={{
                  r: 3,
                  fill: "#15181d",
                  stroke: "#ef4444",
                  strokeWidth: 2,
                }}
                activeDot={{
                  r: 6,
                  fill: "#ef4444",
                  stroke: "#111418",
                  strokeWidth: 2,
                }}
              />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-[#64748b]">
            Waiting for detection events...
          </div>
        )}
      </div>

      {/* Risk Scale */}

      <div className="mt-4 flex items-center justify-between border-t border-[#252b33] pt-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-emerald-400" />

          <span className="text-[10px] uppercase tracking-wide text-[#64748b]">
            Low
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-yellow-400" />

          <span className="text-[10px] uppercase tracking-wide text-[#64748b]">
            Medium
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-orange-400" />

          <span className="text-[10px] uppercase tracking-wide text-[#64748b]">
            High
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-red-400" />

          <span className="text-[10px] uppercase tracking-wide text-[#64748b]">
            Critical
          </span>
        </div>
      </div>
    </section>
  );
}