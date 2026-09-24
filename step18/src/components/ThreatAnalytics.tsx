import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { DetectionEvent } from "../types/detection";

interface ThreatAnalyticsProps {
  events?: DetectionEvent[];
}

export default function ThreatAnalytics({
  events = [],
}: ThreatAnalyticsProps) {
  const totalAlerts = events.length;

  const averageRisk =
    totalAlerts > 0
      ? events.reduce((sum, event) => sum + event.risk_score, 0) /
        totalAlerts
      : 0;

  const uniqueSources = new Set(
    events.map((event) => event.source_ip),
  ).size;

  const threatCounts = events.reduce<Record<string, number>>(
    (acc, event) => {
      acc[event.threat_class] =
        (acc[event.threat_class] ?? 0) + 1;

      return acc;
    },
    {},
  );

  const severityCounts = events.reduce<Record<string, number>>(
    (acc, event) => {
      acc[event.severity] =
        (acc[event.severity] ?? 0) + 1;

      return acc;
    },
    {},
  );

  const threatData = Object.entries(threatCounts).map(
    ([name, value]) => ({
      name,
      value,
    }),
  );

  const severityData = Object.entries(severityCounts).map(
    ([name, value]) => ({
      name,
      value,
    }),
  );

  const severityOrder = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
  ];

  severityData.sort(
    (a, b) =>
      severityOrder.indexOf(a.name) -
      severityOrder.indexOf(b.name),
  );

  return (
    <section className="space-y-6">
      {/* Header */}

      <div>
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />

          <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Security Intelligence
          </span>
        </div>

        <h2 className="mt-2 text-xl font-semibold text-[#f1f5f9]">
          Threat Analytics
        </h2>

        <p className="mt-1 text-sm text-[#64748b]">
          Statistical overview of detected security events
        </p>
      </div>

      {/* Summary Statistics */}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Total Alerts
          </p>

          <p className="mt-2 text-3xl font-bold text-[#f1f5f9]">
            {totalAlerts}
          </p>

          <p className="mt-1 text-[11px] text-[#4f5864]">
            Recorded events
          </p>
        </div>

        <div className="rounded-xl border border-cyan-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Average Risk
          </p>

          <p className="mt-2 text-3xl font-bold text-cyan-400">
            {averageRisk.toFixed(1)}
          </p>

          <p className="mt-1 text-[11px] text-[#4f5864]">
            Risk score / 100
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Unique Sources
          </p>

          <p className="mt-2 text-3xl font-bold text-[#f1f5f9]">
            {uniqueSources}
          </p>

          <p className="mt-1 text-[11px] text-[#4f5864]">
            Source IP addresses
          </p>
        </div>

        <div className="rounded-xl border border-red-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Threat Types
          </p>

          <p className="mt-2 text-3xl font-bold text-red-400">
            {threatData.length}
          </p>

          <p className="mt-1 text-[11px] text-[#4f5864]">
            Distinct classifications
          </p>
        </div>
      </div>

      {/* Charts */}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Threat Distribution */}

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <div className="mb-5">
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[#d7dde5]">
              Threat Distribution
            </h3>

            <p className="mt-1 text-xs text-[#64748b]">
              Number of events by threat classification
            </p>
          </div>

          <div className="h-72">
            {threatData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={threatData}
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
                    dataKey="name"
                    tick={{
                      fill: "#64748b",
                      fontSize: 10,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{
                      fill: "#64748b",
                      fontSize: 10,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    cursor={{ fill: "#ffffff08" }}
                    contentStyle={{
                      backgroundColor: "#111418",
                      border: "1px solid #2a3038",
                      borderRadius: "8px",
                      color: "#f1f5f9",
                    }}
                    labelStyle={{
                      color: "#94a3b8",
                    }}
                  />

                  <Bar
                    dataKey="value"
                    name="Alerts"
                    fill="#ef4444"
                    radius={[5, 5, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-[#64748b]">
                No threat data available.
              </div>
            )}
          </div>
        </div>

        {/* Severity Distribution */}

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <div className="mb-5">
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[#d7dde5]">
              Severity Distribution
            </h3>

            <p className="mt-1 text-xs text-[#64748b]">
              Alert severity breakdown
            </p>
          </div>

          <div className="h-72">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={88}
                    innerRadius={55}
                    paddingAngle={3}
                  >
                    {severityData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={
                          entry.name === "CRITICAL"
                            ? "#ef4444"
                            : entry.name === "HIGH"
                              ? "#f97316"
                              : entry.name === "MEDIUM"
                                ? "#eab308"
                                : "#22c55e"
                        }
                        stroke="#15181d"
                        strokeWidth={2}
                      />
                    ))}
                  </Pie>

                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#111418",
                      border: "1px solid #2a3038",
                      borderRadius: "8px",
                      color: "#f1f5f9",
                    }}
                  />

                  <Legend
                    iconType="circle"
                    wrapperStyle={{
                      fontSize: "11px",
                      color: "#94a3b8",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-[#64748b]">
                No severity data available.
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}