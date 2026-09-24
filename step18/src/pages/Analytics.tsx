import { useEffect, useMemo, useState } from "react";
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

const API_URL = "http://127.0.0.1:8000";

export default function Analytics() {
  const [alerts, setAlerts] = useState<DetectionEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadAlerts = async () => {
      try {
        setLoading(true);

        const response = await fetch(`${API_URL}/api/v1/alerts`);

        if (!response.ok) {
          throw new Error("Failed to fetch alerts");
        }

        const data = await response.json();

        const alertList = Array.isArray(data)
          ? data
          : Array.isArray(data.alerts)
            ? data.alerts
            : [];

        setAlerts(alertList);
        setError("");
      } catch (err) {
        console.error(err);
        setError("Unable to load analytics data.");
      } finally {
        setLoading(false);
      }
    };

    loadAlerts();
  }, []);

  const statistics = useMemo(() => {
    const total = alerts.length;

    const critical = alerts.filter(
      (alert) => alert.severity === "CRITICAL"
    ).length;

    const high = alerts.filter(
      (alert) => alert.severity === "HIGH"
    ).length;

    const medium = alerts.filter(
      (alert) => alert.severity === "MEDIUM"
    ).length;

    const low = alerts.filter(
      (alert) => alert.severity === "LOW"
    ).length;

    const averageRisk =
      total > 0
        ? alerts.reduce((sum, alert) => sum + alert.risk_score, 0) /
        total
        : 0;

    const uniqueSources = new Set(
      alerts.map((alert) => alert.source_ip)
    ).size;

    return {
      total,
      critical,
      high,
      medium,
      low,
      averageRisk,
      uniqueSources,
    };
  }, [alerts]);

  const threatDistribution = useMemo(() => {
    const counts: Record<string, number> = {};

    alerts.forEach((alert) => {
      counts[alert.threat_class] =
        (counts[alert.threat_class] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([threat, count]) => ({
        threat,
        count,
      }))
      .sort((a, b) => b.count - a.count);
  }, [alerts]);

  const severityDistribution = useMemo(() => {
    return [
      {
        name: "CRITICAL",
        value: statistics.critical,
      },
      {
        name: "HIGH",
        value: statistics.high,
      },
      {
        name: "MEDIUM",
        value: statistics.medium,
      },
      {
        name: "LOW",
        value: statistics.low,
      },
    ].filter((item) => item.value > 0);
  }, [statistics]);

  const riskTimeline = useMemo(() => {
    return [...alerts]
      .sort(
        (a, b) =>
          new Date(a.timestamp).getTime() -
          new Date(b.timestamp).getTime()
      )
      .map((alert) => ({
        time: new Date(alert.timestamp).toLocaleTimeString(),
        risk: Number(alert.risk_score.toFixed(1)),
        threat: alert.threat_class,
      }));
  }, [alerts]);

  const severityLabel = (value: string) => {
    if (value === "CRITICAL") {
      return "Critical";
    }

    if (value === "HIGH") {
      return "High";
    }

    if (value === "MEDIUM") {
      return "Medium";
    }

    return "Low";
  };

  if (loading) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <div className="text-sm text-slate-500">
          Loading analytics...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-6">
        <h1 className="text-lg font-semibold text-red-400">
          Analytics Error
        </h1>

        <p className="mt-2 text-sm text-slate-400">
          {error}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">
          Threat Analytics
        </h1>

        <p className="mt-1 text-sm text-slate-500">
          Statistical analysis of detected network threats
        </p>
      </div>

      {/* Statistics */}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <p className="text-sm text-slate-500">
            Total Alerts
          </p>

          <p className="mt-2 text-3xl font-bold text-white">
            {statistics.total}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <p className="text-sm text-slate-500">
            Critical Alerts
          </p>

          <p className="mt-2 text-3xl font-bold text-red-400">
            {statistics.critical}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <p className="text-sm text-slate-500">
            Average Risk
          </p>

          <p className="mt-2 text-3xl font-bold text-orange-400">
            {statistics.averageRisk.toFixed(1)}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <p className="text-sm text-slate-500">
            Unique Sources
          </p>

          <p className="mt-2 text-3xl font-bold text-cyan-400">
            {statistics.uniqueSources}
          </p>
        </div>
      </div>

      {/* Charts */}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Threat Distribution */}

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-5">
            <h2 className="text-lg font-semibold text-white">
              Threat Distribution
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Detected threat classes
            </p>
          </div>

          <div className="h-80">
            {threatDistribution.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-600">
                No threat data available.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatDistribution}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1e293b"
                  />

                  <XAxis
                    dataKey="threat"
                    tick={{ fill: "#64748b", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "#64748b", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#020617",
                      border: "1px solid #1e293b",
                      borderRadius: "8px",
                      color: "#fff",
                    }}
                  />

                  <Bar
                    dataKey="count"
                    name="Alerts"
                    radius={[6, 6, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Severity Distribution */}

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-5">
            <h2 className="text-lg font-semibold text-white">
              Severity Distribution
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Alert severity breakdown
            </p>
          </div>

          <div className="h-80">
            {severityDistribution.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-600">
                No severity data available.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    innerRadius={55}
                    paddingAngle={3}
                  >
                    {severityDistribution.map((entry) => (
                      <Cell key={entry.name} />
                    ))}
                  </Pie>

                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#020617",
                      border: "1px solid #1e293b",
                      borderRadius: "8px",
                      color: "#fff",
                    }}
                  />

                  <Legend
                    formatter={(value) =>
                      severityLabel(String(value))
                    }
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Risk Timeline */}

      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="mb-5">
          <h2 className="text-lg font-semibold text-white">
            Risk Score Timeline
          </h2>

          <p className="mt-1 text-sm text-slate-500">
            Risk score of recorded detection events
          </p>
        </div>

        <div className="h-96">
          {riskTimeline.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-600">
              No risk data available.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskTimeline}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#1e293b"
                />

                <XAxis
                  dataKey="time"
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />

                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />

                <Tooltip
                  contentStyle={{
                    backgroundColor: "#020617",
                    border: "1px solid #1e293b",
                    borderRadius: "8px",
                    color: "#fff",
                  }}
                  formatter={(value) => [
                    `${Number(value).toFixed(1)}`,
                    "Risk Score",
                  ]}
                />

                <Bar
                  dataKey="risk"
                  name="Risk Score"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}