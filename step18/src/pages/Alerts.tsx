import { useEffect, useMemo, useState } from "react";

import AlertDetails from "../components/AlertDetails";
import type { DetectionEvent } from "../types/detection";

const API_URL = "http://127.0.0.1:8000";

export default function Alerts() {
  const [alerts, setAlerts] = useState<DetectionEvent[]>([]);
  const [selectedAlert, setSelectedAlert] =
    useState<DetectionEvent | null>(null);

  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadAlerts = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await fetch(
          `${API_URL}/api/v1/alerts`,
        );

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        setAlerts(
          Array.isArray(data)
            ? data
            : data.alerts ?? [],
        );
      } catch (err) {
        console.error(
          "Failed to load alerts:",
          err,
        );

        setError(
          "Unable to load alerts from the detection API.",
        );
      } finally {
        setLoading(false);
      }
    };

    loadAlerts();
  }, []);

  const filteredAlerts = useMemo(() => {
    const search = searchTerm.toLowerCase().trim();

    return alerts.filter((alert) => {
      const matchesSearch =
        search === "" ||
        alert.source_ip
          .toLowerCase()
          .includes(search) ||
        alert.destination_ip
          .toLowerCase()
          .includes(search) ||
        alert.threat_class
          .toLowerCase()
          .includes(search) ||
        alert.flow_id
          .toLowerCase()
          .includes(search);

      const matchesSeverity =
        severityFilter === "ALL" ||
        alert.severity === severityFilter;

      return matchesSearch && matchesSeverity;
    });
  }, [alerts, searchTerm, severityFilter]);

  const criticalCount = alerts.filter(
    (alert) => alert.severity === "CRITICAL",
  ).length;

  const highCount = alerts.filter(
    (alert) => alert.severity === "HIGH",
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}

      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-red-400" />

            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-red-400">
              Security Operations
            </span>
          </div>

          <h1 className="mt-2 text-2xl font-bold tracking-tight text-[#f1f5f9]">
            Alert Center
          </h1>

          <p className="mt-1 text-sm text-[#64748b]">
            Historical security events stored by the detection platform
          </p>
        </div>

        <div className="rounded-lg border border-[#2a3038] bg-[#15181d] px-4 py-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#64748b]">
            Data Source
          </p>

          <p className="mt-1 text-sm font-medium text-[#d7dde5]">
            PostgreSQL
          </p>
        </div>
      </div>

      {/* Summary */}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Total Alerts
          </p>

          <p className="mt-2 text-3xl font-bold text-[#f1f5f9]">
            {alerts.length}
          </p>

          <p className="mt-1 text-[11px] text-[#4f5864]">
            Recorded events
          </p>
        </div>

        <div className="rounded-xl border border-red-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Critical
          </p>

          <p className="mt-2 text-3xl font-bold text-red-400">
            {criticalCount}
          </p>

          <p className="mt-1 text-[11px] text-red-400/60">
            Immediate attention
          </p>
        </div>

        <div className="rounded-xl border border-orange-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            High
          </p>

          <p className="mt-2 text-3xl font-bold text-orange-400">
            {highCount}
          </p>

          <p className="mt-1 text-[11px] text-orange-400/60">
            Elevated risk
          </p>
        </div>

        <div className="rounded-xl border border-cyan-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Visible
          </p>

          <p className="mt-2 text-3xl font-bold text-cyan-400">
            {filteredAlerts.length}
          </p>

          <p className="mt-1 text-[11px] text-[#4f5864]">
            Current filter result
          </p>
        </div>
      </div>

      {/* Alert Workspace */}

      <div className="overflow-hidden rounded-xl border border-[#2a3038] bg-[#15181d]">
        {/* Workspace Header */}

        <div className="border-b border-[#2a3038] px-5 py-4">
          <div className="flex flex-col justify-between gap-3 md:flex-row md:items-center">
            <div>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />

                <h2 className="text-lg font-semibold text-[#f1f5f9]">
                  Historical Alerts
                </h2>
              </div>

              <p className="mt-1 text-sm text-[#64748b]">
                Search and inspect recorded detection events
              </p>
            </div>

            <div className="rounded-md border border-[#2a3038] bg-[#111418] px-3 py-1.5">
              <span className="text-xs font-medium text-[#94a3b8]">
                {filteredAlerts.length} / {alerts.length}
              </span>
            </div>
          </div>
        </div>

        {/* Filters */}

        <div className="border-b border-[#2a3038] bg-[#111418] p-5">
          <div className="flex flex-col gap-3 lg:flex-row">
            <div className="relative flex-1">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-[#64748b]">
                🔎
              </span>

              <input
                type="text"
                value={searchTerm}
                onChange={(event) =>
                  setSearchTerm(event.target.value)
                }
                placeholder="Search source, destination, threat, or flow ID..."
                className="w-full rounded-lg border border-[#2a3038] bg-[#15181d] py-2.5 pl-10 pr-4 text-sm text-[#f1f5f9] outline-none placeholder:text-[#4f5864] transition focus:border-red-500/50 focus:ring-1 focus:ring-red-500/10"
              />
            </div>

            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
              className="rounded-lg border border-[#2a3038] bg-[#15181d] px-4 py-2.5 text-sm text-[#d7dde5] outline-none transition focus:border-red-500/50"
            >
              <option value="ALL">
                All Severities
              </option>

              <option value="CRITICAL">
                Critical
              </option>

              <option value="HIGH">
                High
              </option>

              <option value="MEDIUM">
                Medium
              </option>

              <option value="LOW">
                Low
              </option>
            </select>

            {(searchTerm || severityFilter !== "ALL") && (
              <button
                type="button"
                onClick={() => {
                  setSearchTerm("");
                  setSeverityFilter("ALL");
                }}
                className="rounded-lg border border-[#2a3038] bg-[#15181d] px-4 py-2.5 text-sm font-medium text-[#94a3b8] transition hover:bg-[#1b1f26] hover:text-white"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Loading */}

        {loading && (
          <div className="px-5 py-16 text-center">
            <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-[#2a3038] border-t-red-400" />

            <p className="mt-4 text-sm text-[#64748b]">
              Loading alerts...
            </p>
          </div>
        )}

        {/* Error */}

        {!loading && error && (
          <div className="p-5">
            <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-5">
              <p className="text-sm font-medium text-red-400">
                Alert API unavailable
              </p>

              <p className="mt-1 text-xs text-[#64748b]">
                {error}
              </p>
            </div>
          </div>
        )}

        {/* Empty */}

        {!loading &&
          !error &&
          filteredAlerts.length === 0 && (
            <div className="px-5 py-16 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-[#2a3038] bg-[#111418] text-lg text-[#4f5864]">
                {alerts.length === 0 ? "✓" : "⌕"}
              </div>

              <p className="mt-4 text-sm font-medium text-[#94a3b8]">
                {alerts.length === 0
                  ? "No alerts have been recorded."
                  : "No alerts match the current filters."}
              </p>

              {alerts.length > 0 && (
                <p className="mt-1 text-xs text-[#4f5864]">
                  Try changing the search term or severity filter.
                </p>
              )}
            </div>
          )}

        {/* Table */}

        {!loading &&
          !error &&
          filteredAlerts.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1050px] text-left text-sm">
                <thead className="border-b border-[#252b33] bg-[#111418] text-[10px] uppercase tracking-[0.12em] text-[#64748b]">
                  <tr>
                    <th className="px-5 py-3.5 font-semibold">
                      Time
                    </th>

                    <th className="px-5 py-3.5 font-semibold">
                      Source
                    </th>

                    <th className="px-5 py-3.5 font-semibold">
                      Destination
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
                  {filteredAlerts.map((alert) => {
                    const riskColor =
                      alert.risk_score >= 80
                        ? "text-red-400"
                        : alert.risk_score >= 60
                          ? "text-orange-400"
                          : alert.risk_score >= 30
                            ? "text-yellow-400"
                            : "text-emerald-400";

                    const severityStyle =
                      alert.severity === "CRITICAL"
                        ? "border-red-500/20 bg-red-500/10 text-red-400"
                        : alert.severity === "HIGH"
                          ? "border-orange-500/20 bg-orange-500/10 text-orange-400"
                          : alert.severity === "MEDIUM"
                            ? "border-yellow-500/20 bg-yellow-500/10 text-yellow-400"
                            : "border-emerald-500/20 bg-emerald-500/10 text-emerald-400";

                    const severityDot =
                      alert.severity === "CRITICAL"
                        ? "bg-red-400"
                        : alert.severity === "HIGH"
                          ? "bg-orange-400"
                          : alert.severity === "MEDIUM"
                            ? "bg-yellow-400"
                            : "bg-emerald-400";

                    return (
                      <tr
                        key={
                          alert.id ??
                          alert.alert_id ??
                          alert.flow_id
                        }
                        onClick={() =>
                          setSelectedAlert(alert)
                        }
                        className="group cursor-pointer border-t border-[#20252c] transition hover:bg-[#1b1f26]"
                      >
                        {/* Time */}

                        <td className="whitespace-nowrap px-5 py-4">
                          <div>
                            <p className="font-mono text-xs text-[#d7dde5]">
                              {new Date(
                                alert.timestamp,
                              ).toLocaleTimeString()}
                            </p>

                            <p className="mt-0.5 text-[10px] text-[#4f5864]">
                              {new Date(
                                alert.timestamp,
                              ).toLocaleDateString()}
                            </p>
                          </div>
                        </td>

                        {/* Source */}

                        <td className="px-5 py-4">
                          <span className="font-mono text-xs text-[#d7dde5]">
                            {alert.source_ip}
                          </span>
                        </td>

                        {/* Destination */}

                        <td className="px-5 py-4">
                          <span className="font-mono text-xs text-[#94a3b8]">
                            {alert.destination_ip}
                          </span>
                        </td>

                        {/* Threat */}

                        <td className="px-5 py-4">
                          <span className="font-medium text-[#d7dde5]">
                            {alert.threat_class}
                          </span>
                        </td>

                        {/* Confidence */}

                        <td className="px-5 py-4">
                          <div className="flex items-center gap-3">
                            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[#2a3038]">
                              <div
                                className="h-full rounded-full bg-cyan-400"
                                style={{
                                  width: `${Math.min(
                                    alert.confidence * 100,
                                    100,
                                  )}%`,
                                }}
                              />
                            </div>

                            <span className="text-xs text-[#94a3b8]">
                              {(
                                alert.confidence * 100
                              ).toFixed(1)}
                              %
                            </span>
                          </div>
                        </td>

                        {/* Risk */}

                        <td className="px-5 py-4">
                          <span
                            className={`font-mono text-sm font-semibold ${riskColor}`}
                          >
                            {alert.risk_score.toFixed(1)}
                          </span>
                        </td>

                        {/* Severity */}

                        <td className="px-5 py-4">
                          <span
                            className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-bold tracking-wide ${severityStyle}`}
                          >
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${severityDot}`}
                            />

                            {alert.severity}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
      </div>

      {/* Alert Details */}

      {selectedAlert && (
        <AlertDetails
          alert={selectedAlert}
          onClose={() =>
            setSelectedAlert(null)
          }
        />
      )}
    </div>
  );
}