import type { DetectionEvent } from "../types/detection";

interface AlertDetailsProps {
  alert: DetectionEvent;
  onClose: () => void;
}

function formatValue(value: number | undefined): string {
  if (value === undefined) {
    return "N/A";
  }

  if (Number.isInteger(value)) {
    return value.toString();
  }

  return value.toFixed(3);
}

function formatContribution(value: number | null): string {
  if (value === null) {
    return "N/A";
  }

  return value.toFixed(1);
}

function getSeverityStyle(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return {
        badge: "border-red-500/30 bg-red-500/10 text-red-400",
        dot: "bg-red-400",
        border: "border-red-500/20",
      };

    case "HIGH":
      return {
        badge: "border-orange-500/30 bg-orange-500/10 text-orange-400",
        dot: "bg-orange-400",
        border: "border-orange-500/20",
      };

    case "MEDIUM":
      return {
        badge: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
        dot: "bg-yellow-400",
        border: "border-yellow-500/20",
      };

    default:
      return {
        badge: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
        dot: "bg-emerald-400",
        border: "border-emerald-500/20",
      };
  }
}

function getRiskColor(risk: number) {
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
}

function getContributionWidth(value: number | null) {
  if (value === null) {
    return 0;
  }

  return Math.min((value / 60) * 100, 100);
}

export default function AlertDetails({
  alert,
  onClose,
}: AlertDetailsProps) {
  const severityStyle = getSeverityStyle(alert.severity);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm sm:p-6">
      <div className="max-h-[92vh] w-full max-w-6xl overflow-hidden rounded-2xl border border-[#2a3038] bg-[#111418] shadow-2xl">
        {/* Header */}

        <div className="flex items-start justify-between border-b border-[#2a3038] bg-[#15181d] px-6 py-5">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${severityStyle.dot}`}
                />

                <span
                  className={`rounded-full border px-3 py-1 text-[10px] font-bold tracking-wide ${severityStyle.badge}`}
                >
                  {alert.severity}
                </span>
              </div>

              <span className="text-[#4f5864]">
                /
              </span>

              <span className="text-sm font-semibold text-[#d7dde5]">
                {alert.threat_class}
              </span>
            </div>

            <h2 className="mt-3 text-xl font-semibold text-[#f1f5f9]">
              Alert Investigation
            </h2>

            <p className="mt-1 text-sm text-[#64748b]">
              Detection event and supporting security evidence
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close alert details"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#2a3038] bg-[#111418] text-[#64748b] transition hover:border-[#3b434f] hover:bg-[#1b1f26] hover:text-[#f1f5f9]"
          >
            ✕
          </button>
        </div>

        <div className="max-h-[calc(92vh-145px)] overflow-y-auto">
          <div className="space-y-6 p-6">
            {/* Threat Overview */}

            <section>
              <div className="mb-3 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400" />

                <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-[#94a3b8]">
                  Threat Overview
                </h3>
              </div>

              <div className="grid gap-4 lg:grid-cols-4">
                <div
                  className={`rounded-xl border ${severityStyle.border} bg-[#15181d] p-5`}
                >
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Threat Class
                  </p>

                  <p className="mt-2 text-lg font-semibold text-[#f1f5f9]">
                    {alert.threat_class}
                  </p>
                </div>

                <div className="rounded-xl border border-red-500/20 bg-[#15181d] p-5">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Risk Score
                  </p>

                  <p
                    className={`mt-1 text-3xl font-bold ${getRiskColor(
                      alert.risk_score,
                    )}`}
                  >
                    {alert.risk_score.toFixed(1)}
                  </p>

                  <p className="mt-1 text-[10px] text-[#4f5864]">
                    Maximum risk: 100
                  </p>
                </div>

                <div className="rounded-xl border border-cyan-500/20 bg-[#15181d] p-5">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Confidence
                  </p>

                  <p className="mt-1 text-3xl font-bold text-cyan-400">
                    {(alert.confidence * 100).toFixed(1)}%
                  </p>

                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[#2a3038]">
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
                </div>

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Event Type
                  </p>

                  <p className="mt-2 text-sm font-semibold text-[#d7dde5]">
                    {alert.event_type}
                  </p>

                  <p className="mt-1 text-[10px] text-[#4f5864]">
                    Detection pipeline event
                  </p>
                </div>
              </div>
            </section>

            {/* Network Identity */}

            <section>
              <div className="mb-3 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />

                <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-[#94a3b8]">
                  Network Identity
                </h3>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Source IP
                  </p>

                  <p className="mt-2 font-mono text-sm font-medium text-[#f1f5f9]">
                    {alert.source_ip}
                  </p>
                </div>

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Destination IP
                  </p>

                  <p className="mt-2 font-mono text-sm font-medium text-[#f1f5f9]">
                    {alert.destination_ip}
                  </p>
                </div>

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Flow ID
                  </p>

                  <p className="mt-2 break-all font-mono text-xs text-[#94a3b8]">
                    {alert.flow_id}
                  </p>
                </div>

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#64748b]">
                    Timestamp
                  </p>

                  <p className="mt-2 font-mono text-xs text-[#d7dde5]">
                    {new Date(alert.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            </section>

            {/* Risk Contributions */}

            <section>
              <div className="mb-3 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-orange-400" />

                <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-[#94a3b8]">
                  Risk Contributions
                </h3>
              </div>

              <div className="grid gap-4 md:grid-cols-3">
                {/* ML */}

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-medium text-[#94a3b8]">
                      ML Detection
                    </p>

                    <span className="font-mono text-sm font-semibold text-cyan-400">
                      {formatContribution(
                        alert.ml_risk_contribution,
                      )}
                    </span>
                  </div>

                  <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#2a3038]">
                    <div
                      className="h-full rounded-full bg-cyan-400"
                      style={{
                        width: `${getContributionWidth(
                          alert.ml_risk_contribution,
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Rule */}

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-medium text-[#94a3b8]">
                      Rule Engine
                    </p>

                    <span className="font-mono text-sm font-semibold text-orange-400">
                      {formatContribution(
                        alert.rule_contribution,
                      )}
                    </span>
                  </div>

                  <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#2a3038]">
                    <div
                      className="h-full rounded-full bg-orange-400"
                      style={{
                        width: `${getContributionWidth(
                          alert.rule_contribution,
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Behavior */}

                <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-medium text-[#94a3b8]">
                      Behavior Engine
                    </p>

                    <span className="font-mono text-sm font-semibold text-yellow-400">
                      {formatContribution(
                        alert.behavior_contribution,
                      )}
                    </span>
                  </div>

                  <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#2a3038]">
                    <div
                      className="h-full rounded-full bg-yellow-400"
                      style={{
                        width: `${getContributionWidth(
                          alert.behavior_contribution,
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </section>

            {/* Evidence */}

            <section>
              <div className="mb-3 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400" />

                <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-[#94a3b8]">
                  Detection Evidence
                </h3>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
                {alert.evidence.length > 0 ? (
                  <div className="space-y-2">
                    {alert.evidence.map((item, index) => (
                      <div
                        key={`${item}-${index}`}
                        className="flex items-start gap-3 rounded-lg border border-[#252b33] bg-[#111418] px-4 py-3"
                      >
                        <div className="mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-red-500/10">
                          <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                        </div>

                        <p className="font-mono text-xs leading-6 text-[#cbd5e1]">
                          {item}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="py-6 text-center">
                    <p className="text-sm text-[#64748b]">
                      No supporting evidence recorded.
                    </p>
                  </div>
                )}
              </div>
            </section>

            {/* Network Features */}

            <section>
              <div className="mb-3 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />

                <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-[#94a3b8]">
                  Network Features
                </h3>
              </div>

              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  ["Packets", alert.features.packets],
                  ["Bytes", alert.features.bytes],
                  [
                    "Destination IPs",
                    alert.features.unique_destination_ips,
                  ],
                  [
                    "Destination Ports",
                    alert.features.unique_destination_ports,
                  ],
                  ["Duration", alert.features.duration],
                  [
                    "Packets/sec",
                    alert.features.packets_per_sec,
                  ],
                  [
                    "Bytes/sec",
                    alert.features.bytes_per_sec,
                  ],
                  [
                    "TCP Packets",
                    alert.features.tcp_packets,
                  ],
                  [
                    "SYN Packets",
                    alert.features.syn_packets,
                  ],
                  [
                    "ACK Packets",
                    alert.features.ack_packets,
                  ],
                  [
                    "RST Packets",
                    alert.features.rst_packets,
                  ],
                  [
                    "DNS Packets",
                    alert.features.dns_packets,
                  ],
                  ["SYN Ratio", alert.features.syn_ratio],
                  ["ACK Ratio", alert.features.ack_ratio],
                  ["RST Ratio", alert.features.rst_ratio],
                  [
                    "Avg Inter-arrival",
                    alert.features.average_inter_arrival,
                  ],
                ].map(([label, value]) => (
                  <div
                    key={String(label)}
                    className="rounded-lg border border-[#252b33] bg-[#15181d] p-3.5"
                  >
                    <p className="text-[10px] font-medium uppercase tracking-wide text-[#64748b]">
                      {String(label)}
                    </p>

                    <p className="mt-1.5 font-mono text-sm font-medium text-[#d7dde5]">
                      {formatValue(value as number | undefined)}
                      {label === "Duration" ||
                      label === "Avg Inter-arrival"
                        ? " s"
                        : ""}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>

        {/* Footer */}

        <div className="flex items-center justify-between border-t border-[#2a3038] bg-[#15181d] px-6 py-4">
          <p className="text-[10px] uppercase tracking-wide text-[#4f5864]">
            Passive detection • No response action performed
          </p>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-[#2a3038] bg-[#1b1f26] px-4 py-2 text-sm font-medium text-[#d7dde5] transition hover:border-[#3b434f] hover:bg-[#252b33] hover:text-white"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}