import { useEffect, useMemo, useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8000";

interface DetectionResult {
  threat_class: string;
  confidence: number;
  ml_risk_contribution: number;
  rule_contribution: number;
  behavior_contribution: number;
  risk_score: number;
  severity: string;
  evidence: string[];
}

interface DetectionFeatures {
  packets: number;
  bytes: number;
  unique_destination_ips: number;
  unique_destination_ports: number;
  duration: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  tcp_packets: number;
  syn_packets: number;
  ack_packets: number;
  rst_packets: number;
  fin_packets: number;
  syn_ratio: number;
  ack_ratio: number;
  rst_ratio: number;
  fin_ratio: number;
  dns_packets: number;
  average_inter_arrival: number;
}

interface FlowRecord {
  flow_id: string;

  source_ip: string;
  source_port: number;

  destination_ip: string;
  destination_port: number;

  protocol: string;

  forward_packets: number;
  reverse_packets: number;

  forward_bytes: number;
  reverse_bytes: number;

  packets: number;
  bytes: number;

  duration: number;

  packets_per_sec: number;
  bytes_per_sec: number;

  avg_packet_size: number;
  packet_size_std: number;

  syn_packets: number;
  ack_packets: number;
  rst_packets: number;
  fin_packets: number;

  syn_ratio: number;
  ack_ratio: number;
  rst_ratio: number;
  fin_ratio: number;

  average_inter_arrival: number;

  dns_packets: number;
  average_dns_length: number;
  average_dns_entropy: number;

  detection: DetectionResult;
  detection_features: DetectionFeatures;
}

interface FlowResponse {
  count: number;
  pcap: string;
  flows: FlowRecord[];
  error?: string;
}

function severityClass(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return "border-red-500/20 bg-red-500/10 text-red-400";

    case "HIGH":
      return "border-orange-500/20 bg-orange-500/10 text-orange-400";

    case "MEDIUM":
      return "border-yellow-500/20 bg-yellow-500/10 text-yellow-400";

    case "LOW":
      return "border-emerald-500/20 bg-emerald-500/10 text-emerald-400";

    default:
      return "border-slate-500/20 bg-slate-500/10 text-slate-400";
  }
}

function threatClass(threat: string) {
  switch (threat) {
    case "RECONNAISSANCE":
      return "text-orange-400";

    case "DDOS":
      return "text-red-400";

    case "DNS_ANOMALY":
      return "text-yellow-400";

    case "BENIGN":
      return "text-emerald-400";

    default:
      return "text-slate-400";
  }
}

function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US", {
    maximumFractionDigits: 2,
  }).format(value);
}

function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${formatNumber(bytes)} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${formatNumber(bytes / 1024)} KB`;
  }

  return `${formatNumber(bytes / (1024 * 1024))} MB`;
}

function FlowDetails({
  flow,
  onClose,
}: {
  flow: FlowRecord;
  onClose: () => void;
}) {
  const detection = flow.detection;
  const features = flow.detection_features;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6">
      <div className="max-h-[90vh] w-full max-w-5xl overflow-y-auto rounded-2xl border border-[#2a3038] bg-[#15181d] shadow-2xl">
        {/* Header */}

        <div className="flex items-center justify-between border-b border-[#2a3038] px-6 py-5">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#64748b]">
              Flow Investigation
            </p>

            <h2 className="mt-1 text-lg font-semibold text-[#f1f5f9]">
              Network Flow
            </h2>

            <p className="mt-1 font-mono text-xs text-[#64748b]">
              {flow.flow_id}
            </p>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg border border-[#2a3038] px-3 py-2 text-sm text-[#94a3b8] transition hover:bg-[#1b1f26] hover:text-[#f1f5f9]"
          >
            Close
          </button>
        </div>

        <div className="space-y-6 p-6">
          {/* ================================================= */}
          {/* AUTHORITATIVE DETECTION */}
          {/* ================================================= */}

          <section>
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-[#f1f5f9]">
                Authoritative Detection
              </h3>

              <p className="mt-1 text-xs text-[#64748b]">
                Result produced by the backend ML + rule + risk engine.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Threat Class
                </p>

                <p
                  className={`mt-2 text-sm font-semibold ${threatClass(
                    detection.threat_class,
                  )}`}
                >
                  {detection.threat_class}
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Confidence
                </p>

                <p className="mt-2 text-xl font-semibold text-[#f1f5f9]">
                  {(detection.confidence * 100).toFixed(1)}%
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Risk Score
                </p>

                <p className="mt-2 text-xl font-semibold text-[#f1f5f9]">
                  {detection.risk_score.toFixed(1)}
                  <span className="text-xs text-[#64748b]"> / 100</span>
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Severity
                </p>

                <div className="mt-2">
                  <span
                    className={`inline-flex rounded-md border px-2.5 py-1 text-xs font-semibold ${severityClass(
                      detection.severity,
                    )}`}
                  >
                    {detection.severity}
                  </span>
                </div>
              </div>
            </div>
          </section>

          {/* ================================================= */}
          {/* NETWORK IDENTITY */}
          {/* ================================================= */}

          <section>
            <h3 className="mb-3 text-sm font-semibold text-[#f1f5f9]">
              Network Identity
            </h3>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Source
                </p>

                <p className="mt-2 font-mono text-sm text-[#f1f5f9]">
                  {flow.source_ip}:{flow.source_port}
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Destination
                </p>

                <p className="mt-2 font-mono text-sm text-[#f1f5f9]">
                  {flow.destination_ip}:{flow.destination_port}
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Protocol
                </p>

                <p className="mt-2 text-sm font-semibold text-[#f1f5f9]">
                  {flow.protocol}
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Flow ID
                </p>

                <p className="mt-2 truncate font-mono text-xs text-[#94a3b8]">
                  {flow.flow_id}
                </p>
              </div>
            </div>
          </section>

          {/* ================================================= */}
          {/* RISK CONTRIBUTIONS */}
          {/* ================================================= */}

          <section>
            <h3 className="mb-3 text-sm font-semibold text-[#f1f5f9]">
              Risk Contributions
            </h3>

            <div className="grid gap-3 md:grid-cols-3">
              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  ML
                </p>

                <p className="mt-2 text-xl font-semibold text-[#f1f5f9]">
                  {detection.ml_risk_contribution.toFixed(1)}
                </p>

                <p className="mt-1 text-xs text-[#64748b]">
                  Model confidence contribution
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Rules
                </p>

                <p className="mt-2 text-xl font-semibold text-[#f1f5f9]">
                  {detection.rule_contribution.toFixed(1)}
                </p>

                <p className="mt-1 text-xs text-[#64748b]">
                  Deterministic rule contribution
                </p>
              </div>

              <div className="rounded-xl border border-[#2a3038] bg-[#1b1f26] p-4">
                <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
                  Behavior
                </p>

                <p className="mt-2 text-xl font-semibold text-[#f1f5f9]">
                  {detection.behavior_contribution.toFixed(1)}
                </p>

                <p className="mt-1 text-xs text-[#64748b]">
                  Behavioral contribution
                </p>
              </div>
            </div>
          </section>

          {/* ================================================= */}
          {/* EVIDENCE */}
          {/* ================================================= */}

          <section>
            <h3 className="mb-3 text-sm font-semibold text-[#f1f5f9]">
              Detection Evidence
            </h3>

            {detection.evidence.length > 0 ? (
              <div className="space-y-2">
                {detection.evidence.map((item, index) => (
                  <div
                    key={`${item}-${index}`}
                    className="rounded-lg border border-[#2a3038] bg-[#111418] px-4 py-3"
                  >
                    <p className="font-mono text-xs text-[#cbd5e1]">
                      {item}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-[#2a3038] bg-[#111418] px-4 py-3 text-xs text-[#64748b]">
                No deterministic rule triggered.
              </div>
            )}
          </section>

          {/* ================================================= */}
          {/* TRAFFIC FEATURES */}
          {/* ================================================= */}

          <section>
            <h3 className="mb-3 text-sm font-semibold text-[#f1f5f9]">
              Detection Features
            </h3>

            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">Packets</p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {formatNumber(features.packets)}
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">Bytes</p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {formatBytes(features.bytes)}
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">
                  Destination IPs
                </p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {features.unique_destination_ips}
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">
                  Destination Ports
                </p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {features.unique_destination_ports}
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">
                  Packet Rate
                </p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {formatNumber(features.packets_per_sec)} /s
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">
                  Byte Rate
                </p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {formatBytes(features.bytes_per_sec)} /s
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">
                  TCP Packets
                </p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {features.tcp_packets}
                </p>
              </div>

              <div className="rounded-lg border border-[#2a3038] bg-[#1b1f26] p-3">
                <p className="text-[10px] text-[#64748b]">
                  SYN Ratio
                </p>
                <p className="mt-1 text-sm text-[#f1f5f9]">
                  {(features.syn_ratio * 100).toFixed(1)}%
                </p>
              </div>
            </div>
          </section>

          {/* ================================================= */}
          {/* PASSIVE MODE */}
          {/* ================================================= */}

          <div className="rounded-xl border border-sky-500/10 bg-sky-500/5 px-4 py-3">
            <p className="text-xs font-semibold text-sky-400">
              PASSIVE ANALYSIS
            </p>

            <p className="mt-1 text-xs leading-5 text-[#64748b]">
              This flow was analyzed from observed PCAP traffic.
              No packets were transmitted back to the monitored network.
              No payload decryption or active probing was performed.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Flows() {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [pcap, setPcap] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [searchTerm, setSearchTerm] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");

  const [selectedFlow, setSelectedFlow] =
    useState<FlowRecord | null>(null);

  useEffect(() => {
    async function loadFlows() {
      try {
        setLoading(true);

        const response = await fetch(
          `${API_BASE_URL}/api/v1/flows`,
        );

        if (!response.ok) {
          throw new Error(
            `Flow API returned HTTP ${response.status}`,
          );
        }

        const data: FlowResponse =
          await response.json();

        setFlows(
          Array.isArray(data.flows)
            ? data.flows
            : [],
        );

        setPcap(
          data.pcap || "",
        );

        setError(
          data.error || "",
        );
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load network flows.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadFlows();
  }, []);

  const filteredFlows = useMemo(() => {
    const search =
      searchTerm
        .toLowerCase()
        .trim();

    return flows.filter((flow) => {
      const matchesSearch =
        search === "" ||
        flow.source_ip
          .toLowerCase()
          .includes(search) ||
        flow.destination_ip
          .toLowerCase()
          .includes(search) ||
        flow.flow_id
          .toLowerCase()
          .includes(search) ||
        flow.detection.threat_class
          .toLowerCase()
          .includes(search);

      const matchesProtocol =
        protocolFilter === "ALL" ||
        flow.protocol === protocolFilter;

      return (
        matchesSearch &&
        matchesProtocol
      );
    });
  }, [
    flows,
    searchTerm,
    protocolFilter,
  ]);

  const statistics = useMemo(() => {
    const critical = flows.filter(
      (flow) =>
        flow.detection.severity ===
        "CRITICAL",
    ).length;

    const high = flows.filter(
      (flow) =>
        flow.detection.severity ===
        "HIGH",
    ).length;

    const threats = flows.filter(
      (flow) =>
        flow.detection.threat_class !==
        "BENIGN",
    ).length;

    const averageRisk =
      flows.length > 0
        ? flows.reduce(
            (sum, flow) =>
              sum +
              flow.detection.risk_score,
            0,
          ) / flows.length
        : 0;

    return {
      total: flows.length,
      threats,
      critical,
      high,
      averageRisk,
    };
  }, [flows]);

  return (
    <div className="space-y-6">
      {/* =================================================== */}
      {/* HEADER */}
      {/* =================================================== */}

      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#64748b]">
            Network Monitoring
          </p>

          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-[#f1f5f9]">
            Flow Explorer
          </h1>

          <p className="mt-1 text-sm text-[#64748b]">
            Passive network flow visibility with authoritative threat detection.
          </p>
        </div>

        <div className="rounded-lg border border-emerald-500/10 bg-emerald-500/5 px-3 py-2">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />

            <span className="text-xs font-medium text-emerald-400">
              PASSIVE READ
            </span>
          </div>

          <p className="mt-1 text-[10px] text-[#64748b]">
            Source: {pcap || "PCAP"}
          </p>
        </div>
      </div>

      {/* =================================================== */}
      {/* STATISTICS */}
      {/* =================================================== */}

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-5">
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Total Flows
          </p>

          <p className="mt-2 text-2xl font-semibold text-[#f1f5f9]">
            {statistics.total}
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Detected Threats
          </p>

          <p className="mt-2 text-2xl font-semibold text-orange-400">
            {statistics.threats}
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Critical
          </p>

          <p className="mt-2 text-2xl font-semibold text-red-400">
            {statistics.critical}
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            High
          </p>

          <p className="mt-2 text-2xl font-semibold text-orange-400">
            {statistics.high}
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Average Risk
          </p>

          <p className="mt-2 text-2xl font-semibold text-[#f1f5f9]">
            {statistics.averageRisk.toFixed(1)}
          </p>
        </div>
      </div>

      {/* =================================================== */}
      {/* FILTERS */}
      {/* =================================================== */}

      <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
        <div className="flex flex-col gap-3 lg:flex-row">
          <input
            type="text"
            placeholder="Search source, destination, flow ID or threat..."
            value={searchTerm}
            onChange={(event) =>
              setSearchTerm(
                event.target.value,
              )
            }
            className="w-full rounded-lg border border-[#2a3038] bg-[#111418] px-4 py-2.5 text-sm text-[#f1f5f9] outline-none placeholder:text-[#4f5864] focus:border-[#47515d]"
          />

          <select
            value={protocolFilter}
            onChange={(event) =>
              setProtocolFilter(
                event.target.value,
              )
            }
            className="rounded-lg border border-[#2a3038] bg-[#111418] px-4 py-2.5 text-sm text-[#f1f5f9] outline-none"
          >
            <option value="ALL">
              All Protocols
            </option>

            <option value="TCP">
              TCP
            </option>

            <option value="UDP">
              UDP
            </option>
          </select>
        </div>
      </div>

      {/* =================================================== */}
      {/* ERROR */}
      {/* =================================================== */}

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3">
          <p className="text-sm font-medium text-red-400">
            Flow API Error
          </p>

          <p className="mt-1 text-xs text-[#94a3b8]">
            {error}
          </p>
        </div>
      )}

      {/* =================================================== */}
      {/* TABLE */}
      {/* =================================================== */}

      <div className="overflow-hidden rounded-xl border border-[#2a3038] bg-[#15181d]">
        <div className="border-b border-[#2a3038] px-5 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-[#f1f5f9]">
                Observed Flows
              </h2>

              <p className="mt-1 text-xs text-[#64748b]">
                {filteredFlows.length} flows displayed
              </p>
            </div>

            <span className="rounded-md border border-[#2a3038] bg-[#1b1f26] px-2.5 py-1 text-[10px] font-medium text-[#94a3b8]">
              PCAP ANALYSIS
            </span>
          </div>
        </div>

        {loading ? (
          <div className="px-5 py-12 text-center text-sm text-[#64748b]">
            Loading network flows...
          </div>
        ) : filteredFlows.length === 0 ? (
          <div className="px-5 py-12 text-center text-sm text-[#64748b]">
            No flows match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1050px] text-left">
              <thead>
                <tr className="border-b border-[#2a3038] text-[10px] uppercase tracking-wider text-[#64748b]">
                  <th className="px-5 py-3 font-medium">
                    Source
                  </th>

                  <th className="px-5 py-3 font-medium">
                    Destination
                  </th>

                  <th className="px-5 py-3 font-medium">
                    Protocol
                  </th>

                  <th className="px-5 py-3 font-medium">
                    Packets
                  </th>

                  <th className="px-5 py-3 font-medium">
                    Threat
                  </th>

                  <th className="px-5 py-3 font-medium">
                    Risk
                  </th>

                  <th className="px-5 py-3 font-medium">
                    Severity
                  </th>
                </tr>
              </thead>

              <tbody>
                {filteredFlows.map(
                  (flow) => (
                    <tr
                      key={flow.flow_id}
                      onClick={() =>
                        setSelectedFlow(
                          flow,
                        )
                      }
                      className="cursor-pointer border-b border-[#20252c] transition hover:bg-[#1b1f26]"
                    >
                      <td className="px-5 py-4">
                        <div className="font-mono text-xs text-[#f1f5f9]">
                          {flow.source_ip}
                        </div>

                        <div className="mt-1 text-[10px] text-[#64748b]">
                          Port{" "}
                          {flow.source_port}
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <div className="font-mono text-xs text-[#f1f5f9]">
                          {flow.destination_ip}
                        </div>

                        <div className="mt-1 text-[10px] text-[#64748b]">
                          Port{" "}
                          {flow.destination_port}
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <span className="rounded-md border border-[#2a3038] bg-[#1b1f26] px-2 py-1 text-[10px] font-medium text-[#94a3b8]">
                          {flow.protocol}
                        </span>
                      </td>

                      <td className="px-5 py-4 text-xs text-[#cbd5e1]">
                        {formatNumber(
                          flow.packets,
                        )}
                      </td>

                      <td className="px-5 py-4">
                        <span
                          className={`text-xs font-semibold ${threatClass(
                            flow.detection
                              .threat_class,
                          )}`}
                        >
                          {
                            flow
                              .detection
                              .threat_class
                          }
                        </span>

                        <p className="mt-1 text-[10px] text-[#64748b]">
                          {(
                            flow
                              .detection
                              .confidence *
                            100
                          ).toFixed(1)}
                          % confidence
                        </p>
                      </td>

                      <td className="px-5 py-4">
                        <span className="text-sm font-semibold text-[#f1f5f9]">
                          {flow.detection.risk_score.toFixed(
                            1,
                          )}
                        </span>
                        <span className="text-[10px] text-[#64748b]">
                          {" "}
                          / 100
                        </span>
                      </td>

                      <td className="px-5 py-4">
                        <span
                          className={`inline-flex rounded-md border px-2 py-1 text-[10px] font-semibold ${severityClass(
                            flow.detection
                              .severity,
                          )}`}
                        >
                          {
                            flow
                              .detection
                              .severity
                          }
                        </span>
                      </td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* =================================================== */}
      {/* MODAL */}
      {/* =================================================== */}

      {selectedFlow && (
        <FlowDetails
          flow={selectedFlow}
          onClose={() =>
            setSelectedFlow(null)
          }
        />
      )}
    </div>
  );
}