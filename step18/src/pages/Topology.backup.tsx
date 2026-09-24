import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

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

interface FlowRecord {
  flow_id: string;

  source_ip: string;
  source_port: number;

  destination_ip: string;
  destination_port: number;

  protocol: string;

  packets: number;
  bytes: number;

  detection: DetectionResult;
}

interface FlowResponse {
  count: number;
  pcap: string;
  flows: FlowRecord[];
  error?: string;
}

interface NetworkNodeData extends Record<string, unknown> {
  label: string;
  role: "SOURCE" | "DESTINATION";
  flowCount: number;
  threatCount: number;
  maxRisk: number;
  highestSeverity: string;
}

function severityRank(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    default:
      return 0;
  }
}

function severityText(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return "text-red-400";
    case "HIGH":
      return "text-orange-400";
    case "MEDIUM":
      return "text-yellow-400";
    case "LOW":
      return "text-emerald-400";
    default:
      return "text-slate-400";
  }
}

function severityBorder(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return "border-red-500/40";
    case "HIGH":
      return "border-orange-500/40";
    case "MEDIUM":
      return "border-yellow-500/40";
    case "LOW":
      return "border-emerald-500/40";
    default:
      return "border-[#2a3038]";
  }
}

function NetworkNode({ data }: { data: NetworkNodeData }) {
  const isSource = data.role === "SOURCE";

  return (
    <div
      className={`min-w-[210px] rounded-xl border bg-[#15181d] px-4 py-4 shadow-xl ${severityBorder(
        data.highestSeverity,
      )}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2 !w-2 !border-0 !bg-slate-500"
      />

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2 !w-2 !border-0 !bg-slate-500"
      />

      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#64748b]">
            {data.role}
          </p>

          <p className="mt-1 font-mono text-sm font-semibold text-[#f1f5f9]">
            {data.label}
          </p>
        </div>

        <div
          className={`flex h-8 w-8 items-center justify-center rounded-lg ${
            isSource
              ? "bg-sky-500/10 text-sky-400"
              : "bg-orange-500/10 text-orange-400"
          }`}
        >
          {isSource ? "↗" : "◉"}
        </div>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2 border-t border-[#252b33] pt-3">
        <div>
          <p className="text-[9px] uppercase text-[#64748b]">
            Flows
          </p>

          <p className="mt-1 text-sm font-semibold text-[#d7dde5]">
            {data.flowCount}
          </p>
        </div>

        <div>
          <p className="text-[9px] uppercase text-[#64748b]">
            Threats
          </p>

          <p className="mt-1 text-sm font-semibold text-orange-400">
            {data.threatCount}
          </p>
        </div>

        <div>
          <p className="text-[9px] uppercase text-[#64748b]">
            Risk
          </p>

          <p
            className={`mt-1 text-sm font-semibold ${severityText(
              data.highestSeverity,
            )}`}
          >
            {data.maxRisk.toFixed(0)}
          </p>
        </div>
      </div>
    </div>
  );
}

const nodeTypes = {
  network: NetworkNode,
};

export default function Topology() {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [pcap, setPcap] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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

        setPcap(data.pcap || "");
        setError(data.error || "");
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load topology data.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadFlows();
  }, []);

  const topology = useMemo(() => {
    const sourceMap = new Map<
      string,
      NetworkNodeData
    >();

    const destinationMap = new Map<
      string,
      NetworkNodeData
    >();

    for (const flow of flows) {
      const threat =
        flow.detection.threat_class !== "BENIGN";

      const sourceExisting =
        sourceMap.get(flow.source_ip);

      if (sourceExisting) {
        sourceExisting.flowCount += 1;

        if (threat) {
          sourceExisting.threatCount += 1;
        }

        sourceExisting.maxRisk = Math.max(
          sourceExisting.maxRisk,
          flow.detection.risk_score,
        );

        if (
          severityRank(
            flow.detection.severity,
          ) >
          severityRank(
            sourceExisting.highestSeverity,
          )
        ) {
          sourceExisting.highestSeverity =
            flow.detection.severity;
        }
      } else {
        sourceMap.set(flow.source_ip, {
          label: flow.source_ip,
          role: "SOURCE",
          flowCount: 1,
          threatCount: threat ? 1 : 0,
          maxRisk:
            flow.detection.risk_score,
          highestSeverity:
            flow.detection.severity,
        });
      }

      const destinationExisting =
        destinationMap.get(
          flow.destination_ip,
        );

      if (destinationExisting) {
        destinationExisting.flowCount += 1;

        if (threat) {
          destinationExisting.threatCount += 1;
        }

        destinationExisting.maxRisk = Math.max(
          destinationExisting.maxRisk,
          flow.detection.risk_score,
        );

        if (
          severityRank(
            flow.detection.severity,
          ) >
          severityRank(
            destinationExisting.highestSeverity,
          )
        ) {
          destinationExisting.highestSeverity =
            flow.detection.severity;
        }
      } else {
        destinationMap.set(
          flow.destination_ip,
          {
            label: flow.destination_ip,
            role: "DESTINATION",
            flowCount: 1,
            threatCount: threat ? 1 : 0,
            maxRisk:
              flow.detection.risk_score,
            highestSeverity:
              flow.detection.severity,
          },
        );
      }
    }

    const nodes: Node<NetworkNodeData>[] = [];

    const sources = Array.from(
      sourceMap.values(),
    );

    const destinations = Array.from(
      destinationMap.values(),
    );

    sources.forEach((source, index) => {
      nodes.push({
        id: `source-${source.label}`,
        type: "network",
        position: {
          x: 80,
          y: 120 + index * 180,
        },
        data: source,
      });
    });

    destinations.forEach(
      (destination, index) => {
        nodes.push({
          id: `destination-${destination.label}`,
          type: "network",
          position: {
            x: 620,
            y: 120 + index * 180,
          },
          data: destination,
        });
      },
    );

    const edges: Edge[] = flows.map(
      (flow, index) => ({
        id: `flow-${index}-${flow.flow_id}`,
        source: `source-${flow.source_ip}`,
        target: `destination-${flow.destination_ip}`,
        animated:
          flow.detection.severity ===
            "CRITICAL" ||
          flow.detection.severity ===
            "HIGH",
        label: `${flow.protocol} : ${flow.destination_port}`,
        style: {
          stroke:
            flow.detection.severity ===
            "CRITICAL"
              ? "#ef4444"
              : flow.detection.severity ===
                  "HIGH"
                ? "#f97316"
                : "#475569",
          strokeWidth:
            flow.detection.threat_class !==
            "BENIGN"
              ? 2
              : 1,
        },
        labelStyle: {
          fill: "#94a3b8",
          fontSize: 10,
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, monospace",
        },
        labelBgStyle: {
          fill: "#111418",
          fillOpacity: 0.95,
          color: "#111418",
        },
        data: {
          flow,
        },
      }),
    );

    return {
      nodes,
      edges,
    };
  }, [flows]);

  const statistics = useMemo(() => {
    const threats = flows.filter(
      (flow) =>
        flow.detection.threat_class !==
        "BENIGN",
    ).length;

    const critical = flows.filter(
      (flow) =>
        flow.detection.severity ===
        "CRITICAL",
    ).length;

    const sourceCount = new Set(
      flows.map(
        (flow) => flow.source_ip,
      ),
    ).size;

    const destinationCount = new Set(
      flows.map(
        (flow) =>
          flow.destination_ip,
      ),
    ).size;

    return {
      flows: flows.length,
      threats,
      critical,
      sourceCount,
      destinationCount,
    };
  }, [flows]);

  return (
    <div className="space-y-6">
      {/* HEADER */}

      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#64748b]">
            Network Monitoring
          </p>

          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-[#f1f5f9]">
            Network Topology
          </h1>

          <p className="mt-1 text-sm text-[#64748b]">
            Passive source-to-destination threat mapping.
          </p>
        </div>

        <div className="rounded-lg border border-sky-500/10 bg-sky-500/5 px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-sky-400">
            Passive Analysis
          </p>

          <p className="mt-1 text-[10px] text-[#64748b]">
            Source: {pcap || "PCAP"}
          </p>
        </div>
      </div>

      {/* STATISTICS */}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Flows
          </p>

          <p className="mt-2 text-2xl font-semibold text-[#f1f5f9]">
            {statistics.flows}
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Sources
          </p>

          <p className="mt-2 text-2xl font-semibold text-sky-400">
            {statistics.sourceCount}
          </p>
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Destinations
          </p>

          <p className="mt-2 text-2xl font-semibold text-[#f1f5f9]">
            {statistics.destinationCount}
          </p>
        </div>

        <div className="rounded-xl border border-orange-500/20 bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Threat Flows
          </p>

          <p className="mt-2 text-2xl font-semibold text-orange-400">
            {statistics.threats}
          </p>
        </div>

        <div className="rounded-xl border border-red-500/20 bg-[#15181d] p-4">
          <p className="text-[10px] uppercase tracking-wider text-[#64748b]">
            Critical
          </p>

          <p className="mt-2 text-2xl font-semibold text-red-400">
            {statistics.critical}
          </p>
        </div>
      </div>

      {/* ERROR */}

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3">
          <p className="text-sm font-medium text-red-400">
            Topology API Error
          </p>

          <p className="mt-1 text-xs text-[#94a3b8]">
            {error}
          </p>
        </div>
      )}

      {/* TOPOLOGY */}

      <div className="overflow-hidden rounded-xl border border-[#2a3038] bg-[#111418]">
        <div className="flex items-center justify-between border-b border-[#2a3038] px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold text-[#f1f5f9]">
              Network Graph
            </h2>

            <p className="mt-1 text-xs text-[#64748b]">
              Source → Destination communication observed in the replayed PCAP.
            </p>
          </div>

          <div className="flex items-center gap-4 text-[10px]">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-sky-400" />
              <span className="text-[#64748b]">
                Source
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-orange-400" />
              <span className="text-[#64748b]">
                Destination
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-red-400" />
              <span className="text-[#64748b]">
                Critical
              </span>
            </div>
          </div>
        </div>

        <div className="h-[620px]">
          {loading ? (
            <div className="flex h-full items-center justify-center text-sm text-[#64748b]">
              Loading network topology...
            </div>
          ) : flows.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-[#64748b]">
              No topology data available.
            </div>
          ) : (
            <ReactFlow
              nodes={topology.nodes}
              edges={topology.edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{
                padding: 0.25,
              }}
              onEdgeClick={(_, edge) => {
                const flow =
                  edge.data?.flow as
                    | FlowRecord
                    | undefined;

                if (flow) {
                  setSelectedFlow(flow);
                }
              }}
              proOptions={{
                hideAttribution: true,
              }}
            >
              <Background color="#20252c" gap={24} />

              <Controls />

              <MiniMap
                nodeColor={(node) => {
                  const data =
                    node.data as unknown as NetworkNodeData;

                  if (
                    data?.highestSeverity ===
                    "CRITICAL"
                  ) {
                    return "#ef4444";
                  }

                  if (
                    data?.role ===
                    "SOURCE"
                  ) {
                    return "#38bdf8";
                  }

                  return "#f97316";
                }}
              />
            </ReactFlow>
          )}
        </div>
      </div>

      {/* SELECTED FLOW */}

      {selectedFlow && (
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#64748b]">
                Selected Flow
              </p>

              <h2 className="mt-1 text-sm font-semibold text-[#f1f5f9]">
                {selectedFlow.source_ip} →
                {" "}
                {selectedFlow.destination_ip}
              </h2>

              <p className="mt-1 font-mono text-xs text-[#64748b]">
                {selectedFlow.protocol} /{" "}
                {selectedFlow.destination_port}
              </p>
            </div>

            <button
              onClick={() =>
                setSelectedFlow(null)
              }
              className="rounded-lg border border-[#2a3038] px-3 py-2 text-xs text-[#94a3b8] transition hover:bg-[#1b1f26] hover:text-[#f1f5f9]"
            >
              Clear
            </button>
          </div>

          <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-5">
            <div>
              <p className="text-[10px] uppercase text-[#64748b]">
                Threat
              </p>

              <p className="mt-1 text-sm font-semibold text-orange-400">
                {selectedFlow.detection.threat_class}
              </p>
            </div>

            <div>
              <p className="text-[10px] uppercase text-[#64748b]">
                Confidence
              </p>

              <p className="mt-1 text-sm font-semibold text-[#f1f5f9]">
                {(
                  selectedFlow.detection.confidence *
                  100
                ).toFixed(1)}
                %
              </p>
            </div>

            <div>
              <p className="text-[10px] uppercase text-[#64748b]">
                Risk
              </p>

              <p className="mt-1 text-sm font-semibold text-[#f1f5f9]">
                {selectedFlow.detection.risk_score.toFixed(
                  1,
                )}
              </p>
            </div>

            <div>
              <p className="text-[10px] uppercase text-[#64748b]">
                Severity
              </p>

              <p
                className={`mt-1 text-sm font-semibold ${severityText(
                  selectedFlow.detection.severity,
                )}`}
              >
                {selectedFlow.detection.severity}
              </p>
            </div>

            <div>
              <p className="text-[10px] uppercase text-[#64748b]">
                Packets
              </p>

              <p className="mt-1 text-sm font-semibold text-[#f1f5f9]">
                {selectedFlow.packets}
              </p>
            </div>
          </div>

          {selectedFlow.detection.evidence.length >
            0 && (
            <div className="mt-5 border-t border-[#252b33] pt-4">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[#64748b]">
                Detection Evidence
              </p>

              <div className="mt-2 space-y-2">
                {selectedFlow.detection.evidence.map(
                  (evidence, index) => (
                    <div
                      key={`${evidence}-${index}`}
                      className="rounded-lg border border-[#2a3038] bg-[#111418] px-3 py-2"
                    >
                      <p className="font-mono text-xs text-[#cbd5e1]">
                        {evidence}
                      </p>
                    </div>
                  ),
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* PASSIVE NOTICE */}

      <div className="rounded-xl border border-sky-500/10 bg-sky-500/5 px-4 py-3">
        <p className="text-xs font-semibold text-sky-400">
          PASSIVE NETWORK OBSERVATION
        </p>

        <p className="mt-1 text-xs leading-5 text-[#64748b]">
          Topology is reconstructed from observed PCAP
          traffic. The monitoring system does not transmit
          packets, perform active probing, or establish
          return-path communication with monitored hosts.
        </p>
      </div>
    </div>
  );
}