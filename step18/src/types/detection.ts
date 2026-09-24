export interface DetectionEvent {
  id?: number;
  event_type: string;
  alert_id?: number;

  timestamp: string;
  flow_id: string;

  source_ip: string;
  destination_ip: string;

  threat_class: string;
  confidence: number;

  ml_risk_contribution: number | null;
  rule_contribution: number | null;
  behavior_contribution: number | null;

  risk_score: number;
  severity: string;

  evidence: string[];
  features: Record<string, number>;
}

export interface TLSFingerprint {
  ja3_hash: string;
  ja3_string: string;
}

export interface TLSIntelligence {
  tls_detected: boolean;
  tls_packet_count: number;
  client_hello_count: number;
  server_hello_count: number;
  tls_versions: string[];
  sni_values: string[];
  alpn_values: string[];
  ja3_fingerprints: TLSFingerprint[];
  evidence: string[];
}

export interface DNSIntelligence {
  dga_score: number;
  dga_classification: string;
  tunnel_score: number;
  tunnel_classification: string;
  evidence: string[];
  aggregate: Record<string, unknown>;
}

export interface C2Timing {
  source_ip: string;
  destination_ip: string;
  communication_count: number;
  average_interval: number;
  minimum_interval: number;
  maximum_interval: number;
  interval_std: number;
  coefficient_of_variation: number;
  periodicity_score: number;
}

export interface C2Destination {
  source_ip: string;
  total_communications: number;
  unique_destinations: number;
  dominant_destination: string;
  dominant_destination_count: number;
  destination_concentration: number;
}

export interface C2Intelligence {
  c2_behavior_score: number;
  c2_classification: string;
  evidence: string[];
  timing: C2Timing[];
  destinations: C2Destination[];
  pairs: Array<{
    source_ip: string;
    destination_ip: string;
    c2_behavior_score: number;
    classification: string;
    evidence: string[];
  }>;
}

export interface FlowRecord {
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

  detection: {
    threat_class: string;
    confidence: number;

    ml_risk_contribution: number | null;
    rule_contribution: number | null;
    behavior_contribution: number | null;

    risk_score: number;
    severity: string;

    evidence: string[];

    dns_intelligence: DNSIntelligence;

    c2_intelligence: C2Intelligence;

    dga_score: number;
    dga_classification: string;

    tunnel_score: number;
    tunnel_classification: string;

    c2_classification: string;
    c2_behavior_score: number;

    tls_intelligence: TLSIntelligence;
  };

  dns_intelligence: DNSIntelligence;

  c2_intelligence: C2Intelligence;

  dga_score: number;
  dga_classification: string;

  tunnel_score: number;
  tunnel_classification: string;

  c2_classification: string;
  c2_behavior_score: number;

  tls_intelligence: TLSIntelligence;

  tls_detected: boolean;
  tls_versions: string[];
  sni_values: string[];
  alpn_values: string[];
  ja3_fingerprints: TLSFingerprint[];

  detection_features: Record<string, number>;
}