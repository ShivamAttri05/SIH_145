import type {
  C2Intelligence,
  DNSIntelligence,
  TLSIntelligence,
} from "../types/detection";

interface SecurityIntelligenceProps {
  tls?: TLSIntelligence;
  dns?: DNSIntelligence;
  c2?: C2Intelligence;
}

function StatusBadge({
  value,
}: {
  value: string;
}) {
  return (
    <span className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs font-medium text-slate-300">
      {value}
    </span>
  );
}

export default function SecurityIntelligence({
  tls,
  dns,
  c2,
}: SecurityIntelligenceProps) {
  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100">
            TLS Intelligence
          </h3>

          <StatusBadge
            value={
              tls?.tls_detected
                ? "DETECTED"
                : "NOT DETECTED"
            }
          />
        </div>

        {tls?.tls_detected ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <div className="text-xs text-slate-500">
                TLS Version
              </div>

              <div className="mt-1 text-sm text-slate-200">
                {tls.tls_versions.join(", ") || "Unknown"}
              </div>
            </div>

            <div>
              <div className="text-xs text-slate-500">
                SNI
              </div>

              <div className="mt-1 text-sm text-slate-200">
                {tls.sni_values.join(", ") || "None"}
              </div>
            </div>

            <div>
              <div className="text-xs text-slate-500">
                ALPN
              </div>

              <div className="mt-1 text-sm text-slate-200">
                {tls.alpn_values.join(", ") || "None"}
              </div>
            </div>

            <div>
              <div className="text-xs text-slate-500">
                JA3
              </div>

              <div className="mt-1 break-all font-mono text-xs text-slate-300">
                {tls.ja3_fingerprints
                  .map(
                    (fingerprint) =>
                      fingerprint.ja3_hash,
                  )
                  .join(", ") || "None"}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-sm text-slate-500">
            No TLS metadata observed.
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-4 text-sm font-semibold text-slate-100">
          DNS Intelligence
        </h3>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="text-xs text-slate-500">
              DGA
            </div>

            <div className="mt-1 text-sm text-slate-200">
              {dns?.dga_classification ?? "N/A"}
            </div>

            <div className="text-xs text-slate-500">
              Score: {dns?.dga_score ?? 0}
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500">
              DNS Tunnel
            </div>

            <div className="mt-1 text-sm text-slate-200">
              {dns?.tunnel_classification ?? "N/A"}
            </div>

            <div className="text-xs text-slate-500">
              Score: {dns?.tunnel_score ?? 0}
            </div>
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-4 text-sm font-semibold text-slate-100">
          C2 Intelligence
        </h3>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="text-xs text-slate-500">
              Classification
            </div>

            <div className="mt-1 text-sm text-slate-200">
              {c2?.c2_classification ?? "N/A"}
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500">
              Behavior Score
            </div>

            <div className="mt-1 text-sm text-slate-200">
              {c2?.c2_behavior_score ?? 0}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}