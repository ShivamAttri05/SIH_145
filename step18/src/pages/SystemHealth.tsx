export default function SystemHealth() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <h1 className="text-2xl font-semibold text-white">
        System Health
      </h1>

      <p className="mt-2 text-sm text-slate-500">
        Detection engine, API, database and WebSocket health.
      </p>
    </div>
  );
}