interface ConnectionStatusProps {
  connected: boolean;
}

export default function ConnectionStatus({
  connected,
}: ConnectionStatusProps) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-4 py-2">
      <span
        className={`h-2.5 w-2.5 rounded-full ${
          connected
            ? "bg-emerald-400"
            : "bg-red-500"
        }`}
      />

      <span className="text-sm text-slate-300">
        {connected
          ? "WEBSOCKET CONNECTED"
          : "WEBSOCKET DISCONNECTED"}
      </span>
    </div>
  );
}