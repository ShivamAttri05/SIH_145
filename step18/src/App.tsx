import { useEffect, useMemo, useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import Sidebar from "./components/Sidebar";

import Alerts from "./pages/Alerts";
import Analytics from "./pages/Analytics";
import Flows from "./pages/Flows";
import SystemHealth from "./pages/SystemHealth";
import Topology from "./pages/Topology";
import AlertTable from "./components/AlertTable";
import AlertDetails from "./components/AlertDetails";
import ThreatAnalytics from "./components/ThreatAnalytics";
import RiskTimeline from "./components/RiskTimeline";
import type { DetectionEvent } from "./types/detection";


const WS_URL = "ws://127.0.0.1:8000/ws/live";

const API_URL = "http://127.0.0.1:8000";


function Dashboard() {

  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [selectedAlert, setSelectedAlert] =
    useState<DetectionEvent | null>(null);

  const [, setConnected] = useState(false);


  useEffect(() => {

    // ========================================================
    // LOAD HISTORICAL ALERTS
    // ========================================================

    const loadHistoricalAlerts = async () => {

      try {

        const response = await fetch(
          `${API_URL}/api/v1/alerts`
        );


        if (!response.ok) {

          throw new Error(
            `HTTP ${response.status}`
          );

        }


        const data = await response.json();


        console.log(
          "HISTORICAL ALERTS LOADED:",
          data
        );


        setEvents(
          data.alerts
        );

      } catch (error) {

        console.error(
          "Failed to load historical alerts:",
          error
        );

      }

    };


    loadHistoricalAlerts();


    // ========================================================
    // CONNECT WEBSOCKET
    // ========================================================

    const socket = new WebSocket(
      WS_URL
    );


    socket.onopen = () => {

      console.log(
        "WebSocket connected."
      );

      setConnected(true);

    };


    socket.onmessage = (message) => {

      try {

        const event: DetectionEvent =
          JSON.parse(
            message.data
          );


        console.log(
          "LIVE EVENT RECEIVED:",
          event
        );


        setEvents(
          (previousEvents) => {

            const updatedEvents = [
              event,
              ...previousEvents,
            ];


            return updatedEvents.slice(
              0,
              100
            );

          }
        );

      } catch (error) {

        console.error(
          "Failed to parse WebSocket event:",
          error
        );

      }

    };


    socket.onclose = () => {

      console.log(
        "WebSocket disconnected."
      );

      setConnected(false);

    };


    socket.onerror = (error) => {

      console.error(
        "WebSocket error:",
        error
      );

      setConnected(false);

    };


    return () => {

      socket.close();

    };

  }, []);

  const statistics = useMemo(() => {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let benign = 0;

    for (const event of events) {
      if (event.severity === "CRITICAL") {
        critical++;
      } else if (event.severity === "HIGH") {
        high++;
      } else if (event.severity === "MEDIUM") {
        medium++;
      } else {
        benign++;
      }
    }

    const averageRisk =
      events.length > 0
        ? events.reduce(
          (sum, event) => sum + event.risk_score,
          0
        ) / events.length
        : 0;

    return {
      critical,
      high,
      medium,
      benign,
      averageRisk,
    };
  }, [events]);


  return (
    <div className="space-y-6">
      {/* Header */}

      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <div className="flex items-center gap-3">
            <div className="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.5)]" />

            <span className="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-400">
              System Operational
            </span>
          </div>

          <h1 className="mt-3 text-3xl font-bold tracking-tight text-[#f1f5f9]">
            SOC Overview
          </h1>

          <p className="mt-1 text-sm text-[#64748b]">
            Real-time cyber threat detection and network security monitoring
          </p>
        </div>

        <div className="rounded-lg border border-[#2a3038] bg-[#15181d] px-4 py-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#64748b]">
            Detection Mode
          </p>

          <p className="mt-1 text-sm font-medium text-[#d7dde5]">
            Passive PCAP Replay
          </p>
        </div>
      </div>

      {/* Statistics */}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Total Alerts
          </p>

          <div className="mt-3 flex items-end justify-between">
            <p className="text-3xl font-bold text-[#f1f5f9]">
              {events.length}
            </p>

            <span className="text-xs text-[#64748b]">
              Recorded
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-red-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Critical
          </p>

          <div className="mt-3 flex items-end justify-between">
            <p className="text-3xl font-bold text-red-400">
              {statistics.critical}
            </p>

            <span className="text-xs text-red-400/70">
              Immediate
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-orange-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            High Risk
          </p>

          <div className="mt-3 flex items-end justify-between">
            <p className="text-3xl font-bold text-orange-400">
              {statistics.high}
            </p>

            <span className="text-xs text-orange-400/70">
              Elevated
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-cyan-500/20 bg-[#15181d] p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-[#64748b]">
            Average Risk
          </p>

          <div className="mt-3 flex items-end justify-between">
            <p className="text-3xl font-bold text-cyan-400">
              {statistics.averageRisk.toFixed(1)}
            </p>

            <span className="text-xs text-[#64748b]">
              / 100
            </span>
          </div>
        </div>
      </div>

      {/* Main Analytics */}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-1">
          <ThreatAnalytics events={events} />
        </div>

        <div className="rounded-xl border border-[#2a3038] bg-[#15181d] p-1">
          <RiskTimeline events={events} />
        </div>
      </div>

      {/* Live Events */}

      <div>
        <AlertTable
          events={events}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
        />
      </div>

      {/* Alert Details */}

      {selectedAlert && (
        <AlertDetails
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  );

}

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-950">
        <Sidebar />

        <main className="ml-64 min-h-screen p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />

            <Route
              path="/alerts"
              element={<Alerts />}
            />

            <Route
              path="/analytics"
              element={<Analytics />}
            />

            <Route
              path="/flows"
              element={<Flows />}
            />

            <Route
              path="/health"
              element={<SystemHealth />}
            />

            <Route
              path="/topology"
              element={<Topology />}
            />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;