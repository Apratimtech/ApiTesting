"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import mqtt, { MqttClient } from "mqtt";
import {
  Bolt,
  Link2,
  Send,
  Wand2,
  Bell,
  Upload,
  ShieldAlert,
  Activity,
  Clock3,
  Terminal,
  Ban,
  Copy,
} from "lucide-react";

type LogType =
  | "SYS"
  | "INFO"
  | "WARN"
  | "ERROR"
  | "IN"
  | "OUT";

type LogEntry = {
  type: LogType;
  message: string;
  topic?: string;
  timestamp: string;
};

type SecurityFinding = {
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  description: string;
};

export default function MQTTConsolePage() {
  const clientRef = useRef<MqttClient | null>(null);

  const [mounted, setMounted] = useState(false);

  const [connected, setConnected] = useState(false);

  const [brokerUrl, setBrokerUrl] = useState(
    "wss://broker.emqx.io:8084/mqtt"
  );

  const [clientId, setClientId] = useState("");

  const [username, setUsername] = useState("");

  const [password, setPassword] = useState("");

  const [topic, setTopic] = useState("devtools/test/topic");

  const [payload, setPayload] = useState(`{
  "device_id": "sensor_x42",
  "status": "active",
  "telemetry": {
    "temperature": 24.5,
    "humidity": 48.2,
    "units": "celsius"
  },
  "timestamp": 1723459122
}`);

  const [retain, setRetain] = useState(false);

  const [qos, setQos] = useState(2);

  const [logs, setLogs] = useState<LogEntry[]>([]);

  const [activeTab, setActiveTab] = useState<
    "logs" | "timing" | "security"
  >("logs");

  const [latency, setLatency] = useState("--");

  const [riskScore, setRiskScore] = useState(12);

  const [securityFindings, setSecurityFindings] = useState<
    SecurityFinding[]
  >([]);

  useEffect(() => {
    setMounted(true);

    setClientId(
      `trustedge_${Math.random()
        .toString(16)
        .slice(2, 8)}`
    );

    addLog(
      "SYS",
      "Initializing secure socket layer..."
    );

    addLog(
      "INFO",
      "Broker URL resolved to 12.44.1.92"
    );

    addLog(
      "WARN",
      "Handshake attempt timed out. Retrying in 2s..."
    );
  }, []);

  const addLog = (
    type: LogType,
    message: string,
    topic?: string
  ) => {
    const timestamp = new Date().toLocaleTimeString(
      [],
      {
        hour12: false,
      }
    );

    setLogs((prev) => [
      ...prev,
      {
        type,
        message,
        topic,
        timestamp,
      },
    ]);
  };

  const updateSecurity = (
    url: string,
    payloadText: string
  ) => {
    const findings: SecurityFinding[] = [];

    let score = 0;

    if (!url.startsWith("wss://")) {
      findings.push({
        severity: "HIGH",
        title: "Insecure MQTT Transport",
        description:
          "Broker uses unencrypted WebSocket transport.",
      });

      score += 35;
    }

    if (
      payloadText.includes("password") ||
      payloadText.includes("token") ||
      payloadText.includes("secret")
    ) {
      findings.push({
        severity: "CRITICAL",
        title: "Sensitive Data Exposure",
        description:
          "Payload contains plaintext sensitive data.",
      });

      score += 40;
    }

    if (
      payloadText.includes("<script>") ||
      payloadText.includes("javascript:")
    ) {
      findings.push({
        severity: "HIGH",
        title: "Potential XSS Payload",
        description:
          "Payload contains suspicious script injection patterns.",
      });

      score += 25;
    }

    if (
      payloadText.includes("' OR 1=1") ||
      payloadText.includes("DROP TABLE")
    ) {
      findings.push({
        severity: "CRITICAL",
        title: "SQL Injection Attempt",
        description:
          "Potential SQL injection payload detected.",
      });

      score += 45;
    }

    if (
      payloadText.includes("../") ||
      payloadText.includes("..\\")
    ) {
      findings.push({
        severity: "HIGH",
        title: "Path Traversal Attempt",
        description:
          "Payload contains directory traversal sequences.",
      });

      score += 30;
    }

    if (findings.length === 0) {
      findings.push({
        severity: "LOW",
        title: "Secure MQTT Configuration",
        description:
          "No major vulnerabilities detected in current session.",
      });

      score = 12;
    }

    setRiskScore(Math.min(score, 100));

    setSecurityFindings(findings);
  };

  const connectBroker = () => {
    try {
      addLog(
        "INFO",
        `Establishing WebSocket connection to ${brokerUrl}`
      );

      updateSecurity(brokerUrl, payload);

      const start = performance.now();

      const client = mqtt.connect(brokerUrl, {
        clientId,
        username,
        password,
        reconnectPeriod: 2000,
        clean: true,
      });

      clientRef.current = client;

      client.on("connect", () => {
        const end = performance.now();

        setLatency(`${Math.floor(end - start)}ms`);

        setConnected(true);

        addLog("SYS", "Awaiting CONNACK...");
        addLog(
          "INFO",
          "MQTT broker connection established"
        );
      });

      client.on("message", (topic, message) => {
        addLog(
          "IN",
          message.toString(),
          topic
        );
      });

      client.on("close", () => {
        setConnected(false);

        addLog(
          "WARN",
          "Broker connection closed"
        );
      });

      client.on("error", (err) => {
        addLog(
          "ERROR",
          err.message
        );
      });
    } catch (err: any) {
      addLog(
        "ERROR",
        err.message || "Connection failed"
      );
    }
  };

  const disconnectBroker = () => {
    clientRef.current?.end();

    setConnected(false);

    addLog(
      "SYS",
      "Disconnected from MQTT broker"
    );
  };

  const publishMessage = () => {
    if (!clientRef.current || !connected) {
      addLog(
        "ERROR",
        "Cannot publish while disconnected"
      );

      return;
    }

    clientRef.current.publish(
      topic,
      payload,
      {
        qos,
        retain,
      }
    );

    addLog(
      "OUT",
      payload,
      topic
    );

    updateSecurity(brokerUrl, payload);
  };

  const subscribeTopic = () => {
    if (!clientRef.current || !connected) {
      addLog(
        "ERROR",
        "Cannot subscribe while disconnected"
      );

      return;
    }

    clientRef.current.subscribe(
      topic,
      {
        qos,
      },
      (err) => {
        if (err) {
          addLog(
            "ERROR",
            "Subscription failed"
          );
        } else {
          addLog(
            "SYS",
            `Subscribed to ${topic}`
          );
        }
      }
    );
  };

  const beautifyJSON = () => {
    try {
      const parsed = JSON.parse(payload);

      setPayload(
        JSON.stringify(parsed, null, 2)
      );

      addLog(
        "INFO",
        "Payload beautified successfully"
      );
    } catch {
      addLog(
        "ERROR",
        "Invalid JSON payload"
      );
    }
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const riskLabel = useMemo(() => {
    if (riskScore >= 80) return "CRITICAL";

    if (riskScore >= 60) return "HIGH";

    if (riskScore >= 30) return "MEDIUM";

    return "LOW";
  }, [riskScore]);

  if (!mounted) return null;

  return (
    <main className="min-h-screen bg-[#03101f] text-[#d9e7ff]">
      <div className="p-6 max-w-[1600px] mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-10">
          <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-cyan-400 to-purple-600 flex items-center justify-center shadow-[0_0_30px_rgba(139,92,246,0.5)]">
            <Bolt className="w-7 h-7 text-black" />
          </div>

          <div>
            <h1 className="text-5xl font-extrabold bg-gradient-to-r from-cyan-300 to-purple-400 bg-clip-text text-transparent">
              MQTT Console
            </h1>

            <div className="flex items-center gap-2 mt-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  connected
                    ? "bg-cyan-400 animate-pulse"
                    : "bg-red-400"
                }`}
              />

              <span
                className={`text-xs uppercase tracking-[0.2em] font-bold ${
                  connected
                    ? "text-cyan-300"
                    : "text-red-300"
                }`}
              >
                {connected
                  ? "Connected"
                  : "Disconnected"}
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-6">
          {/* LEFT */}
          <section className="col-span-12 lg:col-span-5 rounded-2xl border border-cyan-400/20 bg-[#07172b]/80 backdrop-blur-xl p-6">
            <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-6">
              <div className="flex items-center gap-3">
                <Link2 className="w-5 h-5 text-cyan-300" />

                <h2 className="text-3xl font-bold">
                  Connection Settings
                </h2>
              </div>

              <div className="px-3 py-1 rounded-full text-xs border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
                READY
              </div>
            </div>

            <div className="space-y-5">
              <div>
                <label className="text-xs uppercase text-gray-400 block mb-2">
                  Broker URL
                </label>

                <input
                  value={brokerUrl}
                  onChange={(e) =>
                    setBrokerUrl(e.target.value)
                  }
                  className="w-full bg-[#0b1d33] border border-white/10 rounded-xl p-4 outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-xs uppercase text-gray-400 block mb-2">
                  Client ID
                </label>

                <input
                  value={clientId}
                  onChange={(e) =>
                    setClientId(e.target.value)
                  }
                  className="w-full bg-[#0b1d33] border border-white/10 rounded-xl p-4 outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs uppercase text-gray-400 block mb-2">
                    Username
                  </label>

                  <input
                    value={username}
                    onChange={(e) =>
                      setUsername(e.target.value)
                    }
                    className="w-full bg-[#0b1d33] border border-white/10 rounded-xl p-4 outline-none"
                  />
                </div>

                <div>
                  <label className="text-xs uppercase text-gray-400 block mb-2">
                    Password
                  </label>

                  <input
                    type="password"
                    value={password}
                    onChange={(e) =>
                      setPassword(e.target.value)
                    }
                    className="w-full bg-[#0b1d33] border border-white/10 rounded-xl p-4 outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs uppercase text-gray-400 block mb-2">
                    QoS Level
                  </label>

                  <select
                    value={qos}
                    onChange={(e) =>
                      setQos(Number(e.target.value))
                    }
                    className="w-full bg-[#0b1d33] border border-white/10 rounded-xl p-4 outline-none"
                  >
                    <option value={0}>
                      QoS 0
                    </option>
                    <option value={1}>
                      QoS 1
                    </option>
                    <option value={2}>
                      QoS 2
                    </option>
                  </select>
                </div>

                <div className="flex items-end">
                  <button
                    onClick={() =>
                      setRetain(!retain)
                    }
                    className={`w-full p-4 rounded-xl border transition-all ${
                      retain
                        ? "bg-cyan-400/20 border-cyan-400 text-cyan-300"
                        : "bg-[#0b1d33] border-white/10"
                    }`}
                  >
                    Retain:{" "}
                    {retain
                      ? "Enabled"
                      : "Disabled"}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-4 pt-3">
                <button
                  onClick={connectBroker}
                  className="col-span-3 py-4 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 text-black font-bold hover:brightness-110 transition-all"
                >
                  Connect Broker
                </button>

                <button
                  onClick={disconnectBroker}
                  className="border border-red-400/20 rounded-xl text-red-300 hover:bg-red-400/10 transition-all"
                >
                  Disconnect
                </button>
              </div>
            </div>
          </section>

          {/* RIGHT */}
          <section className="col-span-12 lg:col-span-7 rounded-2xl border border-purple-400/20 bg-[#07172b]/80 backdrop-blur-xl p-6">
            <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-6">
              <div className="flex items-center gap-3">
                <Send className="w-5 h-5 text-purple-300" />

                <h2 className="text-3xl font-bold">
                  Publish Message
                </h2>
              </div>

              <button
                onClick={beautifyJSON}
                className="flex items-center gap-2 text-cyan-300 hover:text-white"
              >
                <Wand2 className="w-4 h-4" />
                Beautify JSON
              </button>
            </div>

            <div className="space-y-5">
              <div>
                <label className="text-xs uppercase text-gray-400 block mb-2">
                  Topic
                </label>

                <input
                  value={topic}
                  onChange={(e) =>
                    setTopic(e.target.value)
                  }
                  className="w-full bg-[#0b1d33] border border-white/10 rounded-xl p-4 outline-none"
                />
              </div>

              <div>
                <label className="text-xs uppercase text-gray-400 block mb-2">
                  Message Payload
                </label>

                <textarea
                  value={payload}
                  onChange={(e) =>
                    setPayload(e.target.value)
                  }
                  spellCheck={false}
                  className="w-full min-h-[320px] bg-[#020b18] border border-white/10 rounded-xl p-5 font-mono text-sm outline-none resize-none text-cyan-100"
                />
              </div>

              <div className="grid grid-cols-4 gap-4">
                <button
                  onClick={publishMessage}
                  className="col-span-3 py-4 rounded-xl bg-[#d7b6ff] text-purple-900 font-bold flex items-center justify-center gap-2 hover:brightness-110"
                >
                  <Upload className="w-4 h-4" />
                  Publish Message
                </button>

                <button
                  onClick={subscribeTopic}
                  className="rounded-xl border border-white/10 bg-[#16273b] hover:bg-[#22354a] transition-all flex items-center justify-center gap-2"
                >
                  <Bell className="w-4 h-4" />
                  Subscribe
                </button>
              </div>
            </div>
          </section>

          {/* BOTTOM */}
          <section className="col-span-12 grid grid-cols-12 gap-6">
            {/* RISK */}
            <div className="col-span-12 lg:col-span-3 rounded-2xl border border-white/10 bg-[#07172b]/80 backdrop-blur-xl p-6">
              <div className="text-center">
                <p className="text-xs uppercase tracking-[0.2em] text-gray-400 mb-8">
                  Overall Security Risk
                </p>

                <div className="w-40 h-40 mx-auto rounded-full border-[10px] border-cyan-200/20 flex items-center justify-center relative">
                  <div className="text-center">
                    <div className="text-6xl font-extrabold text-cyan-200">
                      {riskScore}
                    </div>
                  </div>
                </div>

                <div className="mt-6 inline-flex px-4 py-2 rounded-full bg-cyan-400/10 border border-cyan-400/20 text-cyan-200 text-sm font-bold uppercase">
                  {riskLabel} Risk Environment
                </div>
              </div>
            </div>

            {/* LOGS */}
            <div className="col-span-12 lg:col-span-9 rounded-2xl border border-white/10 bg-[#07172b]/80 backdrop-blur-xl overflow-hidden">
              <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
                <div className="flex items-center gap-6">
                  <button
                    onClick={() =>
                      setActiveTab("logs")
                    }
                    className={`text-sm font-bold ${
                      activeTab === "logs"
                        ? "text-cyan-300"
                        : "text-gray-400"
                    }`}
                  >
                    Live Logs
                  </button>

                  <button
                    onClick={() =>
                      setActiveTab("timing")
                    }
                    className={`text-sm font-bold ${
                      activeTab === "timing"
                        ? "text-cyan-300"
                        : "text-gray-400"
                    }`}
                  >
                    Timing
                  </button>

                  <button
                    onClick={() =>
                      setActiveTab("security")
                    }
                    className={`text-sm font-bold ${
                      activeTab === "security"
                        ? "text-cyan-300"
                        : "text-gray-400"
                    }`}
                  >
                    Security Scan
                  </button>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs uppercase tracking-[0.2em] text-gray-400">
                    MQTT Packet Stream
                  </span>

                  <button
                    onClick={clearLogs}
                    className="text-gray-400 hover:text-red-300"
                  >
                    <Ban className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="h-[300px] overflow-auto p-6 font-mono text-sm">
                {activeTab === "logs" && (
                  <div className="space-y-3">
                    {logs.map((log, index) => (
                      <div
                        key={index}
                        className="flex gap-3 border-b border-white/5 pb-2"
                      >
                        <span className="text-white/30 whitespace-nowrap">
                          [{log.timestamp}]
                        </span>

                        <span
                          className={`font-bold w-[60px] ${
                            log.type === "ERROR"
                              ? "text-red-300"
                              : log.type === "WARN"
                              ? "text-yellow-300"
                              : log.type === "OUT"
                              ? "text-purple-300"
                              : log.type === "IN"
                              ? "text-cyan-300"
                              : "text-white"
                          }`}
                        >
                          {log.type}
                        </span>

                        <span className="text-cyan-300">
                          {log.topic
                            ? `[${log.topic}]`
                            : ""}
                        </span>

                        <span className="text-gray-300 break-all">
                          {log.message}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === "timing" && (
                  <div className="space-y-4">
                    <div className="rounded-xl bg-black/20 border border-white/10 p-5 flex items-center gap-4">
                      <Clock3 className="w-6 h-6 text-cyan-300" />

                      <div>
                        <p className="text-sm text-gray-400">
                          Connection Latency
                        </p>

                        <p className="text-3xl font-bold text-cyan-300">
                          {latency}
                        </p>
                      </div>
                    </div>

                    <div className="rounded-xl bg-black/20 border border-white/10 p-5 flex items-center gap-4">
                      <Activity className="w-6 h-6 text-purple-300" />

                      <div>
                        <p className="text-sm text-gray-400">
                          MQTT Messages
                        </p>

                        <p className="text-3xl font-bold text-purple-300">
                          {logs.filter(
                            (l) =>
                              l.type === "IN" ||
                              l.type === "OUT"
                          ).length}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === "security" && (
                  <div className="space-y-4">
                    {securityFindings.map(
                      (finding, index) => (
                        <div
                          key={index}
                          className="rounded-xl border border-white/10 bg-black/20 p-5"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-3">
                              <ShieldAlert className="w-5 h-5 text-red-300" />

                              <h3 className="font-bold text-lg">
                                {finding.title}
                              </h3>
                            </div>

                            <span
                              className={`px-3 py-1 rounded-full text-xs font-bold ${
                                finding.severity ===
                                "CRITICAL"
                                  ? "bg-red-400/10 text-red-300"
                                  : finding.severity ===
                                    "HIGH"
                                  ? "bg-orange-400/10 text-orange-300"
                                  : finding.severity ===
                                    "MEDIUM"
                                  ? "bg-purple-400/10 text-purple-300"
                                  : "bg-cyan-400/10 text-cyan-300"
                              }`}
                            >
                              {finding.severity}
                            </span>
                          </div>

                          <p className="text-gray-400 leading-relaxed">
                            {finding.description}
                          </p>
                        </div>
                      )
                    )}
                  </div>
                )}
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
