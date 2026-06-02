"use client";

import { useEffect, useRef, useState } from "react";
import {
  Shield,
  Trash2,
  Plus,
  Wand2,
  Radio,
  AlertTriangle,
} from "lucide-react";

type MetadataItem = {
  key: string;
  value: string;
};

type Vulnerability = {
  severity: string;
  issue: string;
  description: string;
  category?: string;
  recommendation?: string;
};

export default function GrpcPage() {
  const connectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [scanning, setScanning] = useState(false);

  const [streaming, setStreaming] = useState(false);
  const [useTls, setUseTls] = useState(true);

  const [activeTab, setActiveTab] = useState<
    "Response" | "Metadata" | "Timing" | "Security Scan"
  >("Security Scan");

  const [latency, setLatency] = useState(0);
  const [riskScore, setRiskScore] = useState(0);

  const [riskLevel, setRiskLevel] = useState<
    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  >("LOW");

  const [invoking, setInvoking] = useState(false);
  const [error, setError] = useState("");

  const [serverUrl, setServerUrl] = useState(
    "grpc://localhost:50051"
  );

  const [serviceName, setServiceName] = useState(
    "AnalyzerService"
  );

  const [methodName, setMethodName] = useState(
    "Analyze"
  );

  const [payload, setPayload] = useState(
    JSON.stringify(
      {
        username: "admin",
        password: "' OR 1=1 --",
        token: "jwt_token_here",
      },
      null,
      2
    )
  );

  const [metadata, setMetadata] = useState<
    MetadataItem[]
  >([
    {
      key: "authorization",
      value: "Bearer jwt_token_here",
    },
    {
      key: "x-client-id",
      value: "grpc-console",
    },
  ]);

  const [responseBody, setResponseBody] =
    useState(
      "// Execute request to see response"
    );

  const [timingResponse, setTimingResponse] =
    useState<any>({});

  const [metadataResponse, setMetadataResponse] =
    useState<any>({});

  const [vulnerabilities, setVulnerabilities] =
    useState<Vulnerability[]>([]);

  useEffect(() => {
    return () => {
      if (connectTimeoutRef.current) {
        clearTimeout(connectTimeoutRef.current);
      }
    };
  }, []);

  const validatePayload = () => {
    try {
      return JSON.parse(payload);
    } catch {
      setError("Invalid JSON payload");
      return null;
    }
  };

  const beautify = () => {
    const parsed = validatePayload();

    if (!parsed) return;

    setPayload(
      JSON.stringify(parsed, null, 2)
    );

    setError("");
  };

  const addMetadata = () => {
    setMetadata((prev) => [
      ...prev,
      {
        key: "",
        value: "",
      },
    ]);
  };

  const removeMetadata = (index: number) => {
    setMetadata((prev) =>
      prev.filter((_, i) => i !== index)
    );
  };

  const updateMetadata = (
    index: number,
    field: "key" | "value",
    value: string
  ) => {
    setMetadata((prev) =>
      prev.map((item, i) =>
        i === index
          ? {
              ...item,
              [field]: value,
            }
          : item
      )
    );
  };

  const connect = () => {
    if (connecting) return;

    setError("");

    if (!serverUrl.trim()) {
      setError("Server URL is required");
      return;
    }

    setConnecting(true);

    connectTimeoutRef.current =
      setTimeout(() => {
        setConnecting(false);
        setConnected(true);
      }, 800);
  };

  const invoke = async () => {
    if (invoking) return;

    setError("");
    setScanning(true);
    setInvoking(true);

    const parsedPayload = validatePayload();

    if (!parsedPayload) {
      setInvoking(false);
      setScanning(false);
      return;
    }

    try {
      const headersObject: Record<
        string,
        string
      > = {};

      metadata.forEach((item) => {
        if (item.key.trim()) {
          headersObject[item.key] =
            item.value;
        }
      });

      const requestBody = {
        request: {
          protocol: "grpc",
          target: serverUrl,
          service: serviceName,
          method: methodName,
          headers: headersObject,
          body: parsedPayload,
          streaming,
          tls: useTls,
        },
      };

      const start = performance.now();

      const response = await fetch(
        "http://127.0.0.1:8000/api/v1/analyze",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify(
            requestBody
          ),
        }
      );

      if (!response.ok) {
        throw new Error(
          `HTTP ${response.status}`
        );
      }

      const data = await response.json();

      const end = performance.now();

      const executionTime = Math.floor(
        end - start
      );

      setLatency(executionTime);

      setRiskScore(
        data.overall_risk_score || 0
      );

      setRiskLevel(
        data.severity || "LOW"
      );

      setVulnerabilities(
        data.findings || []
      );

      // ONLY CLEAN RESPONSE TAB
      const cleanResponse = {
        success: data.success,
        timestamp: data.timestamp,
        severity: data.severity,
        summary: data.summary,
      };

      setResponseBody(
        JSON.stringify(
          cleanResponse,
          null,
          2
        )
      );

      // REAL METADATA TAB
      setMetadataResponse({
        grpc: true,
        tls_enabled: useTls,
        streaming,
        service: serviceName,
        method: methodName,
        endpoint: serverUrl,
      });

      // REAL TIMING TAB
      setTimingResponse({
        latency: `${executionTime}ms`,
        analyzed_at:
          data.timestamp,
      });

      setActiveTab(
        "Security Scan"
      );
    } catch (err) {
      console.error(err);

      setError(
        "Failed to connect backend analyzer"
      );

      setResponseBody(
        "// Backend connection failed"
      );
    } finally {
      setInvoking(false);
      setScanning(false);
    }
  };

  return (
    <main className="min-h-screen bg-[#0c1324] text-[#dce1fb] p-8">
      <div className="max-w-[1440px] mx-auto flex flex-col gap-6">
        {/* HEADER */}
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-5xl font-extrabold tracking-tight bg-gradient-to-r from-purple-300 to-cyan-300 bg-clip-text text-transparent drop-shadow-[0_0_15px_rgba(221,183,255,0.4)]">
              gRPC Console
            </h1>

            <p className="text-cyan-300 text-xs uppercase tracking-[0.3em] mt-3 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Enterprise RPC Security
              Testing
            </p>
          </div>

          <div className="flex items-center gap-6 text-sm">
            <div>
              <p className="text-gray-400 text-xs uppercase">
                Latency
              </p>

              <p className="text-cyan-300 font-mono">
                {latency}ms
              </p>
            </div>

            <div className="w-px h-8 bg-white/10" />

            <div>
              <p className="text-gray-400 text-xs uppercase">
                Protocol
              </p>

              <p className="text-purple-300 font-mono">
                {useTls
                  ? "h2 (TLS 1.3)"
                  : "h2c"}
              </p>
            </div>
          </div>
        </div>

        {/* ERROR */}
        {error && (
          <div className="border border-red-400/20 bg-red-400/10 text-red-300 px-4 py-3 rounded-2xl text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* LEFT PANEL */}
          <section className="lg:col-span-5 rounded-2xl border border-white/10 bg-[#151b2d]/70 backdrop-blur-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-cyan-300">
                Connection Settings
              </h2>

              <div
                className={`px-3 py-1 rounded-full text-xs border flex items-center gap-2 ${
                  connected
                    ? "border-purple-400/20 text-purple-300 bg-purple-400/10"
                    : "border-red-400/20 text-red-300 bg-red-400/10"
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    connected
                      ? "bg-purple-300 animate-pulse"
                      : "bg-red-400"
                  }`}
                />

                {connected
                  ? "READY"
                  : "DISCONNECTED"}
              </div>
            </div>

            <div className="space-y-5">
              {/* SERVER URL */}
              <div>
                <label className="text-xs uppercase text-gray-400 block mb-2">
                  Server URL
                </label>

                <input
                  value={serverUrl}
                  onChange={(e) =>
                    setServerUrl(
                      e.target.value
                    )
                  }
                  className="w-full bg-[#0f172a] border border-white/10 rounded-xl p-3 outline-none focus:border-cyan-400"
                />
              </div>

              {/* SERVICE + METHOD */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs uppercase text-gray-400 block mb-2">
                    Service
                  </label>

                  <input
                    value={serviceName}
                    onChange={(e) =>
                      setServiceName(
                        e.target.value
                      )
                    }
                    className="w-full bg-[#0f172a] border border-white/10 rounded-xl p-3 outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="text-xs uppercase text-gray-400 block mb-2">
                    Method
                  </label>

                  <input
                    value={methodName}
                    onChange={(e) =>
                      setMethodName(
                        e.target.value
                      )
                    }
                    className="w-full bg-[#0f172a] border border-white/10 rounded-xl p-3 outline-none focus:border-cyan-400"
                  />
                </div>
              </div>

              {/* TLS */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Shield className="w-5 h-5 text-cyan-300" />

                    <span>
                      TLS Encryption
                    </span>
                  </div>

                  <button
                    onClick={() =>
                      setUseTls(
                        !useTls
                      )
                    }
                    className={`w-12 h-6 rounded-full transition-all ${
                      useTls
                        ? "bg-cyan-400"
                        : "bg-gray-600"
                    }`}
                  >
                    <div
                      className={`w-4 h-4 bg-white rounded-full transition-all ${
                        useTls
                          ? "translate-x-7"
                          : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>

                {/* STREAMING */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Radio className="w-5 h-5 text-purple-300" />

                    <span>
                      Streaming Mode
                    </span>
                  </div>

                  <button
                    onClick={() =>
                      setStreaming(
                        !streaming
                      )
                    }
                    className={`w-12 h-6 rounded-full transition-all ${
                      streaming
                        ? "bg-purple-500"
                        : "bg-gray-600"
                    }`}
                  >
                    <div
                      className={`w-4 h-4 bg-white rounded-full transition-all ${
                        streaming
                          ? "translate-x-7"
                          : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>
              </div>

              {/* METADATA */}
              <div className="bg-black/20 rounded-2xl p-4 border border-white/5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm uppercase text-gray-400">
                    Metadata
                  </h3>

                  <button
                    onClick={
                      addMetadata
                    }
                    className="text-cyan-300"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>

                <div className="space-y-3">
                  {metadata.map(
                    (
                      item,
                      index
                    ) => (
                      <div
                        key={index}
                        className="flex gap-2"
                      >
                        <input
                          value={
                            item.key
                          }
                          onChange={(
                            e
                          ) =>
                            updateMetadata(
                              index,
                              "key",
                              e.target
                                .value
                            )
                          }
                          placeholder="Key"
                          className="flex-1 bg-[#0f172a] border border-white/10 rounded-lg p-2 text-sm"
                        />

                        <input
                          value={
                            item.value
                          }
                          onChange={(
                            e
                          ) =>
                            updateMetadata(
                              index,
                              "value",
                              e.target
                                .value
                            )
                          }
                          placeholder="Value"
                          className="flex-1 bg-[#0f172a] border border-white/10 rounded-lg p-2 text-sm"
                        />

                        <button
                          onClick={() =>
                            removeMetadata(
                              index
                            )
                          }
                          className="text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    )
                  )}
                </div>
              </div>

              {/* CONNECT */}
              <button
                onClick={connect}
                disabled={
                  connecting
                }
                className="w-full py-4 rounded-xl bg-gradient-to-r from-purple-500 to-cyan-500 font-bold"
              >
                {connecting
                  ? "Verifying Endpoint..."
                  : "Connect to Server"}
              </button>
            </div>
          </section>

          {/* REQUEST PANEL */}
          <section className="lg:col-span-7 rounded-2xl border border-cyan-400/20 bg-[#151b2d]/70 backdrop-blur-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-cyan-300">
                Request / Invoke
                Panel
              </h2>

              <button
                onClick={beautify}
                className="flex items-center gap-2 text-sm text-cyan-300"
              >
                <Wand2 className="w-4 h-4" />
                Beautify
              </button>
            </div>

            <div className="bg-[#0f172a] rounded-2xl border border-white/5 overflow-hidden min-h-[350px] flex flex-col">
              <textarea
                value={payload}
                onChange={(e) =>
                  setPayload(
                    e.target.value
                  )
                }
                spellCheck={false}
                className="flex-1 bg-transparent p-5 font-mono text-sm outline-none resize-none text-purple-200"
              />
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6">
              <button
                onClick={invoke}
                disabled={
                  invoking
                }
                className="col-span-3 py-4 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-500 font-bold"
              >
                {invoking
                  ? "Analyzing Security..."
                  : "Invoke Request"}
              </button>

              <button
                onClick={() =>
                  setPayload("{}")
                }
                className="border border-red-400/20 rounded-xl text-red-300"
              >
                Reset
              </button>
            </div>
          </section>

          {/* TABS */}
          <section className="lg:col-span-12 rounded-2xl border border-white/10 bg-[#151b2d]/70 overflow-hidden">
            <div className="flex border-b border-white/10 overflow-x-auto">
              {[
                "Response",
                "Metadata",
                "Timing",
                "Security Scan",
              ].map((tab) => (
                <button
                  key={tab}
                  onClick={() =>
                    setActiveTab(
                      tab as any
                    )
                  }
                  className={`px-8 py-4 text-xs uppercase font-bold whitespace-nowrap ${
                    activeTab ===
                    tab
                      ? "text-purple-300 border-b-2 border-purple-300 bg-purple-300/5"
                      : "text-gray-400"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            <div className="p-6 min-h-[420px] overflow-auto">
              {/* RESPONSE */}
              {activeTab ===
                "Response" && (
                <pre className="font-mono text-sm text-gray-200 whitespace-pre-wrap">
                  {
                    responseBody
                  }
                </pre>
              )}

              {/* METADATA */}
              {activeTab ===
                "Metadata" && (
                <pre className="font-mono text-sm text-gray-200 whitespace-pre-wrap">
                  {JSON.stringify(
                    metadataResponse,
                    null,
                    2
                  )}
                </pre>
              )}

              {/* TIMING */}
              {activeTab ===
                "Timing" && (
                <pre className="font-mono text-sm text-gray-200 whitespace-pre-wrap">
                  {JSON.stringify(
                    timingResponse,
                    null,
                    2
                  )}
                </pre>
              )}

              {/* SECURITY */}
              {activeTab ===
                "Security Scan" && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  <div className="lg:col-span-3 rounded-2xl border border-white/5 bg-black/20 p-6 flex flex-col items-center justify-center">
                    <span className="text-xs uppercase text-gray-400 mb-4">
                      Overall Risk
                      Score
                    </span>

                    <div className="text-6xl font-extrabold text-purple-300">
                      {
                        riskScore
                      }
                    </div>

                    <div
                      className={`mt-4 px-4 py-2 rounded-full text-xs uppercase font-bold ${
                        riskLevel ===
                        "CRITICAL"
                          ? "bg-red-500/20 text-red-300"
                          : riskLevel ===
                            "HIGH"
                          ? "bg-orange-500/20 text-orange-300"
                          : riskLevel ===
                            "MEDIUM"
                          ? "bg-purple-400/10 text-purple-300"
                          : "bg-cyan-400/10 text-cyan-300"
                      }`}
                    >
                      {
                        riskLevel
                      }{" "}
                      Risk
                    </div>
                  </div>

                  <div className="lg:col-span-9">
                    {scanning ? (
                      <div className="flex flex-col items-center justify-center h-64 text-cyan-300 gap-3">
                        <div className="animate-pulse text-xl">
                          🔍
                          Analyzing
                          Request...
                        </div>

                        <p className="text-sm text-gray-400">
                          Please
                          wait
                        </p>
                      </div>
                    ) : vulnerabilities.length ===
                      0 ? (
                      <div className="text-center py-16 text-gray-400">
                        No
                        vulnerabilities
                        detected.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {vulnerabilities.map(
                          (
                            vuln,
                            index
                          ) => (
                            <div
                              key={
                                index
                              }
                              className="rounded-2xl border border-white/5 bg-black/20 p-5"
                            >
                              <div className="flex justify-between items-start mb-4">
                                <span
                                  className={`text-xs px-3 py-1 rounded-full font-bold ${
                                    vuln.severity ===
                                    "CRITICAL"
                                      ? "bg-red-500/20 text-red-300"
                                      : vuln.severity ===
                                        "HIGH"
                                      ? "bg-orange-500/20 text-orange-300"
                                      : vuln.severity ===
                                        "MEDIUM"
                                      ? "bg-yellow-500/20 text-yellow-300"
                                      : "bg-blue-500/20 text-blue-300"
                                  }`}
                                >
                                  {
                                    vuln.severity
                                  }
                                </span>

                                <span className="text-xs text-gray-500">
                                  {
                                    vuln.category
                                  }
                                </span>
                              </div>

                              <h3 className="font-bold mb-2">
                                {
                                  vuln.issue
                                }
                              </h3>

                              <p className="text-sm text-gray-400 mb-3">
                                {
                                  vuln.description
                                }
                              </p>

                              {vuln.recommendation && (
                                <div className="text-xs text-cyan-300 border-t border-white/5 pt-3">
                                  <strong>
                                    Recommendation:
                                  </strong>

                                  <br />

                                  {
                                    vuln.recommendation
                                  }
                                </div>
                              )}
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
