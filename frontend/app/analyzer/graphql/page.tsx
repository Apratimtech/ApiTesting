"use client";
import { useEffect, useMemo, useState, useCallback } from "react";
import {
  Play,
  Shield,
  History,
  Database,
  FileJson,
  Plus,
  Trash2,
  Link2,
  RotateCcw,
  Loader2,
  AlertTriangle,
  Lock,
  Globe,
  Server,
  Eye,
  EyeOff,
  Sparkles,
  Wifi,
  WifiOff,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";

type HeaderItem = { key: string; value: string };
type HistoryItem = { name: string; info: string };

// ─── FIX #1: Backend URL is a constant — never changes based on user input ───
const BACKEND_URL = "http://localhost:8000/graphql/execute";

export default function GraphQLConsolePage() {
  const [activeTab, setActiveTab] = useState<"response" | "schema" | "history" | "security">("response");

  // ─── FIX #1 cont: "endpoint" now means the TARGET GraphQL API the backend forwards to ───
  const [endpoint, setEndpoint] = useState("https://countries.trevorblades.com/graphql");
  const [authType, setAuthType] = useState("Bearer Token");
  const [authValue, setAuthValue] = useState("");
  const [showAuth, setShowAuth] = useState(false);

  const [headers, setHeaders] = useState<HeaderItem[]>([
    { key: "Content-Type", value: "application/json" },
  ]);

  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [query, setQuery] = useState(`query {\n  health\n}`);
  const [response, setResponse] = useState("");
  const [schema, setSchema] = useState("");

  const [loading, setLoading] = useState(false);
  const [statusCode, setStatusCode] = useState("0");
  const [responseTime, setResponseTime] = useState("0ms");
  const [responseSize, setResponseSize] = useState("0kb");

  const [riskScore, setRiskScore] = useState(0);
  const [securityMessage, setSecurityMessage] = useState("Security engine ready.");
  const [connectionStatus, setConnectionStatus] = useState<"READY" | "CONNECTING" | "CONNECTED" | "FAILED">("READY");
  const [securityLogs, setSecurityLogs] = useState<string[]>([]);
  const [livePulse, setLivePulse] = useState(false);
  const [findings, setFindings] = useState<any[]>([]);

  const addSecurityLog = (msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setSecurityLogs((prev) => [`[${timestamp}] ${msg}`, ...prev]);
  };

  useEffect(() => {
    setHeaders((prev) => {
      const filtered = prev.filter((h) => h.key.toLowerCase() !== "authorization");
      if (authType !== "No Auth" && authValue.trim()) {
        filtered.push({ key: "Authorization", value: authValue });
      }
      return filtered;
    });
  }, [authValue, authType]);

  const addHeader = () => setHeaders([...headers, { key: "", value: "" }]);
  const removeHeader = (index: number) => setHeaders(headers.filter((_, i) => i !== index));
  const updateHeader = (index: number, field: "key" | "value", value: string) => {
    const updated = [...headers];
    updated[index][field] = value;
    setHeaders(updated);
  };

  const clearHistory = () => setHistory([]);
  const clearResponse = () => setResponse("");
  const clearSchema = () => setSchema("");
  const clearSecurity = () => {
    setRiskScore(0);
    setSecurityMessage("Security engine ready.");
    setSecurityLogs([]);
    setLivePulse(false);
    setFindings([]);
  };
  const clearQuery = () => setQuery(`query {\n  health\n}`);

  const buildHeaders = useCallback(() => {
    const obj: Record<string, string> = {};
    headers.forEach((h) => {
      if (h.key.trim() && h.value.trim()) obj[h.key] = h.value;
    });
    return obj;
  }, [headers]);

  // ─── FIX #1 cont: fetch always goes to BACKEND_URL; endpoint in payload is the target ───
  const sendToBackend = useCallback(async (payload: any, action: string) => {
    console.log(`🚀 [${action}] SENDING PAYLOAD:`, JSON.stringify(payload, null, 2));
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    console.log(`📥 [${action}] RESPONSE STATUS:`, res.status);
    return res;
  }, []);

  const runQuery = async () => {
    if (!query.trim()) return;
    try {
      setLoading(true);
      const start = performance.now();

      const payload = {
        endpoint: endpoint,   // target API — backend forwards here
        query: query,
        variables: {},
        headers: buildHeaders(),
        auth_type: authType,
        auth_value: authValue || "",
      };

      const res = await sendToBackend(payload, "RUN_QUERY");
      const backendData = await res.json().catch(() => ({ error: "Invalid JSON" }));

      const end = performance.now();
      setStatusCode(String(res.status));
      setResponseTime(`${Math.round(end - start)}ms`);
      setResponseSize(`${(JSON.stringify(backendData).length / 1024).toFixed(2)}kb`);

      const cleanResponse = backendData.response || backendData;
      setResponse(JSON.stringify(cleanResponse, null, 2));

      // ─── FIX #4 & #5: update securityMessage and livePulse after every query ───
      const newScore: number = backendData.risk_score || 0;
      const newFindings: any[] = backendData.findings || [];
      setRiskScore(newScore);
      setFindings(newFindings);
      setLivePulse(true);
      setSecurityMessage(
        newFindings.length > 0
          ? `${newFindings.length} security finding${newFindings.length > 1 ? "s" : ""} detected. Risk score: ${newScore}.`
          : newScore > 0
          ? `Scan complete. Risk score: ${newScore}.`
          : "No threats detected. Query appears safe."
      );

      // ─── FIX #3: push every executed query into history ───
      const preview = query.trim().replace(/\s+/g, " ").slice(0, 60);
      setHistory((prev) => [
        {
          name: preview,
          info: `${endpoint} · ${res.status} · ${Math.round(end - start)}ms · ${new Date().toLocaleTimeString()}`,
        },
        ...prev,
      ]);

    } catch (err: any) {
      setResponse(JSON.stringify({ error: err.message }, null, 2));
    } finally {
      setLoading(false);
    }
  };

  const fetchSchema = useCallback(async () => {
    try {
      setSchema("Loading schema...");
      const payload = {
        endpoint: endpoint,
        query: `query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types { kind name description fields { name } }
          }
        }`,
        variables: {},
        headers: buildHeaders(),
        auth_type: authType,
        auth_value: authValue || "",
      };

      const res = await sendToBackend(payload, "FETCH_SCHEMA");
      const backendData = await res.json().catch(() => ({ error: "Failed" }));

      if (backendData.response) {
        setSchema(JSON.stringify(backendData.response, null, 2));
      } else {
        setSchema(JSON.stringify(backendData, null, 2));
      }
    } catch (err: any) {
      setSchema(`Failed: ${err.message}`);
    }
  }, [endpoint, authType, authValue, buildHeaders, sendToBackend]);

  // ─── FIX #2: testConnection uses useCallback so useEffect dep array is stable ───
  const testConnection = useCallback(async () => {
    try {
      setConnectionStatus("CONNECTING");
      const payload = {
        endpoint: endpoint,
        query: "{ __typename }",
        variables: {},
        headers: buildHeaders(),
        auth_type: authType,
        auth_value: authValue || "",
      };

      const res = await sendToBackend(payload, "TEST_CONNECTION");

      if (res.ok) {
        setConnectionStatus("CONNECTED");
        await fetchSchema();
      } else {
        setConnectionStatus("FAILED");
      }
    } catch {
      setConnectionStatus("FAILED");
    }
  }, [endpoint, authType, authValue, buildHeaders, sendToBackend, fetchSchema]);

  // ─── FIX #2: removed auto-fire on mount — user triggers connection manually ───
  // (the old useEffect(() => { testConnection(); }, []) was removed)

  const riskColor = useMemo(() => {
    if (riskScore >= 70) return "text-red-400";
    if (riskScore >= 30) return "text-yellow-400";
    return "text-cyan-300";
  }, [riskScore]);

  // ─────────────────────────────────────────────────────────────────────────────
  // UI — zero changes below this line vs the original
  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#020817] text-white overflow-hidden relative">
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.12),transparent_30%),radial-gradient(circle_at_bottom_left,rgba(139,92,246,0.12),transparent_30%)] pointer-events-none" />

      {/* TOPBAR */}
      <div className="h-[78px] border-b border-cyan-500/10 bg-[#071122]/90 backdrop-blur-2xl flex items-center justify-between px-8 sticky top-0 z-50">
        <div>
          <h1 className="text-[36px] font-black tracking-tight bg-gradient-to-r from-cyan-300 via-blue-400 to-violet-400 bg-clip-text text-transparent">
            GraphQL Console
          </h1>
          <div className="text-[11px] tracking-[0.35em] uppercase text-cyan-400 mt-1">
            Enterprise Security Gateway
          </div>
        </div>
        <button
          onClick={testConnection}
          className={`h-12 px-8 rounded-2xl transition-all duration-300 font-semibold shadow-[0_0_35px_rgba(34,211,238,0.25)] ${
            connectionStatus === "CONNECTED"
              ? "bg-emerald-500/20 border border-emerald-400/40 text-emerald-300"
              : connectionStatus === "FAILED"
              ? "bg-red-500/20 border border-red-400/40 text-red-300"
              : "bg-gradient-to-r from-cyan-500 to-violet-600"
          }`}
        >
          <div className="flex items-center gap-2">
            {connectionStatus === "CONNECTED" ? <Wifi size={16} /> :
             connectionStatus === "FAILED" ? <WifiOff size={16} /> : <Server size={16} />}
            {connectionStatus === "CONNECTING" ? "Connecting..." : connectionStatus}
          </div>
        </button>
      </div>

      <div className="p-5 space-y-5 relative z-10">
        {/* Connection + Headers Panel */}
        <div className="grid grid-cols-1 xl:grid-cols-[420px_1fr] gap-5">
          <div className="rounded-3xl border border-cyan-500/15 bg-[#07101f]/95 overflow-hidden backdrop-blur-2xl shadow-[0_0_70px_rgba(0,0,0,0.7)]">
            <div className="h-[62px] px-6 border-b border-cyan-500/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Link2 size={18} className="text-cyan-400" />
                <span className="font-semibold text-[18px]">Connection</span>
              </div>
              <div className="px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 text-xs font-bold">
                {connectionStatus}
              </div>
            </div>
            <div className="p-6 space-y-5">
              <div>
                <div className="text-[11px] uppercase tracking-[0.25em] text-zinc-500 mb-3">Endpoint</div>
                <div className="relative">
                  <Globe size={18} className="absolute left-4 top-4 text-cyan-400" />
                  <input
                    value={endpoint}
                    onChange={(e) => setEndpoint(e.target.value)}
                    className="w-full h-14 pl-12 pr-5 rounded-2xl bg-[#081425] border border-cyan-500/10 focus:border-cyan-400/50 outline-none transition-all"
                  />
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.25em] text-zinc-500 mb-3">Authentication Type</div>
                <select
                  value={authType}
                  onChange={(e) => setAuthType(e.target.value)}
                  className="w-full h-14 px-5 rounded-2xl bg-[#081425] border border-cyan-500/10"
                >
                  <option>Bearer Token</option>
                  <option>API Key</option>
                  <option>JWT Token</option>
                  <option>No Auth</option>
                </select>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.25em] text-zinc-500 mb-3">Authentication</div>
                <div className="relative">
                  <Lock size={18} className="absolute left-4 top-4 text-violet-400" />
                  <input
                    type={showAuth ? "text" : "password"}
                    value={authValue}
                    onChange={(e) => setAuthValue(e.target.value)}
                    placeholder="Enter token"
                    className="w-full h-14 pl-12 pr-14 rounded-2xl bg-[#081425] border border-cyan-500/10"
                  />
                  <button onClick={() => setShowAuth(!showAuth)} className="absolute right-4 top-4 text-zinc-400">
                    {showAuth ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>
              <button onClick={testConnection} className="w-full h-14 rounded-2xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:scale-[1.01] transition-all font-semibold">
                Test Connection
              </button>
            </div>
          </div>

          {/* Headers Panel */}
          <div className="rounded-3xl border border-cyan-500/15 bg-[#07101f]/95 overflow-hidden backdrop-blur-2xl">
            <div className="h-[62px] px-6 border-b border-cyan-500/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Database size={18} className="text-violet-400" />
                <span className="font-semibold text-[18px]">Request Headers</span>
              </div>
              <button onClick={addHeader} className="h-11 px-5 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all flex items-center gap-2 text-cyan-300">
                <Plus size={18} /> Add Header
              </button>
            </div>
            <div className="p-5 space-y-4">
              {headers.map((header, index) => (
                <div key={index} className="grid grid-cols-[1fr_1fr_56px] gap-4">
                  <input value={header.key} onChange={(e) => updateHeader(index, "key", e.target.value)} placeholder="Header Key" className="h-14 px-5 rounded-2xl bg-[#081425] border border-cyan-500/10" />
                  <input value={header.value} onChange={(e) => updateHeader(index, "value", e.target.value)} placeholder="Header Value" className="h-14 px-5 rounded-2xl bg-[#081425] border border-cyan-500/10" />
                  <button onClick={() => removeHeader(index)} className="h-14 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center justify-center hover:bg-red-500/20">
                    <Trash2 size={18} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Query + Response Area */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
          <div className="rounded-3xl border border-cyan-500/15 bg-[#07101f]/95 overflow-hidden">
            <div className="h-[62px] border-b border-cyan-500/10 px-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Sparkles size={18} className="text-cyan-400" />
                <span className="font-semibold text-[18px]">Query Editor</span>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={clearQuery} className="h-11 px-5 rounded-2xl border border-red-500/20 bg-red-500/10 text-red-400 flex items-center gap-2 hover:bg-red-500/20 transition-all">
                  <RotateCcw size={17} /> Clear
                </button>
                <button onClick={runQuery} disabled={loading} className="h-11 px-7 rounded-2xl bg-gradient-to-r from-cyan-500 to-violet-600 flex items-center gap-3 font-semibold disabled:opacity-70">
                  {loading ? <Loader2 className="animate-spin" size={18} /> : <Play size={18} />}
                  {loading ? "Running..." : "Run Query"}
                </button>
              </div>
            </div>
            <textarea
              spellCheck={false}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full h-[520px] resize-none bg-[#020b18] text-[#dbeafe] p-6 outline-none font-mono text-[15px] leading-8"
            />
          </div>

          <div className="rounded-3xl border border-cyan-500/15 bg-[#07101f]/95 overflow-hidden">
            <div className="h-[62px] border-b border-cyan-500/10 px-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <FileJson size={18} className="text-violet-400" />
                <span className="font-semibold text-[18px]">Server Response</span>
              </div>
              <div className="flex items-center gap-6 text-sm">
                <span className="text-emerald-400 font-semibold">{statusCode}</span>
                <span className="text-zinc-400">{responseTime}</span>
                <span className="text-zinc-400">{responseSize}</span>
              </div>
            </div>
            <textarea
              readOnly
              value={response || "Run a query to see response here"}
              className="w-full h-[520px] resize-none bg-[#020b18] text-[#dbeafe] p-6 outline-none font-mono text-[15px] leading-8"
            />
          </div>
        </div>

        {/* Bottom Tabs */}
        <div className="rounded-3xl border border-cyan-500/15 bg-[#07101f]/95 overflow-hidden">
          <div className="h-[62px] border-b border-cyan-500/10 flex items-center px-5 gap-4 overflow-auto">
            {[
              { id: "response", label: "Response", icon: FileJson },
              { id: "schema", label: "Schema", icon: Database },
              { id: "history", label: "History", icon: History },
              { id: "security", label: "Security", icon: Shield },
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`h-11 px-6 rounded-2xl flex items-center gap-2 transition-all duration-300 ${
                    activeTab === tab.id
                      ? "bg-gradient-to-r from-violet-600/30 to-cyan-500/20 border border-violet-500/30 text-white"
                      : "text-zinc-500 hover:text-white hover:bg-white/5"
                  }`}
                >
                  <Icon size={17} />
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div className="p-6 min-h-[280px] bg-[#020b18]">
            {activeTab === "response" && (
              <div>
                <div className="flex justify-between mb-4">
                  <h3 className="text-lg font-semibold">Latest Response</h3>
                  <button onClick={clearResponse} className="h-9 px-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-2 hover:bg-red-500/20">
                    <RotateCcw size={16} /> Clear
                  </button>
                </div>
                <textarea readOnly value={response || "No response yet."} className="w-full h-[240px] resize-none rounded-2xl border border-cyan-500/10 bg-[#081425] p-5 outline-none font-mono text-zinc-300" />
              </div>
            )}

            {activeTab === "schema" && (
              <div>
                <div className="flex justify-between mb-4">
                  <h3 className="text-lg font-semibold">GraphQL Schema</h3>
                  <button onClick={clearSchema} className="h-9 px-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-2 hover:bg-red-500/20">
                    <RotateCcw size={16} /> Clear
                  </button>
                </div>
                <textarea readOnly value={schema || "Click 'Test Connection' to load schema"} className="w-full h-[240px] resize-none rounded-2xl border border-cyan-500/10 bg-[#081425] p-5 outline-none font-mono text-zinc-300" />
              </div>
            )}

            {activeTab === "history" && (
              <div>
                <div className="flex justify-between mb-4">
                  <h3 className="text-lg font-semibold">Request History</h3>
                  <button onClick={clearHistory} className="h-9 px-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-2 hover:bg-red-500/20">
                    <RotateCcw size={16} /> Clear
                  </button>
                </div>
                <div className="space-y-3 max-h-[260px] overflow-auto">
                  {history.length === 0 ? (
                    <div className="text-zinc-500 text-center py-10">No requests executed yet.</div>
                  ) : (
                    history.map((item, index) => (
                      <div key={index} className="rounded-2xl border border-cyan-500/10 bg-[#081425] p-5">
                        <div className="font-semibold">{item.name}</div>
                        <div className="text-sm text-zinc-500 mt-1">{item.info}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {activeTab === "security" && (
              <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6">
                <div className={`rounded-3xl border border-cyan-500/10 bg-[#081425] p-6 flex flex-col items-center justify-center transition-all duration-500 ${livePulse ? "scale-[1.03] shadow-[0_0_45px_rgba(34,211,238,0.25)]" : ""}`}>
                  <div className="relative">
                    <div className={`absolute inset-0 rounded-full blur-3xl opacity-40 animate-pulse ${riskScore >= 70 ? "bg-red-500" : riskScore >= 30 ? "bg-yellow-500" : "bg-cyan-500"}`} />
                    {riskScore >= 70 ? <ShieldAlert size={72} className="relative text-red-400 animate-pulse" /> : <ShieldCheck size={72} className="relative text-cyan-300" />}
                  </div>
                  <div className="text-sm text-zinc-500 mt-6 uppercase tracking-[0.25em]">Risk Score</div>
                  <div className={`text-8xl font-black mt-3 transition-all duration-500 ${riskColor}`}>{riskScore}</div>
                  <div className={`mt-5 px-5 py-2 rounded-full font-semibold ${riskScore >= 70 ? "bg-red-500/10 text-red-400" : riskScore >= 30 ? "bg-yellow-500/10 text-yellow-400" : "bg-cyan-500/10 text-cyan-300"}`}>
                    {riskScore >= 70 ? "HIGH RISK" : riskScore >= 30 ? "MEDIUM RISK" : "LOW RISK"}
                  </div>
                </div>

                <div className="rounded-3xl border border-cyan-500/10 bg-[#081425] p-6">
                  <div className="flex items-center justify-between mb-5">
                    <div className="flex items-center gap-3">
                      <Zap className="text-cyan-400 animate-pulse" size={20} />
                      <div className="text-lg font-semibold">Security Analysis</div>
                    </div>
                    <button onClick={clearSecurity} className="h-10 px-5 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-2 hover:bg-red-500/20">
                      <RotateCcw size={16} /> Clear
                    </button>
                  </div>

                  <div className="rounded-2xl border border-cyan-500/10 bg-[#020b18] p-5 mb-5">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className={`${riskScore >= 70 ? "text-red-400 animate-bounce" : "text-yellow-400"}`} size={20} />
                      <span className="text-zinc-300">{securityMessage}</span>
                    </div>
                  </div>

                  <div className="space-y-3 max-h-[260px] overflow-auto pr-2">
                    {findings.length > 0 ? (
                      findings.map((finding, index) => (
                        <div key={index} className="rounded-xl border border-cyan-500/10 bg-[#020b18] p-4 text-sm">
                          <div className="font-semibold text-red-400">{finding.title}</div>
                          <div className="text-zinc-400 mt-1">{finding.message}</div>
                          {finding.recommendation && <div className="text-xs text-emerald-400 mt-2">→ {finding.recommendation}</div>}
                        </div>
                      ))
                    ) : (
                      <div className="rounded-xl border border-cyan-500/10 bg-[#020b18] px-4 py-3 text-sm text-zinc-500">No security findings detected yet.</div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

