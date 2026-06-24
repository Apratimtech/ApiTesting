"use client";
import { useState, useEffect, useRef, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Trash2,
  Plus,
  Eye,
  Zap,
  Play,
  ShieldCheck,
  Download,
  AlertTriangle,
  CheckCircle2,
  Copy,
  RotateCw,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";

// ─────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────
type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD";
type AuthType =
  | "no-auth"
  | "bearer"
  | "basic"
  | "api-key"
  | "jwt";
type BodyType =
  | "none"
  | "json"
  | "raw"
  | "form-data"
  | "x-www-form-urlencoded"
  | "graphql"
  | "html"
  | "javascript";
interface Header {
  key: string;
  value: string;
}
interface Finding {
  issue: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  category?: string;
}
interface SecurityResult {
  findings?: Finding[];
  overall_risk_score?: number;
  success?: boolean;
}
interface ApiResponse {
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: unknown;
  rawText?: string;
  error?: string;
}

// ─────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────
const BACKEND_URL = "http://localhost:8000/api/v1/analyze";
const MAX_BODY_SIZE = 1024 * 1024; // 1MB
const MAX_DISPLAY_SIZE = 50000;
const NO_BODY_METHODS: HttpMethod[] = ["GET", "HEAD", "DELETE"];
const DEFAULT_JSON_BODY = `{
  "username": "admin",
  "password": "123456"
}`;
const severityColors: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-emerald-600 text-white",
  INFO: "bg-blue-600 text-white",
};
const severityBorder: Record<string, string> = {
  CRITICAL: "border-red-500/60",
  HIGH: "border-orange-500/60",
  MEDIUM: "border-yellow-500/60",
  LOW: "border-emerald-500/60",
  INFO: "border-blue-500/60",
};
const severityOrder: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

// ─────────────────────────────────────────────────────────────
// COMPONENT
// ─────────────────────────────────────────────────────────────
export default function Analyzer() {
  const [method, setMethod] = useState<HttpMethod>("POST");
  const [url, setUrl] = useState("https://httpbin.org/anything");
  
  // AUTH
  const [authType, setAuthType] = useState<AuthType>("bearer");
  const [bearer, setBearer] = useState("");
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  const [apiKey, setApiKey] = useState("");

  // HEADERS
  const [headers, setHeaders] = useState<Header[]>([
    { key: "Content-Type", value: "application/json" },
  ]);

  // BODY
  const [bodyType, setBodyType] = useState<BodyType>("json");
  const [body, setBody] = useState(DEFAULT_JSON_BODY);
  const [graphqlVariables, setGraphqlVariables] = useState(`{\n "id": 1\n}`);

  // RESULTS
  const [apiResponse, setApiResponse] = useState<ApiResponse | null>(null);
  const [securityResult, setSecurityResult] = useState<SecurityResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"response" | "security">("security");
  const [responseSubTab, setResponseSubTab] = useState<"body" | "headers" | "raw">("body");
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);
  const prevBodyType = useRef<BodyType>(bodyType);
  const lastRequestRef = useRef<any>(null);

  // ─────────────────────────────────────────────────────────
  // TOAST
  // ─────────────────────────────────────────────────────────
  const showToast = (message: string, type: "success" | "error" = "success") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 2500);
  };

  // ─────────────────────────────────────────────────────────
  // VALIDATION & SANITIZATION
  // ─────────────────────────────────────────────────────────
  const isValidUrl = (str: string): boolean => {
    try {
      const u = new URL(str);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  };

  const sanitizeHeaderValue = (value: string): string => {
    return value.replace(/[\r\n]/g, "");
  };

  // ─────────────────────────────────────────────────────────
  // BODY TYPE SYNC
  // ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (prevBodyType.current === bodyType) return;
    prevBodyType.current = bodyType;
    switch (bodyType) {
      case "none":
        setBody("");
        break;
      case "json":
        setBody(DEFAULT_JSON_BODY);
        break;
      case "html":
        setBody("<h1>Hello World</h1>");
        break;
      case "javascript":
        setBody("// JavaScript payload");
        break;
      case "graphql":
        setBody(`query User($id: ID!) {\n user(id: $id) {\n id\n name\n }\n}`);
        break;
      default:
        setBody("");
    }
  }, [bodyType]);

  useEffect(() => {
    const contentTypeMap: Partial<Record<BodyType, string>> = {
      json: "application/json",
      graphql: "application/json",
      html: "text/html",
      javascript: "application/javascript",
      "x-www-form-urlencoded": "application/x-www-form-urlencoded",
    };
    if (contentTypeMap[bodyType]) {
      setHeaders((prev) => {
        const filtered = prev.filter((h) => h.key.toLowerCase() !== "content-type");
        return [...filtered, { key: "Content-Type", value: contentTypeMap[bodyType]! }];
      });
    }
  }, [bodyType]);

  // ─────────────────────────────────────────────────────────
  // HEADER HELPERS
  // ─────────────────────────────────────────────────────────
  const addHeader = () => {
    setHeaders((prev) => [...prev, { key: "", value: "" }]);
  };

  const removeHeader = (index: number) => {
    setHeaders((prev) => prev.filter((_, i) => i !== index));
  };

  const updateHeader = (index: number, field: keyof Header, value: string) => {
    setHeaders((prev) =>
      prev.map((h, i) =>
        i === index ? { ...h, [field]: sanitizeHeaderValue(value) } : h
      )
    );
  };

  const syncedHeaders = useMemo(() => {
    const clean = headers.filter((h) => h.key.trim() !== "");
    const normalized = new Map<string, string>();

    clean.forEach(({ key, value }) => {
      const lower = key.toLowerCase().trim();
      if (!["authorization", "x-api-key"].includes(lower)) {
        normalized.set(lower, value.trim());
      }
    });

    if ((authType === "bearer" || authType === "jwt") && bearer.trim()) {
      normalized.set("authorization", `Bearer ${bearer.trim()}`);
    }
    if (authType === "basic" && basicUser.trim() && basicPass.trim()) {
      const credentials = `${basicUser}:${basicPass}`;
      const encoded = btoa(unescape(encodeURIComponent(credentials)));
      normalized.set("authorization", `Basic ${encoded}`);
    }
    if (authType === "api-key" && apiKey.trim()) {
      normalized.set("x-api-key", apiKey.trim());
    }

    return Array.from(normalized.entries()).map(([key, value]) => ({
      key: key
        .split("-")
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join("-"),
      value,
    }));
  }, [headers, authType, bearer, basicUser, basicPass, apiKey]);

  // ─────────────────────────────────────────────────────────
  // REQUEST LOGIC
  // ─────────────────────────────────────────────────────────
  const performRequest = async (payloadUrl?: string, payloadMethod?: HttpMethod) => {
    const targetUrl = payloadUrl || url;
    const targetMethod = payloadMethod || method;

    if (!isValidUrl(targetUrl)) {
      showToast("Please enter a valid HTTP/HTTPS URL", "error");
      return;
    }
    if (body.length > MAX_BODY_SIZE) {
      showToast("Body size exceeds 1MB limit", "error");
      return;
    }

    setLoading(true);
    setApiResponse(null);
    setSecurityResult(null);
    abortControllerRef.current = new AbortController();
    const timeoutId = setTimeout(() => abortControllerRef.current?.abort(), 15000);

    try {
      const headerObj: Record<string, string> = {};
      syncedHeaders.forEach(({ key, value }) => {
        headerObj[key] = value;
      });

      const allowsBody = !NO_BODY_METHODS.includes(targetMethod) && bodyType !== "none" && body.trim();
      let finalBody: unknown = undefined;

      if (allowsBody) {
        if (bodyType === "json") {
          try { finalBody = JSON.parse(body); } catch { finalBody = body; }
        } else if (bodyType === "graphql") {
          let variables = {};
          try {
            variables = graphqlVariables ? JSON.parse(graphqlVariables) : {};
          } catch {
            showToast("Invalid GraphQL Variables JSON", "error");
            return;
          }
          finalBody = { query: body, variables };
        } else {
          finalBody = body;
        }
      }

      const targetRes = await fetch("/api/proxy", {
        method: targetMethod,
        headers: { ...headerObj, "x-proxy-url": targetUrl },
        body: allowsBody && finalBody !== undefined
          ? typeof finalBody === "string" ? finalBody : JSON.stringify(finalBody)
          : undefined,
        signal: abortControllerRef.current.signal,
      });

      const rawText = await targetRes.text();
      let responseBody: unknown;
      try { responseBody = JSON.parse(rawText); } catch { responseBody = rawText; }

      const fullResponse: ApiResponse = {
        status: targetRes.status,
        statusText: targetRes.statusText,
        headers: Object.fromEntries(targetRes.headers.entries()),
        body: responseBody,
        rawText,
      };

      setApiResponse(fullResponse);
      lastRequestRef.current = { url: targetUrl, method: targetMethod };

      const safeResponse = { ...fullResponse };
      if (typeof safeResponse.rawText === "string" && safeResponse.rawText.length > MAX_DISPLAY_SIZE) {
        safeResponse.rawText = safeResponse.rawText.substring(0, MAX_DISPLAY_SIZE) + "\n... [TRUNCATED]";
      }

      const analyzePayload = {
        request: { method: targetMethod, url: targetUrl, headers: headerObj, body: finalBody ?? null, bodyType },
        response: safeResponse,
      };

      const analyzeRes = await fetch(BACKEND_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(analyzePayload),
      });

      if (!analyzeRes.ok) throw new Error(`Analyzer error: ${analyzeRes.status}`);
      
      const analyzeData = await analyzeRes.json();
      setSecurityResult({
        ...analyzeData,
        overall_risk_score: Math.min(100, Math.max(0, analyzeData.overall_risk_score || 0)),
      });
      setActiveTab("security");
    } catch (err: any) {
      showToast(err.message || "Request failed", "error");
      setApiResponse({ error: err.message || "Request failed" });
    } finally {
      clearTimeout(timeoutId);
      setLoading(false);
    }
  };

  const handleSend = () => performRequest();
  const handleReplay = () => {
    if (lastRequestRef.current) {
      performRequest(lastRequestRef.current.url, lastRequestRef.current.method);
    } else {
      showToast("No previous request to replay", "error");
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`${label} copied`);
  };

  const downloadReport = () => {
    if (!securityResult) return;
    const report = {
      ...securityResult,
      generated_at: new Date().toISOString(),
      analyzed_url: url,
      method,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `TrustEdge_Report_${new Date().toISOString().split("T")[0]}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const sortedFindings = [...(securityResult?.findings ?? [])].sort(
    (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
  );

  const displayResponseBody = (resp: ApiResponse) => {
    if (!resp.rawText) return "No body";
    if (resp.rawText.length > MAX_DISPLAY_SIZE) {
      return resp.rawText.substring(0, MAX_DISPLAY_SIZE) + "\n\n... [TRUNCATED]";
    }
    return resp.rawText;
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="min-h-screen bg-[#0a0a0f] pb-12">
      <div className="max-w-7xl mx-auto p-6 space-y-8">
        <div className="flex items-center gap-6">
          <motion.div whileHover={{ scale: 1.1, rotate: 5 }} className="p-5 rounded-3xl bg-gradient-to-br from-violet-600 via-fuchsia-600 to-purple-600 shadow-2xl shadow-purple-500/30">
            <Zap className="w-14 h-14 text-white" />
          </motion.div>
          <div>
            <h1 className="text-7xl font-bold tracking-tighter bg-gradient-to-r from-white via-violet-200 to-fuchsia-200 bg-clip-text text-transparent">
              Trust_Edge
            </h1>
            <p className="text-slate-400 text-xl tracking-wide">ENTERPRISE API SECURITY PLATFORM</p>
          </div>
        </div>

        <Card className="border border-slate-700/70 bg-slate-950/90 backdrop-blur-2xl shadow-2xl">
          <CardContent className="p-6 flex gap-4 items-center">
            <Select value={method} onValueChange={(v) => setMethod(v as HttpMethod)}>
              <SelectTrigger className="w-32 h-12"><SelectValue /></SelectTrigger>
              <SelectContent>
                {(["GET","POST","PUT","PATCH","DELETE","HEAD"] as HttpMethod[]).map(m => (
                  <SelectItem key={m} value={m}>{m}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} className="flex-1 h-12 font-mono bg-slate-900/80 border-slate-700" placeholder="https://api.example.com" />
            <Button onClick={handleSend} disabled={loading} className="h-12 px-10 bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-700 hover:to-violet-700">
              <AnimatePresence mode="wait">
                {loading ? (
                  <motion.div key="loading" className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Analyzing...
                  </motion.div>
                ) : (
                  <motion.div key="idle" className="flex items-center gap-2">
                    <Play className="w-5 h-5" /> Send & Analyze
                  </motion.div>
                )}
              </AnimatePresence>
            </Button>
            {lastRequestRef.current && (
              <Button onClick={handleReplay} disabled={loading} variant="outline">
                <RotateCw className="w-4 h-4 mr-2" /> Replay
              </Button>
            )}
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
          <div className="lg:col-span-3">
            <Card className="border-slate-700 bg-slate-950/90 h-full">
              <CardHeader><CardTitle className="text-3xl font-semibold">Request Configuration</CardTitle></CardHeader>
              <CardContent className="p-8">
                <Tabs defaultValue="auth">
                  <TabsList className="grid grid-cols-3 mb-8 bg-slate-900">
                    <TabsTrigger value="auth">Authorization</TabsTrigger>
                    <TabsTrigger value="headers">Headers</TabsTrigger>
                    <TabsTrigger value="body">Body</TabsTrigger>
                  </TabsList>

                  <TabsContent value="auth" className="space-y-5">
                    <Select value={authType} onValueChange={(v) => setAuthType(v as AuthType)}>
                      <SelectTrigger className="h-12"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="no-auth">No Authentication</SelectItem>
                        <SelectItem value="bearer">Bearer Token</SelectItem>
                        <SelectItem value="basic">Basic Auth</SelectItem>
                        <SelectItem value="api-key">API Key</SelectItem>
                        <SelectItem value="jwt">JWT Token</SelectItem>
                      </SelectContent>
                    </Select>
                    {(authType === "bearer" || authType === "jwt") && (
                      <Input value={bearer} onChange={(e) => setBearer(e.target.value)} placeholder="Enter Bearer / JWT Token" />
                    )}
                    {authType === "basic" && (
                      <div className="grid grid-cols-2 gap-4">
                        <Input value={basicUser} onChange={(e) => setBasicUser(e.target.value)} placeholder="Username" />
                        <Input value={basicPass} onChange={(e) => setBasicPass(e.target.value)} type="password" placeholder="Password" />
                      </div>
                    )}
                    {authType === "api-key" && (
                      <Input value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="API Key" />
                    )}
                  </TabsContent>

                  {/* HEADERS SECTION - Fixed */}
                  <TabsContent value="headers" className="space-y-4">
                    {headers.map((h, i) => {
                      const isAuthHeader = ["authorization", "x-api-key"].some(key => 
                        h.key.toLowerCase().includes(key)
                      );
                      return (
                        <div key={i} className="flex gap-3 items-center">
                          <Input
                            value={h.key}
                            placeholder="Header Key"
                            onChange={(e) => updateHeader(i, "key", e.target.value)}
                            className="font-mono"
                            disabled={isAuthHeader}
                          />
                          <Input
                            value={h.value}
                            placeholder="Header Value"
                            onChange={(e) => updateHeader(i, "value", e.target.value)}
                            className="font-mono"
                            disabled={isAuthHeader}
                          />
                          {!isAuthHeader && (
                            <Button 
                              variant="ghost" 
                              size="icon"
                              onClick={() => removeHeader(i)}
                              className="shrink-0"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          )}
                        </div>
                      );
                    })}

                    <Button onClick={addHeader} variant="outline" className="w-full">
                      <Plus className="w-4 h-4 mr-2" /> Add Header
                    </Button>
                  </TabsContent>

                  <TabsContent value="body" className="space-y-4">
                    <Select value={bodyType} onValueChange={(v) => setBodyType(v as BodyType)}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">none</SelectItem>
                        <SelectItem value="json">JSON</SelectItem>
                        <SelectItem value="raw">Raw</SelectItem>
                        <SelectItem value="html">HTML</SelectItem>
                        <SelectItem value="javascript">JavaScript</SelectItem>
                        <SelectItem value="graphql">GraphQL</SelectItem>
                      </SelectContent>
                    </Select>
                    {bodyType !== "none" && (
                      <>
                        <Textarea value={body} onChange={(e) => setBody(e.target.value)} className="min-h-[320px] font-mono" placeholder="Request body..." />
                        {bodyType === "graphql" && (
                          <Textarea value={graphqlVariables} onChange={(e) => setGraphqlVariables(e.target.value)} className="min-h-[120px] font-mono" placeholder="GraphQL Variables (JSON)" />
                        )}
                      </>
                    )}
                    {NO_BODY_METHODS.includes(method) && bodyType !== "none" && (
                      <p className="text-yellow-400 text-sm">⚠️ Body is ignored for {method} requests.</p>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          {/* RIGHT SIDE - Analysis Console */}
          <div className="lg:col-span-2">
            <Card className="border-slate-700 bg-slate-950/90 h-full">
              <CardHeader><CardTitle className="text-3xl font-semibold">Analysis Console</CardTitle></CardHeader>
              <CardContent className="p-8">
                <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as "response" | "security")}>
                  <TabsList className="grid grid-cols-2 mb-8 bg-slate-900">
                    <TabsTrigger value="response">API Response</TabsTrigger>
                    <TabsTrigger value="security">Security Analysis</TabsTrigger>
                  </TabsList>

                  <TabsContent value="response">
                    {!apiResponse ? (
                      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                        <Eye className="w-16 h-16 mb-5 opacity-40" />
                        <p>Send request to view response</p>
                      </div>
                    ) : (
                      <div>
                        <Tabs value={responseSubTab} onValueChange={(v) => setResponseSubTab(v as any)}>
                          <TabsList className="grid grid-cols-3 mb-4">
                            <TabsTrigger value="body">Body</TabsTrigger>
                            <TabsTrigger value="headers">Headers</TabsTrigger>
                            <TabsTrigger value="raw">Raw</TabsTrigger>
                          </TabsList>
                          <TabsContent value="body">
                            <Button variant="outline" size="sm" className="mb-3" onClick={() => copyToClipboard(JSON.stringify(apiResponse.body || apiResponse.rawText, null, 2), "Response Body")}>
                              <Copy className="w-4 h-4 mr-2" /> Copy Body
                            </Button>
                            <pre className="bg-black p-6 rounded-2xl text-sm overflow-auto max-h-[500px] font-mono border border-slate-800 whitespace-pre-wrap">
                              {displayResponseBody(apiResponse)}
                            </pre>
                          </TabsContent>
                          <TabsContent value="headers">
                            <pre className="bg-black p-6 rounded-2xl text-sm overflow-auto max-h-[500px] font-mono border border-slate-800">
                              {JSON.stringify(apiResponse.headers, null, 2)}
                            </pre>
                          </TabsContent>
                          <TabsContent value="raw">
                            <pre className="bg-black p-6 rounded-2xl text-sm overflow-auto max-h-[500px] font-mono border border-slate-800 whitespace-pre-wrap">
                              {apiResponse.rawText || "No raw content"}
                            </pre>
                          </TabsContent>
                        </Tabs>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="security">
                    {!securityResult ? (
                      <div className="flex flex-col items-center justify-center py-24 text-slate-500">
                        <ShieldCheck className="w-20 h-20 mb-6 opacity-40" />
                        <p>Security findings will appear here</p>
                      </div>
                    ) : (
                      <div className="space-y-6">
                        <div className="flex justify-between items-center">
                          <div>
                            <h3 className="text-3xl font-semibold">Security Findings</h3>
                            <p className="text-slate-400">
                              {securityResult.findings?.length ?? 0} issues • Risk Score: <span className="text-orange-400 font-semibold">{securityResult.overall_risk_score}%</span>
                            </p>
                          </div>
                          <Button onClick={downloadReport} className="bg-gradient-to-r from-purple-600 to-violet-600">
                            <Download className="mr-2 h-4 w-4" /> Export Report
                          </Button>
                        </div>

                        {sortedFindings.length > 0 ? (
                          <div className="space-y-6">
                            {sortedFindings.map((f, i) => (
                              <motion.div key={i} initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                                className={`p-7 rounded-3xl border ${severityBorder[f.severity]} bg-slate-900/80`}>
                                <div className="flex justify-between items-start gap-4">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-4">
                                      <AlertTriangle className="w-7 h-7 text-orange-400 shrink-0" />
                                      <h4 className="text-2xl font-semibold">{f.issue}</h4>
                                    </div>
                                    {f.category && <p className="text-purple-400 mt-2 text-sm">Category: {f.category}</p>}
                                    <p className="mt-4 text-slate-300 leading-relaxed">{f.description}</p>
                                  </div>
                                  <Badge className={`text-sm px-5 py-2 shrink-0 ${severityColors[f.severity]}`}>{f.severity}</Badge>
                                </div>
                              </motion.div>
                            ))}
                          </div>
                        ) : (
                          <div className="flex flex-col items-center justify-center py-24 text-emerald-400">
                            <CheckCircle2 className="w-24 h-24 mx-auto mb-6" />
                            <p className="text-3xl font-semibold">No Security Issues Detected</p>
                          </div>
                        )}
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {toast && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 20 }}
            className={`fixed bottom-6 right-6 px-6 py-3 rounded-xl shadow-xl ${toast.type === "error" ? "bg-red-600" : "bg-emerald-600"} text-white z-50`}>
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
