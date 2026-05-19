"use client";
import { useState, useEffect } from "react";
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
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { saveScan } from "@/lib/history";

type BodyType =
  | "none"
  | "json"
  | "raw"
  | "form-data"
  | "x-www-form-urlencoded"
  | "graphql"
  | "html"
  | "javascript";

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

export default function Analyzer() {
  const [method, setMethod] = useState("POST");
  const [url, setUrl] = useState("https://httpbin.org/anything");
  const [authType, setAuthType] = useState<
    "no-auth" | "bearer" | "basic" | "api-key" | "jwt"
  >("bearer");
  const [bearer, setBearer] = useState("");
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [headers, setHeaders] = useState([
    { key: "Content-Type", value: "application/json" },
  ]);
  const [bodyType, setBodyType] = useState<BodyType>("json");
  const [body, setBody] = useState(`{
  "username": "admin",
  "password": "123456"
}`);
  const [graphqlVariables, setGraphqlVariables] = useState(`{
  "id": 1
}`);
  const [apiResponse, setApiResponse] = useState<any>(null);
  const [securityResult, setSecurityResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"response" | "security">("security");

  // Load last request from localStorage
  useEffect(() => {
    const savedReq = localStorage.getItem("last_selected_request");
    if (savedReq) {
      try {
        const req = JSON.parse(savedReq);
        setMethod(req.method || "POST");
        setUrl(req.url || "https://httpbin.org/anything");
        setAuthType(req.authType || "bearer");
        setBearer(req.bearer || "");
        setBasicUser(req.basicUser || "");
        setBasicPass(req.basicPass || "");
        setApiKey(req.apiKey || "");
        setHeaders(req.headers || [{ key: "Content-Type", value: "application/json" }]);
        setBodyType(req.bodyType || "json");
        setBody(req.body || "");
      } catch (e) {
        console.error("Failed to load saved request", e);
      }
    }
  }, []);

  useEffect(() => {
    if (bodyType === "none") setBody("");
    if (bodyType === "json") {
      setBody(`{
  "username": "admin",
  "password": "123456"
}`);
    }
    if (bodyType === "html") setBody("<h1>Hello World</h1>");
    if (bodyType === "javascript") setBody("// JavaScript payload");
    if (bodyType === "graphql") {
      setBody(`query User($id: ID!) {
  user(id: $id) {
    id
    name
  }
}`);
    }
  }, [bodyType]);

  const addHeader = () => {
    setHeaders([...headers, { key: "", value: "" }]);
  };

  const removeHeader = (index: number) => {
    setHeaders(headers.filter((_, i) => i !== index));
  };

  const updateHeader = (index: number, field: "key" | "value", value: string) => {
    const updated = [...headers];
    updated[index][field] = value;
    setHeaders(updated);
  };

  const handleSend = async () => {
    setLoading(true);
    setApiResponse(null);
    setSecurityResult(null);

    try {
      // Build Headers
      let headerObj: Record<string, string> = {};
      headers.forEach((h) => {
        if (h.key?.trim()) {
          headerObj[h.key.trim()] = h.value.trim();
        }
      });

      // ==================== FIXED AUTHORIZATION ====================
      if ((authType === "bearer" || authType === "jwt") && bearer.trim()) {
        headerObj["Authorization"] = `Bearer ${bearer.trim()}`;
      } else if (authType === "basic" && basicUser.trim() && basicPass.trim()) {
        headerObj["Authorization"] = `Basic ${btoa(`${basicUser}:${basicPass}`)}`;
      } else if (authType === "api-key" && apiKey.trim()) {
        headerObj["x-api-key"] = apiKey.trim();
      }

      console.log("📤 Final Headers Sent:", headerObj);

      // Prepare Body
      let finalBody: any = null;
      if (bodyType !== "none" && body.trim() && !["GET", "HEAD", "DELETE"].includes(method)) {
        if (bodyType === "json") {
          try {
            finalBody = JSON.parse(body);
          } catch {
            finalBody = body;
          }
        } else if (bodyType === "graphql") {
          let variables = {};
          try {
            variables = graphqlVariables ? JSON.parse(graphqlVariables) : {};
          } catch {}
          finalBody = { query: body, variables };
        } else {
          finalBody = body;
        }
      }

      // Make Actual API Request
      const targetRes = await fetch(url, {
        method,
        headers: headerObj,
        body: finalBody ? JSON.stringify(finalBody) : undefined,
      });

      const rawText = await targetRes.text();
      let responseBody: any;
      try {
        responseBody = JSON.parse(rawText);
      } catch {
        responseBody = rawText;
      }

      const fullResponse = {
        status: targetRes.status,
        statusText: targetRes.statusText,
        headers: Object.fromEntries(targetRes.headers.entries()),
        body: responseBody,
        rawText,
      };

      setApiResponse(fullResponse);

      // Payload for Backend Analyzer
      const analyzePayload = {
        request: {
          method,
          url,
          headers: headerObj,
          body: finalBody,
          bodyType,
        },
        response: fullResponse,
      };

      console.log("📦 Sending to Analyzer:", analyzePayload);

      const analyzeRes = await fetch("http://localhost:8000/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(analyzePayload),
      });

      const analyzeData = await analyzeRes.json();
      setSecurityResult(analyzeData);

      // Save to history
      saveScan({
        id: Date.now(),
        url,
        method,
        result: analyzeData,
        time: new Date().toLocaleString(),
      });

    } catch (err: any) {
      console.error(err);
      setApiResponse({ error: err.message || "Request failed" });
    } finally {
      setLoading(false);
    }
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
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="min-h-screen bg-[#0a0a0f] pb-12"
    >
      <div className="max-w-7xl mx-auto p-6 space-y-8">
        {/* Header */}
        <div className="flex items-center gap-6">
          <motion.div
            whileHover={{ scale: 1.1, rotate: 5 }}
            className="p-5 rounded-3xl bg-gradient-to-br from-violet-600 via-fuchsia-600 to-purple-600 shadow-2xl shadow-purple-500/30"
          >
            <Zap className="w-14 h-14 text-white" />
          </motion.div>
          <div>
            <h1 className="text-7xl font-bold tracking-tighter bg-gradient-to-r from-white via-violet-200 to-fuchsia-200 bg-clip-text text-transparent">
              Trust_Edge
            </h1>
            <p className="text-slate-400 text-xl tracking-wide">
              ENTERPRISE API SECURITY PLATFORM
            </p>
          </div>
        </div>

        {/* Request Bar */}
        <Card className="border border-slate-700/70 bg-slate-950/90 backdrop-blur-2xl shadow-2xl">
          <CardContent className="p-6 flex gap-4 items-center">
            <Select value={method} onValueChange={setMethod}>
              <SelectTrigger className="w-32 h-12">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 h-12 font-mono bg-slate-900/80 border-slate-700"
              placeholder="https://api.example.com"
            />

            <Button
              onClick={handleSend}
              disabled={loading}
              className="h-12 px-10 bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-700 hover:to-violet-700"
            >
              <AnimatePresence mode="wait">
                {loading ? (
                  <motion.div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Analyzing...
                  </motion.div>
                ) : (
                  <motion.div className="flex items-center gap-2">
                    <Play className="w-5 h-5" />
                    Send & Analyze
                  </motion.div>
                )}
              </AnimatePresence>
            </Button>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
          {/* Request Configuration */}
          <div className="lg:col-span-3">
            <Card className="border-slate-700 bg-slate-950/90 h-full">
              <CardHeader>
                <CardTitle className="text-3xl font-semibold">Request Configuration</CardTitle>
              </CardHeader>
              <CardContent className="p-8">
                <Tabs defaultValue="auth">
                  <TabsList className="grid grid-cols-3 mb-8 bg-slate-900">
                    <TabsTrigger value="auth">Authorization</TabsTrigger>
                    <TabsTrigger value="headers">Headers</TabsTrigger>
                    <TabsTrigger value="body">Body</TabsTrigger>
                  </TabsList>

                  <TabsContent value="auth" className="space-y-5">
                    <Select value={authType} onValueChange={(v: any) => setAuthType(v)}>
                      <SelectTrigger className="h-12">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="no-auth">No Authentication</SelectItem>
                        <SelectItem value="bearer">Bearer Token</SelectItem>
                        <SelectItem value="basic">Basic Auth</SelectItem>
                        <SelectItem value="api-key">API Key</SelectItem>
                        <SelectItem value="jwt">JWT Token</SelectItem>
                      </SelectContent>
                    </Select>

                    {(authType === "bearer" || authType === "jwt") && (
                      <Input
                        value={bearer}
                        onChange={(e) => setBearer(e.target.value)}
                        placeholder="Enter Bearer / JWT Token"
                      />
                    )}

                    {authType === "basic" && (
                      <div className="grid grid-cols-2 gap-4">
                        <Input
                          value={basicUser}
                          onChange={(e) => setBasicUser(e.target.value)}
                          placeholder="Username"
                        />
                        <Input
                          value={basicPass}
                          onChange={(e) => setBasicPass(e.target.value)}
                          type="password"
                          placeholder="Password"
                        />
                      </div>
                    )}

                    {authType === "api-key" && (
                      <Input
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        placeholder="API Key"
                      />
                    )}
                  </TabsContent>

                  <TabsContent value="headers" className="space-y-4">
                    {headers.map((h, i) => (
                      <div key={i} className="flex gap-3 items-center">
                        <Input
                          value={h.key}
                          onChange={(e) => updateHeader(i, "key", e.target.value)}
                          placeholder="Header Key"
                        />
                        <Input
                          value={h.value}
                          onChange={(e) => updateHeader(i, "value", e.target.value)}
                          placeholder="Header Value"
                        />
                        <Button variant="ghost" onClick={() => removeHeader(i)}>
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    ))}
                    <Button onClick={addHeader} variant="outline" className="w-full">
                      <Plus className="w-4 h-4 mr-2" />
                      Add Header
                    </Button>
                  </TabsContent>

                  <TabsContent value="body" className="space-y-4">
                    <Select value={bodyType} onValueChange={(v) => setBodyType(v as BodyType)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
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
                        <Textarea
                          value={body}
                          onChange={(e) => setBody(e.target.value)}
                          className="min-h-[320px] font-mono"
                        />
                        {bodyType === "graphql" && (
                          <Textarea
                            value={graphqlVariables}
                            onChange={(e) => setGraphqlVariables(e.target.value)}
                            className="min-h-[120px] font-mono"
                            placeholder="GraphQL Variables (JSON)"
                          />
                        )}
                      </>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          {/* Analysis Console */}
          <div className="lg:col-span-2">
            <Card className="border-slate-700 bg-slate-950/90 h-full">
              <CardHeader>
                <CardTitle className="text-3xl font-semibold">Analysis Console</CardTitle>
              </CardHeader>
              <CardContent className="p-8">
                <Tabs value={activeTab} onValueChange={(v: any) => setActiveTab(v)}>
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
                      <pre className="bg-black p-6 rounded-2xl text-sm overflow-auto max-h-[500px] font-mono border border-slate-800 whitespace-pre-wrap">
                        {JSON.stringify(apiResponse, null, 2)}
                      </pre>
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
                              {securityResult.findings?.length || 0} issues • Risk Score:{" "}
                              <span className="text-orange-400 font-semibold">
                                {securityResult.overall_risk_score || 0}%
                              </span>
                            </p>
                          </div>
                          <Button onClick={downloadReport} className="bg-gradient-to-r from-purple-600 to-violet-600">
                            <Download className="mr-2 h-4 w-4" />
                            Export Report
                          </Button>
                        </div>

                        {securityResult.findings?.length > 0 ? (
                          <div className="space-y-6">
                            {securityResult.findings
                              .sort((a: any, b: any) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0))
                              .map((f: any, i: number) => (
                                <motion.div
                                  key={i}
                                  initial={{ opacity: 0, y: 30 }}
                                  animate={{ opacity: 1, y: 0 }}
                                  className={`p-7 rounded-3xl border ${severityBorder[f.severity]} bg-slate-900/80`}
                                >
                                  <div className="flex justify-between items-start gap-4">
                                    <div className="flex-1">
                                      <div className="flex items-center gap-4">
                                        <AlertTriangle className="w-7 h-7 text-orange-400" />
                                        <h4 className="text-2xl font-semibold">{f.issue}</h4>
                                      </div>
                                      {f.category && <p className="text-purple-400 mt-2 text-sm">Category: {f.category}</p>}
                                      <p className="mt-4 text-slate-300 leading-relaxed">{f.description}</p>
                                    </div>
                                    <Badge className={`text-sm px-5 py-2 ${severityColors[f.severity]}`}>
                                      {f.severity}
                                    </Badge>
                                  </div>
                                </motion.div>
                              ))}
                          </div>
                        ) : (
                          <div className="flex flex-col items-center justify-center py-24 text-emerald-400">
                            <CheckCircle2 className="w-24 h-24 mx-auto mb-6" />
                            <p className="text-3xl font-semibold">No Security Issues Found</p>
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
    </motion.div>
  );
}
