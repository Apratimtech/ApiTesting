"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
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
import { Trash2, Plus, Eye, Zap, Play, ShieldCheck, Download } from "lucide-react";
import { saveScan } from "@/lib/history";
import { Badge } from "@/components/ui/badge";

type BodyType = "none" | "json" | "raw" | "form-data" | "x-www-form-urlencoded" | "graphql" | "html" | "javascript";

export default function Analyzer() {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("https://jsonplaceholder.typicode.com/posts");

  // Auth
  const [authType, setAuthType] = useState<"no-auth" | "bearer" | "basic" | "api-key" | "jwt">("no-auth");
  const [bearer, setBearer] = useState("");
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  const [apiKey, setApiKey] = useState("");

  // Headers
  const [headers, setHeaders] = useState([{ key: "Content-Type", value: "application/json" }]);

  // Body
  const [bodyType, setBodyType] = useState<BodyType>("json");
  const [body, setBody] = useState(`{\n "title": "Test Post",\n "body": "This is a test"\n}`);
  const [graphqlVariables, setGraphqlVariables] = useState(`{\n "id": 1\n}`);

  // Results
  const [apiResponse, setApiResponse] = useState<any>(null);
  const [securityResult, setSecurityResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"response" | "security">("response");
  const [responseView, setResponseView] = useState<"pretty" | "raw">("pretty");

  // Load request when clicked from Sidebar
  useEffect(() => {
    const loadSavedRequest = () => {
      const savedReq = localStorage.getItem("last_selected_request");
      if (savedReq) {
        try {
          const req = JSON.parse(savedReq);
          setMethod(req.method || "GET");
          setUrl(req.url || "");
          setAuthType(req.authType || "no-auth");
          setBearer(req.bearer || "");
          setBasicUser(req.basicUser || "");
          setBasicPass(req.basicPass || "");
          setApiKey(req.apiKey || "");
          setHeaders(req.headers || [{ key: "Content-Type", value: "application/json" }]);
          setBodyType(req.bodyType || "json");
          setBody(req.body || "");
          setGraphqlVariables(req.graphqlVariables || `{\n "id": 1\n}`);
          localStorage.removeItem("last_selected_request");
        } catch (e) {
          console.error("Failed to load request", e);
        }
      }
    };
    loadSavedRequest();
    const interval = setInterval(loadSavedRequest, 700);
    return () => clearInterval(interval);
  }, []);

  // Reset body when body type changes
  useEffect(() => {
    if (bodyType === "none") {
      setBody("");
    } else if (bodyType === "json" || bodyType === "graphql") {
      setBody(`{\n "title": "Test Post",\n "body": "This is a test"\n}`);
    } else if (bodyType === "raw" || bodyType === "html" || bodyType === "javascript") {
      setBody(bodyType === "html" ? "<h1>Hello World</h1>" : "// JavaScript code here...");
    } else if (bodyType === "form-data" || bodyType === "x-www-form-urlencoded") {
      setBody("key1=value1&key2=value2");
    }
  }, [bodyType]);

  const handleSend = async () => {
    setLoading(true);
    setApiResponse(null);
    setSecurityResult(null);

    let headerObj: Record<string, string> = {};
    headers.forEach((h) => {
      if (h.key?.trim()) headerObj[h.key.trim()] = h.value.trim();
    });

    const hasContentType = Object.keys(headerObj).some(
      key => key.toLowerCase() === "content-type"
    );

    if (!hasContentType) {
      if (bodyType === "json" || bodyType === "graphql") {
        headerObj["Content-Type"] = "application/json";
      } else if (bodyType === "javascript") {
        headerObj["Content-Type"] = "application/javascript";
      } else if (bodyType === "html") {
        headerObj["Content-Type"] = "text/html";
      } else if (bodyType === "x-www-form-urlencoded") {
        headerObj["Content-Type"] = "application/x-www-form-urlencoded";
      } else if (bodyType === "raw") {
        headerObj["Content-Type"] = "text/plain";
      }
    }

    // Authorization
    if ((authType === "bearer" || authType === "jwt") && bearer.trim()) {
      headerObj["Authorization"] = `Bearer ${bearer.trim()}`;
    }
    if (authType === "basic" && basicUser && basicPass) {
      headerObj["Authorization"] = `Basic ${btoa(`${basicUser}:${basicPass}`)}`;
    }
    if (authType === "api-key" && apiKey.trim()) {
      headerObj["x-api-key"] = apiKey.trim();
    }

    let finalBody: any = null;
    if (bodyType !== "none" && body.trim() && !["GET", "HEAD", "DELETE"].includes(method)) {
      try {
        finalBody = (bodyType === "json" || bodyType === "graphql") ? JSON.parse(body) : body;
      } catch {
        finalBody = body;
      }
    }

    const requestPayload = {
      id: Date.now().toString(),
      method,
      url,
      headers: headerObj,
      body: finalBody,
    };

    try {
      const targetRes = await fetch(url, {
        method,
        headers: headerObj,
        body: finalBody
          ? (typeof finalBody === "string" ? finalBody : JSON.stringify(finalBody))
          : undefined,
      });

      const rawText = await targetRes.text();
      let responseBody;
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
        rawText: rawText,
      };

      setApiResponse(fullResponse);

      // ✅ YOUR REQUESTED BACKEND CALL
      const analyzeRes = await fetch("http://localhost:8000/api/v1/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          id: Date.now().toString(),
          method,
          url,
          headers: headerObj,
          body: finalBody,
        }),
      });

      const analyzeData = await analyzeRes.json();

      setSecurityResult({
        findings: [],
        overall_risk_score: 0,
        severity: "LOW",
        ...analyzeData,
      });

      saveScan({
        id: Date.now(),
        url,
        method,
        result: analyzeData,
        risk: analyzeData.overall_risk_score || 0,
        time: new Date().toLocaleString(),
      });
    } catch (err: any) {
      setApiResponse({ error: err.message || "Request failed" });
    } finally {
      setLoading(false);
    }
  };

  const addHeader = () => setHeaders([...headers, { key: "", value: "" }]);
  const removeHeader = (index: number) => setHeaders(headers.filter((_, i) => i !== index));
  const updateHeader = (index: number, field: "key" | "value", value: string) => {
    const updated = [...headers];
    updated[index][field] = value;
    setHeaders(updated);
  };

  const downloadReport = () => {
    if (!securityResult) return;
    const report = {
      ...securityResult,
      generated_at: new Date().toISOString(),
      analyzed_url: url,
      method: method,
      generated_by: "Trust_Edge Analyzer",
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `TrustEdge_Report_${new Date().toISOString().slice(0,10)}.json`;
    link.click();
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-7xl mx-auto p-6 space-y-8">
      <div className="flex items-center gap-4">
        <div className="p-3 bg-gradient-to-br from-purple-600 to-violet-600 rounded-2xl">
          <Zap className="w-10 h-10 text-white" />
        </div>
        <div>
          <h1 className="text-5xl font-bold tracking-tighter text-white">Trust_Edge</h1>
        </div>
      </div>

      {/* URL Bar */}
      <Card className="border-slate-700 bg-slate-950/90 backdrop-blur-xl">
        <CardContent className="p-6 flex gap-4 items-center">
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger className="w-32 h-14 text-lg font-medium">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"].map((m) => (
                <SelectItem key={m} value={m}>{m}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 h-14 bg-slate-900 border-slate-700 text-lg font-mono"
            placeholder="https://api.example.com/endpoint"
          />
          <Button
            onClick={handleSend}
            disabled={loading}
            className="h-14 px-12 bg-purple-600 hover:bg-purple-700 text-lg font-semibold"
          >
            {loading ? "Analyzing..." : <><Play className="w-5 h-5 mr-2" /> Send & Analyze</>}
          </Button>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        <div className="lg:col-span-3 space-y-6">
          <Card className="border-slate-700 bg-slate-950/90 backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-2xl">Request Configuration</CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <Tabs defaultValue="body" className="w-full">
                <TabsList className="grid grid-cols-3 mb-8 bg-slate-900 border border-slate-700 rounded-xl p-1">
                  <TabsTrigger value="auth">Authorization</TabsTrigger>
                  <TabsTrigger value="headers">Headers</TabsTrigger>
                  <TabsTrigger value="body">Body</TabsTrigger>
                </TabsList>

                <TabsContent value="auth" className="space-y-6">
                  <Select value={authType} onValueChange={(v: any) => setAuthType(v)}>
                    <SelectTrigger className="h-12">
                      <SelectValue placeholder="Select authentication type" />
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
                    <Input value={bearer} onChange={(e) => setBearer(e.target.value)} placeholder="Enter Bearer / JWT Token" className="font-mono" />
                  )}
                  {authType === "basic" && (
                    <div className="grid grid-cols-2 gap-4">
                      <Input value={basicUser} onChange={(e) => setBasicUser(e.target.value)} placeholder="Username" />
                      <Input type="password" value={basicPass} onChange={(e) => setBasicPass(e.target.value)} placeholder="Password" />
                    </div>
                  )}
                  {authType === "api-key" && (
                    <Input value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="API Key" className="font-mono" />
                  )}
                </TabsContent>

                <TabsContent value="headers" className="space-y-4">
                  {headers.map((h, i) => (
                    <div key={i} className="flex gap-3 items-center">
                      <Input value={h.key} onChange={(e) => updateHeader(i, "key", e.target.value)} placeholder="Header Key" className="font-mono" />
                      <Input value={h.value} onChange={(e) => updateHeader(i, "value", e.target.value)} placeholder="Header Value" className="font-mono" />
                      <Button variant="ghost" size="icon" onClick={() => removeHeader(i)}>
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                  <Button onClick={addHeader} variant="outline" className="w-full border-dashed">
                    <Plus className="w-4 h-4 mr-2" /> Add Header
                  </Button>
                </TabsContent>

                <TabsContent value="body" className="space-y-4">
                  <Select value={bodyType} onValueChange={(value) => setBodyType(value as BodyType)}>
                    <SelectTrigger className="h-12">
                      <SelectValue placeholder="Select body type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="raw">Raw</SelectItem>
                      <SelectItem value="html">HTML</SelectItem>
                      <SelectItem value="javascript">JavaScript</SelectItem>
                      <SelectItem value="form-data">form-data</SelectItem>
                      <SelectItem value="x-www-form-urlencoded">x-www-form-urlencoded</SelectItem>
                      <SelectItem value="graphql">GraphQL</SelectItem>
                    </SelectContent>
                  </Select>

                  {bodyType !== "none" && (
                    <div className="space-y-4">
                      <Textarea
                        value={body}
                        onChange={(e) => setBody(e.target.value)}
                        className="min-h-[320px] font-mono bg-slate-950 border-slate-700 resize-y text-sm"
                        placeholder={
                          bodyType === "html" ? "<h1>Hello World</h1>" :
                          bodyType === "javascript" ? "// Write your JavaScript here" :
                          bodyType === "graphql" ? "Write your GraphQL query..." :
                          "Enter request body..."
                        }
                      />
                      {bodyType === "graphql" && (
                        <div>
                          <p className="text-sm text-slate-400 mb-2">GraphQL Variables</p>
                          <Textarea
                            value={graphqlVariables}
                            onChange={(e) => setGraphqlVariables(e.target.value)}
                            className="min-h-[140px] font-mono bg-slate-950 border-slate-700"
                            placeholder='{\n "id": 1\n}'
                          />
                        </div>
                      )}
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* Response & Security Analysis */}
        <div className="lg:col-span-2">
          <Card className="border-slate-700 bg-slate-950/90 backdrop-blur-xl h-full">
            <CardHeader>
              <CardTitle className="text-2xl">Response & Security Analysis</CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <Tabs value={activeTab} onValueChange={(v: any) => setActiveTab(v)}>
                <TabsList className="grid grid-cols-2 mb-6">
                  <TabsTrigger value="response">API Response</TabsTrigger>
                  <TabsTrigger value="security">Security Analysis</TabsTrigger>
                </TabsList>

                <TabsContent value="response" className="min-h-[420px]">
                  {!apiResponse ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-500 py-12">
                      <Eye className="w-20 h-20 mb-6 opacity-40" />
                      <p className="text-xl">Send request to see response</p>
                    </div>
                  ) : apiResponse.error ? (
                    <p className="text-red-400 text-lg">{apiResponse.error}</p>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <div className="text-2xl font-mono">
                          {apiResponse.status} {apiResponse.statusText}
                        </div>
                        <Select value={responseView} onValueChange={(v: "pretty" | "raw") => setResponseView(v)}>
                          <SelectTrigger className="w-40">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="pretty">Pretty</SelectItem>
                            <SelectItem value="raw">Raw</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      {responseView === "pretty" ? (
                        <pre className="bg-black p-6 rounded-2xl text-sm overflow-auto max-h-[500px] font-mono border border-slate-800">
                          {JSON.stringify(apiResponse, null, 2)}
                        </pre>
                      ) : (
                        <pre className="bg-black p-6 rounded-2xl text-sm overflow-auto max-h-[500px] font-mono border border-slate-800 whitespace-pre-wrap">
                          {apiResponse.rawText || JSON.stringify(apiResponse, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="security" className="min-h-[420px] space-y-6">
                  {!securityResult ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-500 py-16">
                      <ShieldCheck className="w-20 h-20 mb-6 opacity-40" />
                      <p className="text-2xl font-medium">Security Analysis</p>
                      <p className="text-slate-400 mt-2">Send request to analyze vulnerabilities</p>
                    </div>
                  ) : (
                    <div className="space-y-8">
                      <div className="bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-700 rounded-3xl p-8">
                        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                          <div>
                            <p className="text-sm text-slate-400 mb-1">OVERALL RISK SCORE</p>
                            <div className="flex items-baseline gap-3">
                              <span className={`text-7xl font-bold tracking-tighter ${
                                securityResult.overall_risk_score >= 8 ? 'text-red-500' :
                                securityResult.overall_risk_score >= 6 ? 'text-orange-500' : 'text-green-500'
                              }`}>
                                {securityResult.overall_risk_score}
                              </span>
                              <span className="text-4xl text-slate-500">/10</span>
                            </div>
                            <p className="text-2xl font-semibold mt-2">
                              {securityResult.severity || "MEDIUM"} RISK LEVEL
                            </p>
                          </div>
                          <Button
                            onClick={downloadReport}
                            className="bg-purple-600 hover:bg-purple-700 px-8 py-6 text-lg flex items-center gap-2"
                          >
                            <Download className="w-5 h-5" />
                            Download Full Report
                          </Button>
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-6">
                          <h3 className="text-2xl font-semibold">Vulnerability Findings</h3>
                          <p className="text-slate-400">
                            {securityResult.findings?.length || 0} issues detected
                          </p>
                        </div>
                        {securityResult.findings && securityResult.findings.length > 0 ? (
                          <div className="space-y-5">
                            {securityResult.findings
                              .sort((a: any, b: any) => (b.severity || 0) - (a.severity || 0))
                              .map((f: any, i: number) => (
                                <div key={i} className="bg-slate-900 border border-slate-700 rounded-2xl p-7 hover:border-slate-600 transition-all">
                                  <div className="flex justify-between items-start mb-5">
                                    <div className="flex-1">
                                      <h4 className="text-xl font-semibold text-white">{f.issue}</h4>
                                      <p className="text-purple-400 text-sm mt-1">Category: {f.category}</p>
                                    </div>
                                    <Badge className={`${f.severity >= 8 ? 'bg-red-500' : f.severity >= 6 ? 'bg-orange-500' : 'bg-yellow-500'} text-white`}>
                                      {f.severity}/10
                                    </Badge>
                                  </div>
                                  <p className="text-slate-300 leading-relaxed mb-6">{f.description}</p>
                                  {f.recommendation && (
                                    <div className="bg-slate-800 border-l-4 border-purple-500 pl-5 py-4 rounded-r-xl">
                                      <p className="text-purple-400 font-medium text-sm mb-1">RECOMMENDATION</p>
                                      <p className="text-slate-200">{f.recommendation}</p>
                                    </div>
                                  )}
                                </div>
                              ))}
                          </div>
                        ) : (
                          <div className="text-center py-16 text-green-400">
                            <ShieldCheck className="w-16 h-16 mx-auto mb-4" />
                            <p className="text-2xl font-medium">No vulnerabilities detected</p>
                            <p className="text-slate-500 mt-2">Your API request looks secure</p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
