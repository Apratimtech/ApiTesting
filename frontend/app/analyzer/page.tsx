"use client";
import { useState } from "react";
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
import { Trash2, Plus, Eye, Zap, Play, AlertTriangle, ShieldCheck } from "lucide-react";
import { saveScan } from "@/lib/history";
import { Badge } from "@/components/ui/badge"; // assume you have this

type BodyType = "none" | "json" | "raw" | "form-data" | "x-www-form-urlencoded" | "binary" | "graphql";

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
  const [body, setBody] = useState(`{\n  "title": "Test Post",\n  "body": "This is a test"\n}`);

  // Results
  const [apiResponse, setApiResponse] = useState<any>(null);
  const [securityResult, setSecurityResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"response" | "security">("response");

  const handleSend = async () => {
    setLoading(true);
    setApiResponse(null);
    setSecurityResult(null);

    let headerObj: Record<string, string> = {};
    headers.forEach((h) => {
      if (h.key?.trim()) headerObj[h.key.trim()] = h.value.trim();
    });

    // Add Authorization
    if ((authType === "bearer" || authType === "jwt") && bearer.trim()) {
      headerObj["Authorization"] = `Bearer ${bearer.trim()}`;
    }
    if (authType === "basic" && basicUser && basicPass) {
      headerObj["Authorization"] = `Basic ${btoa(`${basicUser}:${basicPass}`)}`;
    }
    if (authType === "api-key" && apiKey.trim()) {
      headerObj["x-api-key"] = apiKey.trim(); // or "Authorization" depending on API
    }

    // Prepare body
    let finalBody: any = null;
    if (bodyType !== "none" && body.trim() && !["GET", "HEAD", "DELETE"].includes(method)) {
      try {
        finalBody = (bodyType === "json" || bodyType === "graphql") ? JSON.parse(body) : body;
      } catch {
        finalBody = body;
      }
    }

    const requestPayload = {
      url,
      method,
      headers: headerObj,
      body: finalBody,
    };

    try {
      // 1. Call the actual target API
      const targetRes = await fetch(url, {
        method,
        headers: headerObj,
        body: finalBody ? (typeof finalBody === "string" ? finalBody : JSON.stringify(finalBody)) : undefined,
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
      };

      setApiResponse(fullResponse);

      // 2. Send to your security analyzer (send both request + response)
      const analyzeRes = await fetch("http://localhost:8000/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request: requestPayload,
          response: fullResponse,
        }),
      });

      const analyzeData = await analyzeRes.json();
      setSecurityResult(analyzeData);

      // Save to history
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

  const getRiskColor = (score: number) => {
    if (score >= 8) return "bg-red-500";
    if (score >= 5) return "bg-orange-500";
    return "bg-green-500";
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-7xl mx-auto p-6 space-y-8">
      <div className="flex items-center gap-4">
        <div className="p-3 bg-gradient-to-br from-purple-600 to-violet-600 rounded-2xl">
          <Zap className="w-10 h-10 text-white" />
        </div>
        <div>
          <h1 className="text-5xl font-bold tracking-tighter text-white">Trust_Edge</h1>
          <p className="text-slate-400 text-lg">API Security Analyzer • Postman + Security</p>
        </div>
      </div>

      {/* URL Bar */}
      <Card className="glass neon-glow border-slate-700 bg-slate-950/80 backdrop-blur-xl">
        <CardContent className="p-6 flex gap-4 items-center">
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger className="w-28 h-14">
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

          <Button onClick={handleSend} disabled={loading} className="h-14 px-10 bg-purple-600 hover:bg-purple-700">
            {loading ? "Analyzing..." : <><Play className="w-5 h-5 mr-2" /> Send & Analyze</>}
          </Button>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        {/* Request Configuration */}
        <div className="lg:col-span-3">
          <Card className="glass neon-glow h-full border-slate-700 bg-slate-950/80 backdrop-blur-xl">
            <CardHeader>
              <CardTitle>Request Configuration</CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <Tabs defaultValue="auth" className="w-full">
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
                    <Input value={bearer} onChange={(e) => setBearer(e.target.value)} placeholder="Paste token here..." className="font-mono" />
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
                      <Input value={h.key} onChange={(e) => updateHeader(i, "key", e.target.value)} placeholder="Key" className="font-mono" />
                      <Input value={h.value} onChange={(e) => updateHeader(i, "value", e.target.value)} placeholder="Value" className="font-mono" />
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
                  <Select value={bodyType} onValueChange={(value: BodyType) => setBodyType(value)}>
                    <SelectTrigger className="h-12">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="raw">Raw</SelectItem>
                      <SelectItem value="form-data">form-data</SelectItem>
                      <SelectItem value="x-www-form-urlencoded">x-www-form-urlencoded</SelectItem>
                      <SelectItem value="graphql">GraphQL</SelectItem>
                    </SelectContent>
                  </Select>

                  {bodyType !== "none" && (
                    <Textarea
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      className="min-h-[380px] font-mono bg-slate-950 border-slate-700 resize-y"
                      placeholder="Request body..."
                    />
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* Response & Security */}
        <div className="lg:col-span-2">
          <Card className="glass neon-glow h-full border-slate-700 bg-slate-950/80 backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                Response & Analysis
                {securityResult && (
                  <Badge className={`${getRiskColor(securityResult.overall_risk_score)} text-white`}>
                    Risk: {securityResult.overall_risk_score}/10
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <Tabs value={activeTab} onValueChange={(v: any) => setActiveTab(v)}>
                <TabsList className="grid grid-cols-2 mb-6">
                  <TabsTrigger value="response">API Response</TabsTrigger>
                  <TabsTrigger value="security">Security Analysis</TabsTrigger>
                </TabsList>

                <TabsContent value="response" className="min-h-[400px]">
                  {!apiResponse ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-500">
                      <Eye className="w-16 h-16 mb-4 opacity-40" />
                      <p>Send request to see response</p>
                    </div>
                  ) : apiResponse.error ? (
                    <p className="text-red-400">{apiResponse.error}</p>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex gap-4">
                        <div className="text-2xl font-mono">
                          {apiResponse.status} {apiResponse.statusText}
                        </div>
                      </div>
                      <pre className="bg-black p-6 rounded-xl text-sm overflow-auto max-h-[500px]">
                        {JSON.stringify(apiResponse, null, 2)}
                      </pre>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="security" className="min-h-[400px]">
                  {!securityResult ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-500">
                      <ShieldCheck className="w-16 h-16 mb-4 opacity-40" />
                      <p>Security analysis will appear here</p>
                    </div>
                  ) : securityResult.error ? (
                    <p className="text-red-400">{securityResult.error}</p>
                  ) : (
                    <div className="space-y-6">
                      <div>
                        <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                          <AlertTriangle className="w-5 h-5" /> Findings ({securityResult.findings?.length || 0})
                        </h3>
                        <div className="space-y-3">
                          {securityResult.findings?.map((f: any, i: number) => (
                            <div key={i} className="p-4 bg-slate-900 rounded-xl border border-slate-700">
                              <div className="flex justify-between">
                                <p className="font-medium">{f.issue}</p>
                                <Badge variant={f.severity >= 8 ? "destructive" : f.severity >= 5 ? "default" : "secondary"}>
                                  Severity: {f.severity}
                                </Badge>
                              </div>
                              {f.description && <p className="text-sm text-slate-400 mt-1">{f.description}</p>}
                              {f.category && <p className="text-xs text-purple-400 mt-2">Category: {f.category}</p>}
                            </div>
                          ))}
                        </div>
                      </div>

                      {securityResult.ai_suggestions && (
                        <div>
                          <h3 className="text-lg font-semibold mb-2">AI Suggestions</h3>
                          <pre className="bg-black p-4 rounded-xl text-sm">{JSON.stringify(securityResult.ai_suggestions, null, 2)}</pre>
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
    </motion.div>
  );
}
