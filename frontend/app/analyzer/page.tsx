"use client";
import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Trash2, Plus, AlertTriangle, ShieldCheck, Eye, Zap, CheckCircle } from "lucide-react";
import { saveScan } from "@/lib/history";

export default function Analyzer() {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("https://jsonplaceholder.typicode.com/posts");

  const [authType, setAuthType] = useState<"no-auth" | "bearer" | "basic" | "api-key">("no-auth");
  const [bearer, setBearer] = useState("");
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  const [apiKey, setApiKey] = useState("");

  const [headers, setHeaders] = useState([{ key: "Content-Type", value: "application/json" }]);

  const [bodyType, setBodyType] = useState("json");
  const [body, setBody] = useState(`{\n  "title": "Test Post",\n  "body": "This is a test"\n}`);

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
      if (h.key?.trim()) headerObj[h.key] = h.value;
    });

    if (authType === "bearer" && bearer.trim()) {
      headerObj["Authorization"] = `Bearer ${bearer.trim()}`;
    }
    if (authType === "basic" && basicUser && basicPass) {
      headerObj["Authorization"] = `Basic ${btoa(`${basicUser}:${basicPass}`)}`;
    }
    if (authType === "api-key" && apiKey.trim()) {
      headerObj["x-api-key"] = apiKey.trim();
    }

    let finalBody: any = null;
    try {
      finalBody = bodyType === "json" ? JSON.parse(body) : body;
    } catch {
      finalBody = body;
    }

    const payloadForAnalyzer = {
      request: {
        url,
        method,
        headers: headerObj,
        body: finalBody
      }
    };

    try {
      const targetRes = await fetch(url, {
        method: method,
        headers: headerObj,
        body: (method !== "GET" && method !== "HEAD") ? JSON.stringify(finalBody) : undefined,
      });

      // ✅ FIXED PART (ONLY CHANGE)
      let responseBody;
      const rawText = await targetRes.text();
      try {
        responseBody = JSON.parse(rawText);
      } catch {
        responseBody = rawText;
      }

      setApiResponse({
        status: targetRes.status,
        statusText: targetRes.statusText,
        body: responseBody,
      });

      const analyzeRes = await fetch("http://localhost:8000/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payloadForAnalyzer),
      });

      const analysisData = await analyzeRes.json();
      setSecurityResult(analysisData);

      saveScan({
        id: Date.now(),
        url,
        method,
        result: analysisData,
        risk: analysisData.overall_risk_score || 0,
        time: new Date().toLocaleString(),
      });

    } catch (err: any) {
      console.error("Request failed:", err);
      setApiResponse({ error: err.message || "Failed to reach target API" });
      setSecurityResult({ error: "Security analysis failed. Is backend running?" });
    }

    setLoading(false);
  };

  const addHeader = () => setHeaders([...headers, { key: "", value: "" }]);
  const removeHeader = (index: number) => setHeaders(headers.filter((_, i) => i !== index));
  const updateHeader = (index: number, field: "key" | "value", value: string) => {
    const updated = [...headers];
    updated[index][field] = value;
    setHeaders(updated);
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-7xl mx-auto p-6 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-5xl font-bold tracking-tighter text-white flex items-center gap-3">
            <Zap className="w-10 h-10 text-purple-500" /> Trust_Edge
          </h1>
          <p className="text-slate-400 text-lg">Professional API Security Analyzer</p>
        </div>
      </div>

      <Card className="glass neon-glow border-slate-700">
        <CardContent className="p-6 flex gap-4 items-center">
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger className="w-32 h-12"><SelectValue /></SelectTrigger>
            <SelectContent>
              {["GET", "POST", "PUT", "DELETE", "PATCH"].map(m => (
                <SelectItem key={m} value={m}>{m}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 h-12 bg-slate-950 border-slate-700 text-lg font-mono"
          />

          <Button onClick={handleSend} disabled={loading} className="h-12 px-10 neon-glow font-semibold">
            {loading ? "Sending & Analyzing..." : "Send & Analyze"}
          </Button>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        <div className="lg:col-span-3">
          <Card className="glass neon-glow h-full border-slate-700">
            <CardHeader>
              <CardTitle>Request Configuration</CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <Tabs defaultValue="auth">
                <TabsList className="grid grid-cols-3 mb-8 bg-slate-950 border border-slate-700">
                  <TabsTrigger value="auth">Authorization</TabsTrigger>
                  <TabsTrigger value="headers">Headers</TabsTrigger>
                  <TabsTrigger value="body">Body</TabsTrigger>
                </TabsList>

                <TabsContent value="auth" className="space-y-6">
                  <Select value={authType} onValueChange={(value: any) => setAuthType(value)}>
                    <SelectTrigger className="h-12">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="no-auth">No Authentication</SelectItem>
                      <SelectItem value="bearer">Bearer Token</SelectItem>
                      <SelectItem value="basic">Basic Auth</SelectItem>
                      <SelectItem value="api-key">API Key</SelectItem>
                    </SelectContent>
                  </Select>
                </TabsContent>

                <TabsContent value="headers" className="space-y-4">
                  {headers.map((h, i) => (
                    <div key={i} className="flex gap-3 items-center group">
                      <Input value={h.key} onChange={e => updateHeader(i, "key", e.target.value)} />
                      <Input value={h.value} onChange={e => updateHeader(i, "value", e.target.value)} />
                      <Button variant="ghost" size="icon" onClick={() => removeHeader(i)}>
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                  <Button onClick={addHeader}>
                    <Plus className="w-4 h-4 mr-2" /> Add Header
                  </Button>
                </TabsContent>

                <TabsContent value="body">
                  <Textarea value={body} onChange={(e) => setBody(e.target.value)} />
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-2">
          <Card className="glass neon-glow h-full border-slate-700">
            <CardHeader>
              <CardTitle>Response & Analysis</CardTitle>
            </CardHeader>

            <CardContent>
              {apiResponse && (
                <pre>
                  {typeof apiResponse.body === "object"
                    ? JSON.stringify(apiResponse.body, null, 2)
                    : apiResponse.body}
                </pre>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
