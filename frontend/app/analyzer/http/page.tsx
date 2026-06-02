"use client";
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Zap, Play, Save, Power, Send, Trash2 } from "lucide-react";
import { motion } from "framer-motion";

export default function HttpScreen() {
  const [method, setMethod] = useState<"GET" | "POST" | "PUT" | "PATCH" | "DELETE">("GET");
  const [url, setUrl] = useState("https://jsonplaceholder.typicode.com/posts");
  const [headers, setHeaders] = useState([{ key: "Content-Type", value: "application/json" }]);
  const [body, setBody] = useState('{\n  "title": "Trust_Edge Test",\n  "body": "Hello from Trust_Edge!"\n}');

  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [status, setStatus] = useState<number | null>(null);
  const [responseTime, setResponseTime] = useState<number | null>(null);

  const [logs, setLogs] = useState<string[]>([
    "⚡ HTTP Client Initialized",
    "Ready to send requests..."
  ]);

  useEffect(() => {
    const saved = localStorage.getItem("last_selected_request");
    if (saved) {
      try {
        const req = JSON.parse(saved);
        if (req.type === "HTTP") {
          setMethod(req.method || "GET");
          setUrl(req.url || url);
          if (req.body) setBody(req.body);
          if (req.headers && Array.isArray(req.headers)) {
            setHeaders(req.headers);
          }
        }
      } catch (e) {
        console.error("Failed to load saved HTTP request", e);
      }
    }
  }, []);

  const addLog = (text: string) => {
    setLogs(prev => [`${new Date().toLocaleTimeString()} ${text}`, ...prev].slice(0, 50));
  };

  const addHeader = () => setHeaders([...headers, { key: "", value: "" }]);

  const updateHeader = (index: number, field: "key" | "value", value: string) => {
    const newHeaders = [...headers];
    newHeaders[index][field] = value;
    setHeaders(newHeaders);
  };

  const removeHeader = (index: number) => {
    setHeaders(headers.filter((_, i) => i !== index));
  };

  const sendRequest = async () => {
    if (!url) {
      addLog("⚠️ Please enter a valid URL");
      return;
    }

    setIsLoading(true);
    setResponse(null);
    setStatus(null);
    setResponseTime(null);

    addLog(`🚀 Sending ${method} → ${url}`);

    try {
      const start = Date.now();

      // Build headers from user input
      const headerObj: Record<string, string> = headers.reduce((acc, h) => {
        if (h.key.trim()) acc[h.key.trim()] = h.value;
        return acc;
      }, {} as Record<string, string>);

      const options: RequestInit = {
        method,
        // Route through /api/proxy to fix CORS on external APIs
        // x-proxy-url tells the proxy where to forward the request
        headers: {
          ...headerObj,
          "x-proxy-url": url,
        },
      };

      if (["POST", "PUT", "PATCH"].includes(method) && body) {
        options.body = body;
      }

      // Call /api/proxy instead of the external URL directly
      const res = await fetch("/api/proxy", options);
      const duration = Date.now() - start;

      let data;
      try {
        data = await res.json();
      } catch {
        data = await res.text();
      }

      setStatus(res.status);
      setResponse(data);
      setResponseTime(duration);

      addLog(`✅ ${method} ${res.status} ${res.statusText} (${duration}ms)`);
    } catch (error: any) {
      setResponse({ error: error.message });
      addLog(`❌ Request Failed: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const saveRequest = () => {
    const reqData = {
      id: Date.now().toString(),
      name: `${method} ${url.split("//")[1]?.split("/")[0] || "Request"}`,
      method,
      url,
      type: "HTTP",
      body: ["POST", "PUT", "PATCH"].includes(method) ? body : undefined,
      headers,
    };
    localStorage.setItem("last_selected_request", JSON.stringify(reqData));
    alert("✅ HTTP Request Saved!");
  };

  return (
    <div className="min-h-screen bg-[#0a0b12] text-white pb-12">
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center gap-5 mb-12">
          <motion.div
            whileHover={{ rotate: 12, scale: 1.1 }}
            className="p-5 rounded-3xl bg-gradient-to-br from-blue-500 to-cyan-600 shadow-xl shadow-blue-500/30"
          >
            <Zap className="w-14 h-14 text-white" />
          </motion.div>
          <div>
            <h1 className="text-6xl font-bold tracking-tighter">HTTP Client</h1>
            <p className="text-slate-400 text-xl">REST API Testing Console</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Panel */}
          <div className="lg:col-span-5 space-y-6">
            <Card className="bg-slate-950 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-3 text-blue-400">
                  <Power className="w-6 h-6" /> Request Settings
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6 p-8">
                <div className="flex gap-3">
                  <Select value={method} onValueChange={(v: any) => setMethod(v)}>
                    <SelectTrigger className="w-32 bg-slate-900 border-slate-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                      <SelectItem value="PUT">PUT</SelectItem>
                      <SelectItem value="PATCH">PATCH</SelectItem>
                      <SelectItem value="DELETE">DELETE</SelectItem>
                    </SelectContent>
                  </Select>

                  <Input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://api.example.com"
                    className="bg-slate-900 border-slate-700 font-mono"
                  />
                </div>

                {/* Headers */}
                <div>
                  <div className="flex justify-between mb-3">
                    <label className="text-sm text-slate-400">Headers</label>
                    <Button onClick={addHeader} variant="outline" size="sm">+ Add</Button>
                  </div>
                  {headers.map((header, index) => (
                    <div key={index} className="flex gap-2 mb-2">
                      <Input
                        placeholder="Header Key"
                        value={header.key}
                        onChange={(e) => updateHeader(index, "key", e.target.value)}
                        className="bg-slate-900 border-slate-700"
                      />
                      <Input
                        placeholder="Value"
                        value={header.value}
                        onChange={(e) => updateHeader(index, "value", e.target.value)}
                        className="bg-slate-900 border-slate-700"
                      />
                      <Button variant="destructive" size="icon" onClick={() => removeHeader(index)}>
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>

                <Button
                  onClick={saveRequest}
                  variant="outline"
                  className="w-full border-violet-500 text-violet-400 hover:bg-violet-500/10"
                >
                  <Save className="mr-2 h-4 w-4" /> Save Request
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Right Panel */}
          <div className="lg:col-span-7">
            <Card className="bg-slate-950 border-slate-700 h-full">
              <CardHeader>
                <CardTitle className="flex items-center gap-3 text-violet-400">
                  <Send className="w-6 h-6" /> Request Body
                </CardTitle>
              </CardHeader>
              <CardContent className="p-8 space-y-6">
                {["POST", "PUT", "PATCH"].includes(method) && (
                  <Textarea
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    className="min-h-[260px] font-mono bg-slate-900 border-slate-700 resize-y"
                    placeholder="Enter JSON payload..."
                  />
                )}

                <Button
                  onClick={sendRequest}
                  disabled={isLoading || !url}
                  className="w-full h-14 text-lg bg-gradient-to-r from-blue-600 via-cyan-600 to-teal-600 hover:brightness-110 transition-all"
                >
                  {isLoading ? "Sending Request..." : "Send Request"}
                  <Play className="ml-3" />
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Response + Logs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
          <Card className="bg-slate-950 border-slate-700">
            <CardHeader><CardTitle>Response</CardTitle></CardHeader>
            <CardContent>
              {status && (
                <div className={`inline-flex items-center px-4 py-1.5 rounded-lg text-sm mb-4 ${
                  status < 300 ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"
                }`}>
                  Status: {status} — {responseTime}ms
                </div>
              )}
              <pre className="bg-black/80 border border-slate-800 p-6 h-[420px] overflow-auto font-mono text-sm rounded-xl text-slate-300">
                {response ? JSON.stringify(response, null, 2) : "Send a request to see response here..."}
              </pre>
            </CardContent>
          </Card>

          <Card className="bg-slate-950 border-slate-700">
            <CardHeader><CardTitle>Console Logs</CardTitle></CardHeader>
            <CardContent>
              <pre className="bg-black/80 border border-slate-800 p-6 h-[420px] overflow-auto font-mono text-sm text-emerald-400 rounded-xl">
                {logs.map((log, i) => (
                  <div key={i} className="py-1">{log}</div>
                ))}
              </pre>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
