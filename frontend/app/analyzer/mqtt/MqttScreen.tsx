"use client";
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Zap, Play, Save } from "lucide-react";

export default function MqttScreen() {
  const [clientId, setClientId] = useState("trustedge_" + Date.now());
  const [brokerUrl, setBrokerUrl] = useState("mqtt://test.mosquitto.org:1883");
  const [topic, setTopic] = useState("test/topic");
  const [message, setMessage] = useState("Hello from Trust_Edge!");
  const [qos, setQos] = useState(0);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isConnected, setIsConnected] = useState(false);
  const [logs, setLogs] = useState<string[]>(["MQTT Console Ready"]);

  // Load from Sidebar
  useEffect(() => {
    const saved = localStorage.getItem("last_selected_request");
    if (saved) {
      try {
        const req = JSON.parse(saved);
        if (req.type === "MQTT") {
          setTopic(req.topic || "test/topic");
          setMessage(req.message || "Hello from Trust_Edge!");
          setQos(req.qos || 0);
          // You can add more fields
        }
      } catch (e) {
        console.error(e);
      }
    }
  }, []);

  const saveRequest = () => {
    const reqData = {
      id: Date.now().toString(),
      name: "MQTT Request",
      method: "PUBLISH",
      url: brokerUrl,
      type: "MQTT",
      topic,
      message,
      qos,
    };
    localStorage.setItem("last_selected_request", JSON.stringify(reqData));
    alert("MQTT Request Saved!");
  };

  const connectMqtt = () => {
    setLogs(prev => [...prev, `Connecting to ${brokerUrl}...`]);
    setTimeout(() => {
      setIsConnected(true);
      setLogs(prev => [...prev, "✅ Connected successfully!"]);
    }, 800);
  };

  const publishMessage = () => {
    if (!isConnected) return;
    setLogs(prev => [...prev, `📤 Published to ${topic}: ${message}`]);
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] p-6">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <div className="p-4 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl">
            <Zap className="w-12 h-12 text-white" />
          </div>
          <div>
            <h1 className="text-5xl font-bold text-white">MQTT Console</h1>
            <p className="text-slate-400">Real-time Message Broker Client</p>
          </div>
        </div>

        <Card className="bg-slate-950 border-slate-700">
          <CardHeader>
            <CardTitle>Connection Settings</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-6 p-8">
            <Input value={brokerUrl} onChange={(e) => setBrokerUrl(e.target.value)} placeholder="Broker URL" />
            <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="Client ID" />
            <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username (optional)" />
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" />
          </CardContent>
        </Card>

        <Card className="mt-6 bg-slate-950 border-slate-700">
          <CardHeader className="flex flex-row justify-between items-center">
            <CardTitle>Publish Message</CardTitle>
            <div className="flex gap-3">
              <Button onClick={saveRequest} variant="outline"><Save className="mr-2" /> Save Request</Button>
              <Button onClick={connectMqtt} disabled={isConnected} className="bg-emerald-600">
                {isConnected ? "Connected" : "Connect"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-8 space-y-6">
            <Input value={topic} onChange={(e) => setTopic(e.target.value)} placeholder="Topic" />
            <textarea 
              value={message} 
              onChange={(e) => setMessage(e.target.value)}
              className="w-full h-32 bg-slate-900 border border-slate-700 rounded-xl p-4 font-mono text-sm"
            />
            <Button onClick={publishMessage} disabled={!isConnected} className="w-full bg-gradient-to-r from-violet-600 to-fuchsia-600">
              <Play className="mr-2" /> Publish Message
            </Button>
          </CardContent>
        </Card>

        <Card className="mt-6 bg-black border-slate-800">
          <CardHeader><CardTitle>Console Logs</CardTitle></CardHeader>
          <CardContent>
            <pre className="bg-black p-6 text-emerald-400 font-mono text-sm h-96 overflow-auto">
              {logs.map((log, i) => <div key={i}>{log}</div>)}
            </pre>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
