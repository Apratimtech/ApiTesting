"use client";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function ApiTester() {
  const [input, setInput] = useState(`{
  "request": {
    "url": "https://jsonplaceholder.typicode.com/posts/1",
    "method": "GET",
    "headers": {},
    "body": {}
  },
  "response": {}
}`);
  const [raw, setRaw] = useState("");
  const [pretty, setPretty] = useState("");

  const handleExecute = async () => {
    try {
      const parsed = JSON.parse(input);

      const res = await fetch("http://localhost:8000/api/v1/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(parsed),
      });

      const data = await res.json();

      setRaw(JSON.stringify(data));
      setPretty(JSON.stringify(data, null, 2));
    } catch (err) {
      setRaw("❌ Invalid JSON or Request Failed");
      setPretty("");
    }
  };

  return (
    <div className="max-w-7xl mx-auto p-10">
      
      <h1 className="text-5xl font-bold mb-10">⚡ API Tester</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">

        {/* LEFT PANEL */}
        <Card className="glass neon-glow border-slate-700">
          <CardContent className="p-8">
            <h2 className="text-xl mb-4">Enter Raw JSON</h2>

            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="w-full h-80 bg-black text-green-400 p-4 rounded-xl font-mono"
            />

            <Button
              onClick={handleExecute}
              className="mt-6 w-full bg-green-600 hover:bg-green-700"
            >
              Execute Request
            </Button>
          </CardContent>
        </Card>

        {/* RIGHT PANEL */}
        <div className="space-y-8">

          <Card className="glass border-slate-700">
            <CardContent className="p-6">
              <h2 className="text-lg mb-2">Raw Response</h2>
              <pre className="bg-black text-green-400 p-4 rounded-xl overflow-auto">
                {raw}
              </pre>
            </CardContent>
          </Card>

          <Card className="glass border-slate-700">
            <CardContent className="p-6">
              <h2 className="text-lg mb-2">Pretty Response</h2>
              <pre className="bg-slate-900 p-4 rounded-xl overflow-auto">
                {pretty}
              </pre>
            </CardContent>
          </Card>

        </div>
      </div>
    </div>
  );
}
