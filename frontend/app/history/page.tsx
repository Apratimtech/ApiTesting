"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card, CardContent } from "@/components/ui/card";
import { getScans, clearScans } from "@/lib/history";

export default function History() {
  const [scans, setScans] = useState<any[]>([]);

  useEffect(() => {
    setScans(getScans());
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="max-w-5xl mx-auto"
    >
      <div className="flex justify-between items-center mb-10">
        <h1 className="text-5xl font-bold tracking-tighter">
          Analysis History
        </h1>

        <button
          onClick={() => {
            clearScans();
            setScans([]);
          }}
          className="bg-red-500/20 text-red-400 px-6 py-2 rounded-xl hover:bg-red-500/30 transition"
        >
          Clear
        </button>
      </div>

      <div className="space-y-6">
        {scans.length === 0 && (
          <p className="text-slate-400 text-center">
            No scans yet
          </p>
        )}

        {scans.map((scan) => (
          <Card key={scan.id} className="glass neon-glow">
            <CardContent className="p-8">
              <div className="flex justify-between items-center">

                {/* LEFT */}
                <div>
                  <p className="text-xl font-medium truncate max-w-[400px]">
                    {scan.url}
                  </p>
                  <p className="text-slate-400">
                    {scan.method} • {scan.time}
                  </p>
                </div>

                {/* RIGHT */}
                <div className="text-right">
                  <span
                    className={`text-4xl font-bold ${
                      scan.risk >= 7
                        ? "text-red-400"
                        : scan.risk >= 4
                        ? "text-yellow-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {scan.risk}
                  </span>
                  <p className="text-sm">Risk Score</p>
                </div>

              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </motion.div>
  );
}
