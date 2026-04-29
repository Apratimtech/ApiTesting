"use client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, AlertTriangle } from "lucide-react";
import { motion } from "framer-motion";
import { useState, useEffect } from "react";

export default function Dashboard() {
  const [riskScore, setRiskScore] = useState(2.7);
  const [analysesToday, setAnalysesToday] = useState(64);
  const [criticalIssues, setCriticalIssues] = useState(2);

  // Real-time updating numbers
  useEffect(() => {
    const interval = setInterval(() => {
      setRiskScore(prev => Math.max(0.8, Math.min(9.5, parseFloat((prev + (Math.random() * 1.4 - 0.7)).toFixed(1)))));
      setAnalysesToday(prev => prev + Math.floor(Math.random() * 5) + 2);
      setCriticalIssues(prev => Math.max(0, prev + (Math.random() > 0.8 ? 1 : Math.random() > 0.95 ? -1 : 0)));
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="max-w-7xl mx-auto space-y-12"
    >
      <div>
        <h1 className="text-6xl font-bold tracking-tighter bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
          Welcome to Trust_Edge
        </h1>
        <p className="text-slate-400 text-2xl mt-4">Your API Security Command Center</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {/* Overall Risk */}
        <motion.div 
          whileHover={{ scale: 1.06, y: -12 }} 
          transition={{ type: "spring", stiffness: 300 }}
        >
          <Card className="glass neon-glow border-slate-700 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-2xl">Overall Risk</CardTitle>
            </CardHeader>
            <CardContent className="text-center pt-6">
              <div className="text-[6.5rem] font-bold text-emerald-400 tracking-tighter">{riskScore}</div>
              <p className="text-emerald-400 text-xl">LOW • Live</p>
            </CardContent>
          </Card>
        </motion.div>

        {/* Analyses Today */}
        <motion.div 
          whileHover={{ scale: 1.06, y: -12 }} 
          transition={{ type: "spring", stiffness: 300 }}
        >
          <Card className="glass neon-glow border-slate-700 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-2xl">Analyses Today</CardTitle>
            </CardHeader>
            <CardContent className="text-center pt-6">
              <div className="text-[6.5rem] font-bold text-white tracking-tighter">{analysesToday}</div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Critical Issues */}
        <motion.div 
          whileHover={{ scale: 1.06, y: -12 }} 
          transition={{ type: "spring", stiffness: 300 }}
        >
          <Card className="glass neon-glow border-slate-700 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-3 text-2xl">Critical Issues</CardTitle>
            </CardHeader>
            <CardContent className="text-center pt-6">
              <div className="text-[6.5rem] font-bold text-red-400 tracking-tighter">{criticalIssues}</div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </motion.div>
  );
}
