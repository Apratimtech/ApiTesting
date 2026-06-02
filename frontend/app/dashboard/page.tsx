"use client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Zap, AlertTriangle, Activity } from "lucide-react";
import { motion } from "framer-motion";
import { useState, useEffect } from "react";

export default function Dashboard() {
  const [riskScore, setRiskScore] = useState(2.3);
  const [analysesToday, setAnalysesToday] = useState(142);
  const [criticalIssues, setCriticalIssues] = useState(2);
  const [liveRequests, setLiveRequests] = useState(4580);

  useEffect(() => {
    const interval = setInterval(() => {
      setRiskScore(prev => Math.max(0.5, Math.min(7.5, parseFloat((prev + (Math.random() * 0.4 - 0.2)).toFixed(1)))));
      setAnalysesToday(prev => prev + Math.floor(Math.random() * 3) + 1);
      setCriticalIssues(prev => Math.max(0, prev + (Math.random() > 0.95 ? 1 : 0)));
      setLiveRequests(prev => prev + Math.floor(Math.random() * 18) + 5);
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <>
      <style jsx global>{`
        .glass-card {
          background: rgba(15, 16, 25, 0.95);
          backdrop-filter: blur(24px);
          border: 1px solid rgba(148, 163, 184, 0.15);
          box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.6);
          transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
          position: relative;
          overflow: hidden;
        }

        .glass-card:hover {
          transform: translateY(-10px) scale(1.03);
          box-shadow: 0 40px 80px -15px rgb(124 58 237 / 0.4);
        }

        /* Big Visible Hanging Rope */
        .rope {
          position: absolute;
          top: -55px;
          left: 50%;
          width: 5px;
          height: 58px;
          background: linear-gradient(#64748b, #475569);
          transform: translateX(-50%);
          z-index: 10;
          border-radius: 3px;
        }

        .rope::after {
          content: '';
          position: absolute;
          top: 100%;
          left: 50%;
          width: 22px;
          height: 22px;
          background: #334155;
          border-radius: 50%;
          transform: translateX(-50%);
          border: 3px solid #64748b;
        }
      `}</style>

      <div className="min-h-screen bg-[#0a0b12] text-white">
        <div className="max-w-7xl mx-auto px-6 py-12">
          
          {/* Title with Beautiful Hover Effect */}
          <motion.div className="mb-16 text-center">
            <motion.h1 
              className="text-7xl font-bold tracking-tighter cursor-pointer"
              whileHover={{ 
                scale: 1.08, 
                color: "#c4b5fd",
                textShadow: "0 0 30px rgba(167, 139, 250, 0.8)"
              }}
              transition={{ duration: 0.4 }}
              style={{
                background: "linear-gradient(90deg, #a5b4fc, #c4b5fd, #e0bbff, #a5b4fc)",
                backgroundSize: "200% 100%",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent"
              }}
            >
              Welcome to Trust_Edge
            </motion.h1>
          </motion.div>

          {/* Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            
            {/* Card 1 */}
            <motion.div
              initial={{ y: -300, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.7, type: "spring", stiffness: 45, damping: 12 }}
            >
              <div className="rope" />
              <Card className="glass-card h-full group">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3">
                    <Shield className="text-emerald-400" size={28} />
                    Overall Risk
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-center pt-2">
                  <div className="text-[5.5rem] font-bold text-emerald-400 tracking-tighter">
                    {riskScore}
                  </div>
                  <p className="text-emerald-400 text-xl">LOW • LIVE</p>
                </CardContent>
              </Card>
            </motion.div>

            {/* Card 2 */}
            <motion.div
              initial={{ y: -300, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.1, type: "spring", stiffness: 45, damping: 12 }}
            >
              <div className="rope" />
              <Card className="glass-card h-full group">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3">
                    <Zap className="text-blue-400" size={28} />
                    Analyses Today
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-center pt-2">
                  <div className="text-[5.5rem] font-bold tracking-tighter text-white">
                    {analysesToday}
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            {/* Card 3 */}
            <motion.div
              initial={{ y: -300, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.9, delay: 0.2, type: "spring", stiffness: 45, damping: 12 }}
            >
              <div className="rope" />
              <Card className="glass-card h-full group">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3">
                    <AlertTriangle className="text-red-400" size={28} />
                    Critical Issues
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-center pt-2">
                  <div className="text-[5.5rem] font-bold text-red-400 tracking-tighter">
                    {criticalIssues}
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            {/* Card 4 */}
            <motion.div
              initial={{ y: -300, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 1.0, delay: 0.3, type: "spring", stiffness: 45, damping: 12 }}
            >
              <div className="rope" />
              <Card className="glass-card h-full group">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3">
                    <Activity className="text-purple-400" size={28} />
                    Live Requests
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-center pt-2">
                  <div className="text-[5.5rem] font-bold text-purple-400 tracking-tighter">
                    {liveRequests.toLocaleString()}
                  </div>
                  <p className="text-purple-400">per minute</p>
                </CardContent>
              </Card>
            </motion.div>

          </div>
        </div>
      </div>
    </>
  );
}
