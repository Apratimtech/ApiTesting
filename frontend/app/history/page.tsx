"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card, CardContent } from "@/components/ui/card";
import { Clock, User, Zap, ExternalLink, Trash2 } from "lucide-react";
import { getScans, clearScans, removeScan } from "@/lib/history"; // Make sure removeScan exists
import { useRouter } from "next/navigation";

export default function History() {
  const router = useRouter();
  const [scans, setScans] = useState<any[]>([]);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    setScans(getScans());
  }, []);

  const handleViewScan = (scan: any) => {
    localStorage.setItem("last_selected_request", JSON.stringify({
      id: scan.id,
      name: scan.url,
      method: scan.method,
      url: scan.url,
      type: "HTTP",
      risk: scan.risk
    }));
    router.push("/analyzer");
  };

  const handleDelete = (id: string) => {
    setDeletingId(id);

    setTimeout(() => {
      removeScan(id); // You'll need this function in your history lib
      setScans(prev => prev.filter(scan => scan.id !== id));
      setDeletingId(null);
    }, 400);
  };

  const handleClearAll = () => {
    if (scans.length === 0) return;
    clearScans();
    setScans([]);
  };

  return (
    <>
      <style jsx global>{`
        .history-card {
          background: rgba(15, 16, 25, 0.95);
          backdrop-filter: blur(24px);
          border: 1px solid rgba(148, 163, 184, 0.15);
          box-shadow: 0 20px 40px -15px rgb(0 0 0 / 0.5);
          transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .history-card:hover {
          transform: translateY(-6px) scale(1.02);
          box-shadow: 0 35px 70px -15px rgb(124 58 237 / 0.35);
        }
      `}</style>

      <div className="min-h-screen bg-[#0a0b12] text-white">
        <div className="max-w-6xl mx-auto px-6 py-12">

          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex justify-between items-center mb-12"
          >
            <div>
              <h1 className="text-5xl font-bold tracking-tighter">Analysis History</h1>
              <p className="text-slate-400 mt-2">Track all your security scans</p>
            </div>

            <button
              onClick={handleClearAll}
              className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 px-6 py-3 rounded-2xl transition-all"
            >
              <Trash2 size={18} />
              Clear All
            </button>
          </motion.div>

          {/* History List */}
          <div className="space-y-6">
            {scans.length === 0 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-center py-20 text-slate-400"
              >
                <Clock size={60} className="mx-auto mb-4 opacity-40" />
                <p className="text-xl">No scans yet</p>
              </motion.div>
            )}

            {scans.map((scan, index) => {
              const isDeleting = deletingId === scan.id;
              return (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, y: 40 }}
                  animate={{
                    opacity: isDeleting ? 0 : 1,
                    y: isDeleting ? 30 : 0,
                    scale: isDeleting ? 0.95 : 1
                  }}
                  transition={{ duration: 0.4 }}
                  className="relative"
                >
                  <Card
                    className="history-card cursor-pointer group"
                    onClick={() => !isDeleting && handleViewScan(scan)}
                  >
                    <CardContent className="p-8">
                      <div className="flex justify-between items-start">
                        {/* Left Info */}
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-3">
                            <div className="px-3 py-1 bg-white/10 text-xs font-mono rounded-lg">
                              {scan.method}
                            </div>
                            <div className="flex items-center gap-2 text-slate-400 text-sm">
                              <User size={16} />
                              <span>Admin</span>
                            </div>
                            <div className="flex items-center gap-2 text-slate-400 text-sm">
                              <Clock size={16} />
                              <span>{scan.time}</span>
                            </div>
                          </div>

                          <p className="text-xl font-medium text-white group-hover:text-violet-300 transition-colors break-all">
                            {scan.url}
                          </p>
                        </div>

                        {/* Risk Score */}
                        <div className="text-right">
                          <div className={`text-6xl font-bold tracking-tighter ${
                            scan.risk >= 7 ? "text-red-400" :
                            scan.risk >= 4 ? "text-yellow-400" : "text-emerald-400"
                          }`}>
                            {scan.risk}
                          </div>
                          <p className="text-sm text-slate-400">Risk Score</p>
                        </div>
                      </div>
                    </CardContent>

                    {/* Delete Button */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDelete(scan.id);
                      }}
                      className="absolute top-6 right-6 p-2 text-red-400 hover:bg-red-500/20 rounded-xl opacity-0 group-hover:opacity-100 transition-all"
                    >
                      <Trash2 size={20} />
                    </button>
                  </Card>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </>
  );
}
