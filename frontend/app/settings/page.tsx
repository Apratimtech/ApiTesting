"use client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useTheme } from "next-themes";
import { motion } from "framer-motion";
import { useEffect, useState } from "react";

export default function Settings() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Fix hydration error
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="min-h-screen" />; // Prevents mismatch
  }

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-4xl mx-auto"
    >
      <h1 className="text-5xl font-bold tracking-tighter mb-12">Settings</h1>

      <Card className="glass neon-glow border-slate-700">
        <CardHeader>
          <CardTitle className="text-3xl">Appearance</CardTitle>
        </CardHeader>
        <CardContent className="p-10 space-y-12">
          
          {/* Theme Selection */}
          <div>
            <Label className="text-xl mb-6 block">Theme Mode</Label>
            <div className="grid grid-cols-2 gap-6">
              <button 
                onClick={() => setTheme("dark")}
                className={`p-8 rounded-3xl text-xl font-medium transition-all border ${theme === "dark" 
                  ? "border-blue-500 bg-slate-900 shadow-lg" 
                  : "border-slate-700 hover:bg-slate-900"}`}
              >
                🌙 Dark Mode
              </button>

              <button 
                onClick={() => setTheme("light")}
                className={`p-8 rounded-3xl text-xl font-medium transition-all border ${theme === "light" 
                  ? "border-blue-500 bg-white text-black shadow-lg" 
                  : "border-slate-700 hover:bg-slate-900"}`}
              >
                ☀️ Light Mode
              </button>
            </div>
          </div>

          {/* Font Family */}
          <div>
            <Label className="text-xl mb-6 block">Font Family</Label>
            <Select defaultValue="inter">
              <SelectTrigger className="h-14 text-lg">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="inter">Inter (Recommended)</SelectItem>
                <SelectItem value="system">System Default</SelectItem>
                <SelectItem value="sans">Sans Serif</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="pt-8 text-sm text-slate-400 border-t border-slate-700">
            More customization options coming soon.
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
