"use client";
import { Home, Zap, History, Settings, Terminal } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";

const menu = [
  { name: "Dashboard", href: "/dashboard", icon: Home },
  { name: "Analyzer", href: "/analyzer", icon: Zap },
  { name: "API Tester", href: "/api-tester", icon: Terminal }, // ✅ NEW SLOT
  { name: "History", href: "/history", icon: History },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <div className="w-72 bg-slate-950 border-r border-slate-800 h-screen flex flex-col">
      
      {/* Logo */}
      <div className="px-8 py-10 border-b border-slate-800">
        <motion.div whileHover={{ scale: 1.05 }} className="flex items-center gap-4">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center">
            🛡️
          </div>
          <h1 className="text-2xl font-bold">Trust_Edge</h1>
        </motion.div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-2">
        {menu.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link key={item.name} href={item.href}>
              <motion.div
                whileHover={{ x: 5 }}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all
                  ${
                    isActive
                      ? "bg-gradient-to-r from-blue-600 to-purple-600 text-white"
                      : "text-slate-400 hover:bg-slate-900 hover:text-white"
                  }`}
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </motion.div>
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
