"use client";
import { Sun, Moon, LogOut } from "lucide-react";
import { motion } from "framer-motion";
import { useTheme } from "next-themes";

export default function Topbar({ setIsLoggedIn }: { setIsLoggedIn: (value: boolean) => void }) {
  const { theme, setTheme } = useTheme();

  const handleLogout = () => {
    localStorage.removeItem("trust_edge_logged_in");
    setIsLoggedIn(false);
    window.location.href = "/";
  };

  return (
    <div className="h-20 glass border-b border-slate-700/50 px-10 flex items-center justify-between backdrop-blur-2xl">
      <div className="text-3xl font-semibold tracking-tight text-white">Trust_Edge</div>

      <div className="flex items-center gap-6">
        {/* Theme Toggle */}
        <motion.button
          whileHover={{ scale: 1.15, rotate: 20 }}
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          className="p-4 rounded-2xl hover:bg-slate-800 transition-all"
        >
          {theme === "dark" ? (
            <Sun className="w-6 h-6 text-yellow-400" />
          ) : (
            <Moon className="w-6 h-6" />
          )}
        </motion.button>

        {/* Logout Button */}
        <motion.button
          whileHover={{ scale: 1.08 }}
          whileTap={{ scale: 0.95 }}
          onClick={handleLogout}
          className="flex items-center gap-3 px-8 py-4 bg-red-600 hover:bg-red-700 rounded-3xl text-white font-medium transition-all button-hover"
        >
          <LogOut className="w-5 h-5" />
          Logout
        </motion.button>
      </div>
    </div>
  );
}
