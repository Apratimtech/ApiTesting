"use client";
import "./globals.css";
import { useState, useEffect } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";
import { ThemeProvider } from "next-themes";
import { motion } from "framer-motion";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    const logged = localStorage.getItem("trust_edge_logged_in");
    setIsLoggedIn(logged === "true");
  }, []);

  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
          {isLoggedIn ? (
            <div className="flex h-screen overflow-hidden bg-slate-950">
              <Sidebar />
              <div className="flex-1 flex flex-col">
                <Topbar setIsLoggedIn={setIsLoggedIn} />
                <motion.main 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6 }}
                  className="flex-1 overflow-auto p-10 bg-slate-950 dark:bg-slate-950"
                >
                  {children}
                </motion.main>
              </div>
            </div>
          ) : (
            children
          )}
        </ThemeProvider>
      </body>
    </html>
  );
}
