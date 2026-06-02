"use client";

import { motion } from "framer-motion";

export default function MainWrapper({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <motion.main
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="flex-1 overflow-auto p-6 bg-[#020617]"
    >
      {children}
    </motion.main>
  );
}
