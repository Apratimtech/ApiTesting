"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Shield, Mail, Lock, User, Phone, ArrowRight, Key } from "lucide-react";

type TabType = "login" | "register" | "forgot";

export default function AuthPage() {
  const [tab, setTab] = useState<TabType>("login");

  const [formData, setFormData] = useState({
    username: "",
    name: "",
    email: "",
    phone: "",
    password: "",
  });

  const [otpSent, setOtpSent] = useState(false);
  const [otp, setOtp] = useState("");
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const checkPasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength += 25;
    if (password.length >= 12) strength += 20;
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[a-z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[^A-Za-z0-9]/.test(password)) strength += 10;
    setPasswordStrength(strength);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (name === "password") checkPasswordStrength(value);
    if (errors[name]) setErrors(prev => ({ ...prev, [name]: "" }));
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (tab === "register") {
      if (!formData.username.trim()) newErrors.username = "Username is required";
      if (!formData.name.trim()) newErrors.name = "Full name is required";
      if (!formData.phone.trim()) newErrors.phone = "Phone number is required";
    }

    if (!formData.email.trim()) newErrors.email = "Email is required";
    else if (!/\S+@\S+\.\S+/.test(formData.email)) newErrors.email = "Invalid email";

    if (tab !== "forgot" && !formData.password) newErrors.password = "Password is required";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setIsSubmitting(true);
    setMessage(null);

    try {
      if (tab === "forgot") {
        const res = await fetch("http://localhost:8000/api/v1/auth/forgot-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: formData.email, phone: formData.phone || undefined }),
        });

        const data = await res.json();

        if (res.ok) {
          setOtpSent(true);
          setMessage({ text: data.message || "OTP sent successfully", type: "success" });
        } else {
          setMessage({ text: data.detail || "Failed to send OTP", type: "error" });
        }
      } else {
        // Demo Login / Register
        localStorage.setItem("trust_edge_logged_in", "true");
        window.location.href = "/analyzer";   // Changed to /analyzer as per your current page
      }
    } catch (err) {
      setMessage({ text: "Network error. Please check if backend is running.", type: "error" });
    }

    setIsSubmitting(false);
  };

  const verifyOTP = async () => {
    if (!otp || otp.length !== 6) {
      setErrors({ otp: "Please enter 6-digit OTP" });
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: formData.email, otp }),
      });

      const data = await res.json();

      if (res.ok) {
        setMessage({ text: "OTP Verified! You can now reset your password.", type: "success" });
        setTimeout(() => {
          setTab("login");
          setOtpSent(false);
          setOtp("");
        }, 2000);
      } else {
        setMessage({ text: data.detail || "Invalid OTP", type: "error" });
      }
    } catch (err) {
      setMessage({ text: "Verification failed", type: "error" });
    }
    setIsSubmitting(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-zinc-950 flex items-center justify-center p-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="flex justify-center mb-4">
            <div className="p-4 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-3xl shadow-2xl shadow-violet-500/50">
              <Shield className="w-12 h-12 text-white" />
            </div>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-white">Trust_Edge</h1>
          <p className="text-slate-400 mt-1">Enterprise API Security Intelligence</p>
        </div>

        {/* Tabs */}
        <div className="flex bg-zinc-900 p-1 rounded-3xl mb-8 border border-zinc-700">
          {(["login", "register", "forgot"] as const).map((t) => (
            <button
              key={t}
              onClick={() => { setTab(t); setOtpSent(false); setMessage(null); }}
              className={`flex-1 py-3.5 rounded-3xl text-sm font-medium transition-all ${
                tab === t 
                  ? "bg-white text-black shadow-lg" 
                  : "text-slate-400 hover:text-white"
              }`}
            >
              {t === "login" ? "Sign In" : t === "register" ? "Register" : "Forgot Password"}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {(tab === "login" || tab === "register") && (
            <>
              {tab === "register" && (
                <>
                  <div>
                    <label className="text-xs text-slate-400 mb-1.5 block">Username</label>
                    <div className="relative">
                      <User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                      <input
                        type="text"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        className="w-full pl-11 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 focus:ring-1 focus:ring-violet-500 outline-none"
                        placeholder="Enter username"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 mb-1.5 block">Full Name</label>
                    <div className="relative">
                      <User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                      <input
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                        className="w-full pl-11 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 focus:ring-1 focus:ring-violet-500 outline-none"
                        placeholder="Enter full name"
                      />
                    </div>
                  </div>
                </>
              )}

              <div>
                <label className="text-xs text-slate-400 mb-1.5 block">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    className="w-full pl-11 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 focus:ring-1 focus:ring-violet-500 outline-none"
                    placeholder="official@trustedge.gov.in"
                  />
                </div>
                {errors.email && <p className="text-red-400 text-xs mt-1">{errors.email}</p>}
              </div>

              {tab === "register" && (
                <div>
                  <label className="text-xs text-slate-400 mb-1.5 block">Phone Number</label>
                  <div className="relative">
                    <Phone className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                    <input
                      type="tel"
                      name="phone"
                      value={formData.phone}
                      onChange={handleChange}
                      className="w-full pl-11 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 focus:ring-1 focus:ring-violet-500 outline-none"
                      placeholder="+91 9876543210"
                    />
                  </div>
                </div>
              )}

              <div>
                <label className="text-xs text-slate-400 mb-1.5 block">Password</label>
                <div className="relative">
                  <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    className="w-full pl-11 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 focus:ring-1 focus:ring-violet-500 outline-none"
                    placeholder="••••••••"
                  />
                </div>
                {tab === "register" && formData.password && (
                  <div className="mt-2 h-1 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all ${
                        passwordStrength >= 80 ? "bg-green-500" : passwordStrength >= 50 ? "bg-yellow-500" : "bg-red-500"
                      }`}
                      style={{ width: `${passwordStrength}%` }}
                    />
                  </div>
                )}
                {errors.password && <p className="text-red-400 text-xs mt-1">{errors.password}</p>}
              </div>

              {tab === "login" && (
                <div className="text-right">
                  <button
                    type="button"
                    onClick={() => setTab("forgot")}
                    className="text-violet-400 hover:text-violet-300 text-sm"
                  >
                    Forgot Password?
                  </button>
                </div>
              )}
            </>
          )}

          {/* Forgot Password Section */}
          {tab === "forgot" && (
            <div className="space-y-6">
              <div>
                <label className="text-xs text-slate-400 mb-1.5 block">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    className="w-full pl-11 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 focus:ring-1 focus:ring-violet-500 outline-none"
                  />
                </div>
              </div>

              {otpSent && (
                <div>
                  <label className="text-xs text-slate-400 mb-1.5 block">Enter OTP</label>
                  <input
                    type="text"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    className="w-full pl-4 pr-4 py-3 bg-zinc-900 border border-zinc-700 rounded-2xl focus:border-violet-500 text-center tracking-widest text-lg"
                    placeholder="123456"
                  />
                </div>
              )}
            </div>
          )}

          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            type="submit"
            disabled={isSubmitting}
            onClick={tab === "forgot" && otpSent ? verifyOTP : undefined}
            className="w-full py-4 bg-gradient-to-r from-violet-600 to-indigo-600 rounded-2xl font-semibold text-lg shadow-lg shadow-violet-500/30 hover:shadow-violet-500/50 transition-all flex items-center justify-center gap-2"
          >
            {isSubmitting ? "Processing..." : 
              tab === "forgot" && otpSent ? "Verify OTP" :
              tab === "forgot" ? "Send OTP" :
              tab === "login" ? "Sign In Securely" : "Create Account"}
            <ArrowRight className="w-5 h-5" />
          </motion.button>
        </form>

        {message && (
          <p className={`text-center mt-6 text-sm ${message.type === "success" ? "text-emerald-400" : "text-red-400"}`}>
            {message.text}
          </p>
        )}
      </motion.div>
    </div>
  );
}
