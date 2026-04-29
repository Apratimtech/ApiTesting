"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Shield, Mail, Lock, UserPlus, ArrowRight, Phone, User, Key } from "lucide-react";

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
  const [message, setMessage] = useState("");

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

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (tab === "register") {
      if (!formData.username) newErrors.username = "Username is required";
      if (!formData.name) newErrors.name = "Full name is required";
      if (!formData.phone) newErrors.phone = "Phone number is required";
    }

    if (!formData.email) newErrors.email = "Email is required";
    if (!formData.password && tab !== "forgot") newErrors.password = "Password is required";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setIsSubmitting(true);
    setMessage("");

    await new Promise(res => setTimeout(res, 1000));

    if (tab === "forgot") {
      setOtpSent(true);
      setMessage("OTP sent successfully to your email and registered phone number");
    } else {
      localStorage.setItem("trust_edge_logged_in", "true");
      window.location.href = "/dashboard";
    }

    setIsSubmitting(false);
  };

  const verifyOTP = async () => {
    if (!otp) return setErrors({ otp: "Please enter OTP" });

    setIsSubmitting(true);
    await new Promise(res => setTimeout(res, 800));
    setMessage("Password reset successful. You can now login with new password.");
    
    setTimeout(() => {
      setTab("login");
      setOtpSent(false);
      setOtp("");
      setMessage("");
      setFormData(prev => ({ ...prev, password: "" }));
    }, 1800);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-zinc-950 text-white overflow-hidden relative">
      {/* Subtle Background Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(at_40%_20%,rgba(167,139,250,0.12),transparent_50%)]" />

      <div className="relative min-h-screen flex items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-lg"
        >
          {/* Logo Header with 3D Effect */}
          <div className="flex flex-col items-center mb-10">
            <motion.div 
              whileHover={{ rotateY: 15, rotateX: 10 }}
              className="p-5 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-3xl shadow-2xl shadow-violet-500/40 border border-white/10 mb-6 transition-all hover:shadow-violet-500/60"
            >
              <Shield className="w-14 h-14 text-white drop-shadow-lg" />
            </motion.div>
            <h1 className="text-5xl font-bold tracking-tighter bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
              Trust_Edge
            </h1>
            <p className="text-slate-400 mt-2 text-lg tracking-wide">Enterprise API Security Intelligence</p>
          </div>

          {/* Tab Switcher */}
          <div className="flex bg-zinc-900/80 backdrop-blur-2xl p-1.5 rounded-3xl mb-10 border border-white/5 shadow-inner">
            {(["login", "register"] as const).map((t) => (
              <button
                key={t}
                onClick={() => { setTab(t); setOtpSent(false); }}
                className={`flex-1 py-4 rounded-3xl font-semibold text-lg transition-all duration-300 ${
                  tab === t 
                    ? "bg-white text-black shadow-xl shadow-white/20" 
                    : "text-slate-400 hover:text-white hover:bg-white/5"
                }`}
              >
                {t === "login" ? "Sign In" : "Create Account"}
              </button>
            ))}
            <button
              onClick={() => { setTab("forgot"); setOtpSent(false); }}
              className={`flex-1 py-4 rounded-3xl font-semibold text-lg transition-all duration-300 ${
                tab === "forgot" 
                  ? "bg-white text-black shadow-xl shadow-white/20" 
                  : "text-slate-400 hover:text-white hover:bg-white/5"
              }`}
            >
              Forgot Password
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Login & Register Fields */}
            {(tab === "login" || tab === "register") && (
              <>
                {tab === "register" && (
                  <>
                    <div>
                      <label className="text-sm text-slate-400 mb-2 block">Username</label>
                      <div className="relative group">
                        <User className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                        <input
                          type="text"
                          name="username"
                          placeholder="Enter username"
                          value={formData.username}
                          onChange={handleChange}
                          className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg placeholder:text-slate-500"
                        />
                      </div>
                      {errors.username && <p className="text-red-400 text-sm mt-1.5">{errors.username}</p>}
                    </div>

                    <div>
                      <label className="text-sm text-slate-400 mb-2 block">Full Name</label>
                      <div className="relative group">
                        <UserPlus className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                        <input
                          type="text"
                          name="name"
                          placeholder="Enter your full name"
                          value={formData.name}
                          onChange={handleChange}
                          className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg placeholder:text-slate-500"
                        />
                      </div>
                      {errors.name && <p className="text-red-400 text-sm mt-1.5">{errors.name}</p>}
                    </div>
                  </>
                )}

                {/* Email Field - Clean without placeholder text */}
                <div>
                  <label className="text-sm text-slate-400 mb-2 block">Email Address</label>
                  <div className="relative group">
                    <Mail className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg"
                    />
                  </div>
                  {errors.email && <p className="text-red-400 text-sm mt-1.5">{errors.email}</p>}
                </div>

                {tab === "register" && (
                  <div>
                    <label className="text-sm text-slate-400 mb-2 block">Phone Number</label>
                    <div className="relative group">
                      <Phone className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                      <input
                        type="tel"
                        name="phone"
                        placeholder="+91 98765 43210"
                        value={formData.phone}
                        onChange={handleChange}
                        className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg placeholder:text-slate-500"
                      />
                    </div>
                    {errors.phone && <p className="text-red-400 text-sm mt-1.5">{errors.phone}</p>}
                  </div>
                )}

                {/* Password Field */}
                <div>
                  <label className="text-sm text-slate-400 mb-2 block">Password</label>
                  <div className="relative group">
                    <Lock className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                    <input
                      type="password"
                      name="password"
                      placeholder="••••••••"
                      value={formData.password}
                      onChange={handleChange}
                      className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg"
                    />
                  </div>

                  {tab === "register" && formData.password && (
                    <div className="mt-3 px-1">
                      <div className="h-1 bg-zinc-800 rounded-full overflow-hidden">
                        <motion.div
                          className={`h-full transition-all duration-500 ${
                            passwordStrength >= 80 ? "bg-emerald-500" : passwordStrength >= 50 ? "bg-amber-500" : "bg-red-500"
                          }`}
                          initial={{ width: 0 }}
                          animate={{ width: `${passwordStrength}%` }}
                        />
                      </div>
                    </div>
                  )}
                  {errors.password && <p className="text-red-400 text-sm mt-1.5">{errors.password}</p>}
                </div>

                {/* Forgot Password Link - Only in Login Tab */}
                {tab === "login" && (
                  <div className="text-right">
                    <button
                      type="button"
                      onClick={() => setTab("forgot")}
                      className="text-violet-400 hover:text-violet-300 text-sm font-medium transition-colors hover:underline"
                    >
                      Forgot Password?
                    </button>
                  </div>
                )}
              </>
            )}

            {/* Forgot Password OTP Section */}
            {tab === "forgot" && (
              <div className="space-y-6 pt-4">
                <div>
                  <label className="text-sm text-slate-400 mb-2 block">Email Address</label>
                  <div className="relative group">
                    <Mail className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg"
                    />
                  </div>
                </div>

                {otpSent && (
                  <div>
                    <label className="text-sm text-slate-400 mb-2 block">Enter OTP</label>
                    <div className="relative group">
                      <Key className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400 group-hover:text-violet-400 transition-colors" />
                      <input
                        type="text"
                        placeholder="6-digit OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        maxLength={6}
                        className="w-full pl-14 pr-7 py-6 bg-zinc-900/80 border border-zinc-700 rounded-3xl focus:border-violet-500 focus:ring-2 focus:ring-violet-500/30 transition-all text-lg tracking-widest"
                      />
                    </div>
                    {errors.otp && <p className="text-red-400 text-sm mt-1.5">{errors.otp}</p>}
                  </div>
                )}
              </div>
            )}

            {/* Glowing Submit Button */}
            <motion.button
              whileHover={{ scale: 1.03, boxShadow: "0 0 30px rgba(167, 139, 250, 0.5)" }}
              whileTap={{ scale: 0.97 }}
              type="submit"
              disabled={isSubmitting}
              onClick={tab === "forgot" && otpSent ? verifyOTP : undefined}
              className="w-full py-6 bg-gradient-to-r from-violet-600 via-indigo-600 to-violet-600 rounded-3xl font-semibold text-lg flex items-center justify-center gap-3 shadow-2xl shadow-violet-500/40 hover:shadow-violet-500/60 transition-all duration-300 relative overflow-hidden group"
            >
              <span className="relative z-10">
                {isSubmitting 
                  ? "Processing..." 
                  : tab === "login" 
                    ? "Sign In Securely" 
                    : tab === "register" 
                      ? "Create Secure Account" 
                      : otpSent 
                        ? "Verify OTP" 
                        : "Send OTP to Email & Phone"}
              </span>
              {!isSubmitting && <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />}
            </motion.button>
          </form>

          {message && (
            <motion.p 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center text-emerald-400 text-sm mt-8 font-medium"
            >
              {message}
            </motion.p>
          )}
        </motion.div>
      </div>
    </div>
  );
}
