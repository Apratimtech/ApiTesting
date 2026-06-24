'use client';
import React, { useState } from 'react';
import { Play, Trash2, Plus, AlertCircle, Terminal, Settings as SettingsIcon, ShieldAlert, Code2, FileText, Eye, EyeOff, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const MCPConsole = () => {
  const [mode, setMode] = useState<'STDIO' | 'HTTP'>('STDIO');
  const [isExecuting, setIsExecuting] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('Message');

  // STDIO
  const [jsonInput, setJsonInput] = useState(JSON.stringify({
    "jsonrpc": "2.0",
    "method": "trust_edge/v1/scan_protocol",
    "params": {
      "target_id": "ax-9082-pk-12",
      "depth": 5,
      "verbose": true,
      "timeout": 30000
    },
    "id": 1024
  }, null, 2));

  // HTTP
  const [httpUrl, setHttpUrl] = useState('http://localhost:3000/api/rpc');
  const [httpBody, setHttpBody] = useState(JSON.stringify({
    "jsonrpc": "2.0",
    "method": "trust_edge/v1/scan_protocol",
    "params": {
      "target_id": "ax-9082-pk-12",
      "depth": 5,
      "verbose": true
    },
    "id": Date.now()
  }, null, 2));

  const [headers, setHeaders] = useState([{ key: 'Content-Type', value: 'application/json' }]);
  const [authType, setAuthType] = useState<'none' | 'bearer' | 'basic'>('none');
  const [bearerToken, setBearerToken] = useState('');
  const [basicAuth, setBasicAuth] = useState({ username: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [timeoutMs, setTimeoutMs] = useState(30000);
  const [strictSSL, setStrictSSL] = useState(true);

  // STDIO Enhanced
  const [args, setArgs] = useState({
    target_id: "ax-9082-pk-12",
    depth: 5,
    verbose: true,
    timeout: 30000,
    scan_type: "full"
  });

  const [envVars, setEnvVars] = useState([
    { key: "MCP_LOG_LEVEL", value: "DEBUG" },
    { key: "TRUST_EDGE_API_KEY", value: "te_sk_••••••••••••••••" },
    { key: "SCAN_TIMEOUT", value: "60000" },
  ]);

  // Security
  const [securityScanResult, setSecurityScanResult] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);

  const stdioTabs = [
    { name: 'Message', icon: <Terminal size={16} /> },
    { name: 'Arguments', icon: <Code2 size={16} /> },
    { name: 'Env Vars', icon: <SettingsIcon size={16} /> },
    { name: 'Security Scanner', icon: <ShieldAlert size={16} />, alert: true },
    { name: 'Docs', icon: <FileText size={16} /> },
  ];

  const httpTabs = [
    { name: 'Message', icon: <Terminal size={16} /> },
    { name: 'Authorization', icon: null },
    { name: 'Headers', icon: null },
    { name: 'Settings', icon: <SettingsIcon size={16} /> },
    { name: 'Security Scanner', icon: <ShieldAlert size={16} />, alert: true },
    { name: 'Docs', icon: <FileText size={16} /> },
  ];

  const currentTabs = mode === 'STDIO' ? stdioTabs : httpTabs;

  const validateJson = (jsonString: string) => {
    try {
      JSON.parse(jsonString);
      return { valid: true };
    } catch (e: any) {
      return { valid: false, message: `Invalid JSON: ${e.message}` };
    }
  };

  const handleRunCommand = async () => {
    setError(null);
    setResponse(null);
    const body = mode === 'STDIO' ? jsonInput : httpBody;
    const validation = validateJson(body);
    if (!validation.valid) {
      setError(validation.message);
      return;
    }
    setIsExecuting(true);
    try {
      if (mode === 'STDIO') {
        const res = await fetch('/api/rpc', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(JSON.parse(body)),
        });
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();
        setResponse(data);
      } else {
        const headerObj: Record<string, string> = {};
        headers.forEach(h => { if (h.key?.trim()) headerObj[h.key] = h.value; });
        if (authType === 'bearer' && bearerToken) headerObj['Authorization'] = `Bearer ${bearerToken}`;
        if (authType === 'basic' && basicAuth.username) {
          const cred = btoa(`${basicAuth.username}:${basicAuth.password}`);
          headerObj['Authorization'] = `Basic ${cred}`;
        }
        const res = await fetch(httpUrl, { method: 'POST', headers: headerObj, body });
        let bodyData;
        try { bodyData = await res.json(); } catch { bodyData = await res.text(); }
        setResponse({ status: res.status, statusText: res.statusText, headers: Object.fromEntries(res.headers.entries()), body: bodyData });
      }
    } catch (err: any) {
      setError(err.message || "Request failed");
    } finally {
      setIsExecuting(false);
    }
  };

  const runSecurityScan = async () => {
    setIsScanning(true);
    setSecurityScanResult(null);
    setError(null);
    try {
      const payloadToAnalyze = mode === 'STDIO' ? jsonInput : httpBody;
      const securityRequest = {
        jsonrpc: "2.0",
        method: "trust_edge/v1/security_scan",
        params: {
          payload: JSON.parse(payloadToAnalyze),
          target_url: mode === 'HTTP' ? httpUrl : 'local-stdio',
          headers: mode === 'HTTP' ? headers : [],
          auth_type: authType,
        },
        id: Date.now()
      };
      const res = await fetch('/api/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(securityRequest),
      });
      if (!res.ok) throw new Error('Scan failed');
      const result = await res.json();
      setSecurityScanResult(result);
      setResponse(result);
    } catch (err: any) {
      setError("Security scan failed. Backend may not support this method yet.");
      setSecurityScanResult({ vulnerabilities: [{ type: "INFO", severity: "low", message: "Backend security endpoint not available" }] });
    } finally {
      setIsScanning(false);
    }
  };

  const clearRequest = () => {
    if (mode === 'STDIO') setJsonInput("");
    else setHttpBody("");
  };

  const clearResponse = () => {
    setResponse(null);
    setError(null);
    setSecurityScanResult(null);
  };

  const addHeader = () => setHeaders([...headers, { key: '', value: '' }]);
  const removeHeader = (index: number) => {
    if (headers.length > 1) setHeaders(headers.filter((_, i) => i !== index));
  };
  const updateHeader = (index: number, field: 'key' | 'value', value: string) => {
    const newHeaders = [...headers];
    newHeaders[index][field] = value;
    setHeaders(newHeaders);
  };

  const addEnvVar = () => setEnvVars([...envVars, { key: "", value: "" }]);
  const updateEnvVar = (index: number, field: 'key' | 'value', value: string) => {
    const newEnv = [...envVars];
    newEnv[index][field] = value;
    setEnvVars(newEnv);
  };
  const removeEnvVar = (index: number) => {
    if (envVars.length > 1) setEnvVars(envVars.filter((_, i) => i !== index));
  };

  const syncJsonWithArgs = () => {
    const newJson = {
      jsonrpc: "2.0",
      method: "trust_edge/v1/scan_protocol",
      params: { ...args },
      id: Date.now()
    };
    setJsonInput(JSON.stringify(newJson, null, 2));
  };

  const renderRequestContent = () => {
    // Message Tab
    if (activeTab === 'Message') {
      const isHttp = mode === 'HTTP';
      return (
        <motion.div
          key={isHttp ? "http-msg" : "stdio-msg"}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col h-full bg-[#1a1f2e] border border-gray-700 rounded-2xl overflow-hidden relative"
        >
          <div className="flex-1 p-6 min-h-0">
            <div className="text-xs uppercase tracking-widest text-gray-400 mb-3">JSON-RPC PAYLOAD</div>
            <textarea
              spellCheck="false"
              className="w-full h-full bg-transparent font-mono text-sm text-blue-300 outline-none resize-none leading-relaxed overflow-auto"
              value={isHttp ? httpBody : jsonInput}
              onChange={(e) => isHttp ? setHttpBody(e.target.value) : setJsonInput(e.target.value)}
              placeholder={`{\n "jsonrpc": "2.0",\n "method": "...",\n "params": {}\n}`}
            />
          </div>
          <motion.button
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={handleRunCommand}
            disabled={isExecuting}
            className="absolute bottom-6 right-6 px-8 py-3 bg-gradient-to-r from-blue-600 via-cyan-500 to-teal-400 rounded-2xl font-semibold flex items-center gap-3 shadow-xl disabled:opacity-60"
          >
            <Play size={18} fill="currentColor" />
            {isExecuting ? (isHttp ? 'Sending...' : 'Executing...') : (isHttp ? 'Send Request' : 'Execute Command')}
          </motion.button>
        </motion.div>
      );
    }

    // Authorization Tab
    if (activeTab === 'Authorization') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-6 h-full overflow-auto">
          <h3 className="text-lg font-semibold mb-6">Authorization</h3>
          <div className="space-y-6">
            <div className="flex gap-3">
              {(['none', 'bearer', 'basic'] as const).map(type => (
                <button
                  key={type}
                  onClick={() => setAuthType(type)}
                  className={`flex-1 py-3 rounded-xl border ${authType === type ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 hover:border-gray-600'}`}
                >
                  {type === 'none' && 'No Auth'}
                  {type === 'bearer' && 'Bearer Token'}
                  {type === 'basic' && 'Basic Auth'}
                </button>
              ))}
            </div>
            {authType === 'bearer' && (
              <input type="text" value={bearerToken} onChange={e => setBearerToken(e.target.value)} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" placeholder="Bearer token..." />
            )}
            {authType === 'basic' && (
              <div className="grid grid-cols-2 gap-4">
                <input type="text" value={basicAuth.username} onChange={e => setBasicAuth({...basicAuth, username: e.target.value})} className="bg-black border border-gray-700 rounded-xl px-4 py-3" placeholder="Username" />
                <div className="relative">
                  <input type={showPassword ? "text" : "password"} value={basicAuth.password} onChange={e => setBasicAuth({...basicAuth, password: e.target.value})} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3" placeholder="Password" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-3.5 text-gray-400">
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      );
    }

    // Headers Tab
    if (activeTab === 'Headers') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-6 h-full overflow-auto">
          <div className="flex justify-between mb-6">
            <h3 className="text-lg font-semibold">Headers</h3>
            <button onClick={addHeader} className="text-blue-400 hover:text-blue-300 flex items-center gap-1">
              <Plus size={18} /> Add
            </button>
          </div>
          <div className="space-y-4">
            {headers.map((h, i) => (
              <div key={i} className="flex gap-4 items-center group">
                <input value={h.key} onChange={e => updateHeader(i, 'key', e.target.value)} className="flex-1 bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" placeholder="Key" />
                <input value={h.value} onChange={e => updateHeader(i, 'value', e.target.value)} className="flex-1 bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" placeholder="Value" />
                <button onClick={() => removeHeader(i)} className="opacity-0 group-hover:opacity-100 text-red-400"><Trash2 size={18} /></button>
              </div>
            ))}
          </div>
        </div>
      );
    }

    // Settings Tab
    if (activeTab === 'Settings') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-6 h-full overflow-auto">
          <h3 className="text-lg font-semibold mb-6">Settings</h3>
          <div className="space-y-6">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Endpoint URL</label>
              <input type="text" value={httpUrl} onChange={e => setHttpUrl(e.target.value)} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" />
            </div>
            <div className="grid grid-cols-2 gap-6">
              <div>
                <label className="block text-sm text-gray-400 mb-2">Timeout (ms)</label>
                <input type="number" value={timeoutMs} onChange={e => setTimeoutMs(parseInt(e.target.value))} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3" />
              </div>
              <div className="flex items-center gap-3 pt-8">
                <input type="checkbox" checked={strictSSL} onChange={e => setStrictSSL(e.target.checked)} className="w-5 h-5 accent-blue-500" />
                <span>Strict SSL</span>
              </div>
            </div>
          </div>
        </div>
      );
    }

    // Security Scanner Tab
    if (activeTab === 'Security Scanner') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-6 h-full overflow-auto">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <ShieldAlert size={24} className="text-orange-400" />
              <h3 className="text-lg font-semibold">Security Scanner</h3>
            </div>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={runSecurityScan}
              disabled={isScanning}
              className="px-6 py-2.5 bg-zinc-700 hover:bg-zinc-600 rounded-2xl font-medium flex items-center gap-2 text-sm"
            >
              <ShieldAlert size={18} />
              {isScanning ? 'Scanning...' : 'Run Analysis'}
            </motion.button>
          </div>
          {securityScanResult ? (
            <div className="space-y-4">
              {securityScanResult.vulnerabilities?.map((v: any, i: number) => (
                <div key={i} className="p-4 rounded-2xl bg-black/60 border border-gray-700">
                  <div className="flex items-start gap-3">
                    {v.severity === 'high' || v.severity === 'critical' ? <XCircle className="text-red-400" /> : <AlertTriangle className="text-amber-400" />}
                    <div className="flex-1">
                      <div className="font-medium">{v.type} <span className="text-xs text-gray-500">({v.severity})</span></div>
                      <div className="text-sm text-gray-300 mt-1">{v.message}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-80 flex items-center justify-center text-gray-500 border border-dashed border-gray-700 rounded-3xl">
              Click "Run Analysis" to scan payload, URL and configuration
            </div>
          )}
        </div>
      );
    }

    // Arguments Tab
    if (activeTab === 'Arguments') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-6 h-full overflow-auto">
          <div className="flex justify-between mb-6">
            <h3 className="text-lg font-semibold">Arguments</h3>
            <button onClick={syncJsonWithArgs} className="text-blue-400 text-sm flex items-center gap-1.5">
              <Code2 size={16} /> Sync to JSON
            </button>
          </div>
          <div className="grid grid-cols-2 gap-6">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Target ID</label>
              <input value={args.target_id} onChange={e => setArgs({...args, target_id: e.target.value})} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2">Depth</label>
              <input type="number" value={args.depth} onChange={e => setArgs({...args, depth: parseInt(e.target.value)})} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2">Scan Type</label>
              <select value={args.scan_type} onChange={e => setArgs({...args, scan_type: e.target.value})} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3">
                <option value="full">Full</option>
                <option value="surface">Surface</option>
                <option value="deep">Deep</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2">Timeout (ms)</label>
              <input type="number" value={args.timeout} onChange={e => setArgs({...args, timeout: parseInt(e.target.value)})} className="w-full bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" />
            </div>
          </div>
          <div className="mt-6 flex items-center gap-3">
            <input type="checkbox" checked={args.verbose} onChange={e => setArgs({...args, verbose: e.target.checked})} className="w-5 h-5 accent-blue-500" />
            <span>Verbose Output</span>
          </div>
        </div>
      );
    }

    // Env Vars Tab
    if (activeTab === 'Env Vars') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-6 h-full overflow-auto">
          <div className="flex justify-between mb-6">
            <h3 className="text-lg font-semibold">Environment Variables</h3>
            <button onClick={addEnvVar} className="text-blue-400 flex items-center gap-1">
              <Plus size={18} /> Add
            </button>
          </div>
          <div className="space-y-4">
            {envVars.map((env, i) => (
              <div key={i} className="flex gap-4 items-center group">
                <input value={env.key} onChange={e => updateEnvVar(i, 'key', e.target.value)} className="flex-1 bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" placeholder="KEY" />
                <input value={env.value} onChange={e => updateEnvVar(i, 'value', e.target.value)} className="flex-1 bg-black border border-gray-700 rounded-xl px-4 py-3 font-mono" placeholder="value" />
                <button onClick={() => removeEnvVar(i)} className="opacity-0 group-hover:opacity-100 text-red-400"><Trash2 size={18} /></button>
              </div>
            ))}
          </div>
        </div>
      );
    }

    // Docs Tab
    if (activeTab === 'Docs') {
      return (
        <div className="bg-[#1a1f2e] border border-gray-700 rounded-2xl p-8 h-full overflow-auto">
          <h3 className="text-xl font-semibold mb-6">Trust Edge Protocol Documentation</h3>
          <div className="space-y-6 text-sm">
            <div>
              <h4 className="font-medium text-blue-400 mb-2">Main Method</h4>
              <p><code>trust_edge/v1/scan_protocol</code> — Perform protocol security scan</p>
            </div>
            <div>
              <h4 className="font-medium text-blue-400 mb-2">Security Analysis</h4>
              <p><code>trust_edge/v1/security_scan</code> — Analyzes payload and configuration for vulnerabilities</p>
            </div>
          </div>
        </div>
      );
    }

    return null;
  };

  return (
    <div className="min-h-screen bg-[#0a0b0f] text-gray-200 font-sans">
      {/* Clean Header */}
      <div className="border-b border-gray-800 bg-[#11151f] px-8 py-6">
        <div className="flex items-center justify-between">
          <h1 className="text-4xl font-bold tracking-tighter text-white">MCP Console</h1>
          <div className="text-sm text-gray-500">Protocol Scanner</div>
        </div>
      </div>

      <div className="bg-[#11151f] border-b border-gray-800 px-8 py-4">
        <div className="flex items-center gap-4">
          <select value={mode} onChange={(e) => { setMode(e.target.value as 'STDIO' | 'HTTP'); setActiveTab('Message'); }} className="bg-[#0a0b0f] border border-gray-700 rounded-2xl px-6 py-3 text-sm font-medium">
            <option value="STDIO">STDIO (Local)</option>
            <option value="HTTP">HTTP / Remote</option>
          </select>
          <div className="flex-1">
            <input type="text" placeholder="Quick command search or paste JSON-RPC payload..." className="w-full bg-black border border-gray-700 focus:border-blue-500 rounded-2xl px-6 py-3.5 text-sm outline-none" />
          </div>
          <motion.button whileHover={{ scale: 1.05 }} onClick={handleRunCommand} disabled={isExecuting} className="px-10 py-3.5 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-2xl font-semibold text-sm flex items-center gap-3 shadow-lg">
            {isExecuting ? "Executing..." : "Connect & Run"}
          </motion.button>
        </div>
      </div>

      <div className="flex h-[calc(100vh-185px)] p-6 gap-6">
        <div className="flex-1 flex flex-col bg-[#11151f] border border-gray-800 rounded-3xl overflow-hidden shadow-2xl">
          <div className="flex border-b border-gray-800 bg-[#0a0b0f] overflow-x-auto">
            {currentTabs.map(tab => (
              <motion.button
                key={tab.name}
                onClick={() => setActiveTab(tab.name)}
                className={`flex items-center gap-3 px-8 py-5 text-sm font-medium border-b-2 whitespace-nowrap ${activeTab === tab.name ? 'border-blue-500 text-white' : 'border-transparent text-gray-400 hover:text-white'}`}
              >
                {tab.icon} {tab.name}
                {tab.alert && <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />}
              </motion.button>
            ))}
            <motion.button onClick={clearRequest} className="ml-auto flex items-center gap-2 px-8 text-sm text-gray-400 hover:text-red-400">
              <Trash2 size={17} /> Clear
            </motion.button>
          </div>

          <div className="flex-1 p-6 overflow-auto">
            <AnimatePresence mode="wait">
              {renderRequestContent()}
            </AnimatePresence>
          </div>

          <div className="flex-1 flex flex-col bg-[#0a0b0f] border-t border-gray-800 min-h-0">
            <div className="px-8 py-4 border-b border-gray-700 flex justify-between bg-[#11151f]">
              <div className="uppercase tracking-[2px] text-xs font-semibold text-blue-400">RESPONSE PAYLOAD</div>
              {(response || error) && <button onClick={clearResponse}><Trash2 size={19} className="text-red-400" /></button>}
            </div>
            <div className="flex-1 p-8 overflow-auto font-mono text-sm bg-black/95">
              {error ? (
                <div className="text-red-400 flex gap-4"><AlertCircle size={32} /><div>{error}</div></div>
              ) : response ? (
                <pre className="text-emerald-400 whitespace-pre-wrap">{JSON.stringify(response, null, 2)}</pre>
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">No response yet</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MCPConsole;
