"use client";
import { useEffect, useState, useCallback } from "react";
import {
  Zap, Home, History, Settings, Plus, Trash2,
  ChevronDown, ChevronRight, FolderOpen, FileText
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

type BodyType =
  | "none"
  | "json"
  | "raw"
  | "form-data"
  | "x-www-form-urlencoded"
  | "graphql"
  | "html"
  | "javascript";

type RequestItem = {
  id: string;
  name: string;
  method: string;
  url: string;
  type: string;
  // Common fields
  authType?: "no-auth" | "bearer" | "basic" | "api-key" | "jwt";
  bearer?: string;
  basicUser?: string;
  basicPass?: string;
  apiKey?: string;
  headers?: Array<{ key: string; value: string }>;
  bodyType?: BodyType;
  body?: string;
  graphqlVariables?: string;
  // MQTT specific
  topic?: string;
  message?: string;
  qos?: number;
  // gRPC specific
  serverUrl?: string;
  serviceName?: string;
  methodName?: string;
  payload?: string;
  metadata?: Array<{ key: string; value: string }>;
};

type Collection = {
  id: number;
  name: string;
  requests: RequestItem[];
  collections: Collection[];
  isOpen: boolean;
};

const PROTOCOLS = [
  { name: "HTTP", icon: "🌐", color: "#60a5fa", defaultMethod: "GET", route: "/analyzer/http" },
  { name: "GraphQL", icon: "⚡", color: "#f472b6", defaultMethod: "POST", route: "/analyzer/graphql" },
  { name: "WebSocket", icon: "🔌", color: "#34d399", defaultMethod: "GET", route: "/analyzer/websocket" },
  { name: "gRPC", icon: "🔄", color: "#22d3ee", defaultMethod: "POST", route: "/analyzer/grpc" },
  { name: "MQTT", icon: "📡", color: "#a78bfa", defaultMethod: "PUBLISH", route: "/analyzer/mqtt" },
  { name: "Socket.IO", icon: "⚡", color: "#fb923c", defaultMethod: "EMIT", route: "/analyzer/socketio" },
  { name: "AI", icon: "🤖", color: "#c084fc", defaultMethod: "POST", route: "/analyzer/ai" },
  { name: "MCP", icon: "🔧", color: "#fbbf24", defaultMethod: "POST", route: "/analyzer/mcp" },
];

export default function Sidebar() {
  const router = useRouter();

  const [collections, setCollections] = useState<Collection[]>([]);
  const [editingId, setEditingId] = useState<string | number | null>(null);
  const [editingName, setEditingName] = useState("");
  const [showNewModal, setShowNewModal] = useState(false);
  const [currentParentId, setCurrentParentId] = useState<number | null>(null);
  const [isCreatingFolder, setIsCreatingFolder] = useState(false);
  const [newName, setNewName] = useState("");
  const [selectedProtocol, setSelectedProtocol] = useState("HTTP");
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<{ id: number | string; isFolder: boolean; name: string } | null>(null);
  const [deletingId, setDeletingId] = useState<string | number | null>(null);

  // Load collections from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem("trustedge_collections");
      if (saved) {
        setCollections(JSON.parse(saved));
      } else {
        const defaults: Collection[] = [{
          id: 1,
          name: "My Collection",
          requests: [],
          collections: [],
          isOpen: true
        }];
        setCollections(defaults);
        localStorage.setItem("trustedge_collections", JSON.stringify(defaults));
      }
    } catch (error) {
      console.error("Failed to load collections:", error);
      const defaults: Collection[] = [{
        id: 1,
        name: "My Collection",
        requests: [],
        collections: [],
        isOpen: true
      }];
      setCollections(defaults);
      localStorage.setItem("trustedge_collections", JSON.stringify(defaults));
    }
  }, []);

  const saveCollections = useCallback((updated: Collection[]) => {
    try {
      setCollections(updated);
      localStorage.setItem("trustedge_collections", JSON.stringify(updated));
    } catch (error) {
      console.error("Failed to save collections:", error);
    }
  }, []);

  const toggleFolder = useCallback((id: number) => {
    const update = (cols: Collection[]): Collection[] =>
      cols.map(col =>
        col.id === id
          ? { ...col, isOpen: !col.isOpen }
          : { ...col, collections: update(col.collections || []) }
      );
    saveCollections(update(collections));
  }, [collections, saveCollections]);

  const openNewModal = useCallback((parentId: number | null, isFolder: boolean) => {
    setCurrentParentId(parentId);
    setIsCreatingFolder(isFolder);
    setNewName("");
    setSelectedProtocol("HTTP");
    setShowNewModal(true);
  }, []);

  const createNewItem = useCallback(() => {
    const trimmedName = newName.trim();
    if (!trimmedName) return;

    if (isCreatingFolder) {
      const newFolder: Collection = {
        id: Date.now(),
        name: trimmedName,
        requests: [],
        collections: [],
        isOpen: true
      };

      const updateFn = (cols: Collection[]): Collection[] =>
        cols.map(col =>
          col.id === currentParentId
            ? { ...col, collections: [...(col.collections || []), newFolder] }
            : { ...col, collections: updateFn(col.collections || []) }
        );

      saveCollections(currentParentId === null ? [...collections, newFolder] : updateFn(collections));
    } else {
      const protocol = PROTOCOLS.find(p => p.name === selectedProtocol)!;

      const newReq: RequestItem = {
        id: Date.now().toString(),
        name: trimmedName,
        method: protocol.defaultMethod,
        url: selectedProtocol === "HTTP" ? "https://httpbin.org/get" : "",
        type: selectedProtocol,
        // gRPC defaults
        serverUrl: selectedProtocol === "gRPC" ? "grpc://localhost:50051" : undefined,
        serviceName: selectedProtocol === "gRPC" ? "user.UserService" : undefined,
        methodName: selectedProtocol === "gRPC" ? "CreateUser" : undefined,
        payload: selectedProtocol === "gRPC" ? `{\n  "name": "John Doe",\n  "email": "john@example.com"\n}` : undefined,
        // MQTT defaults
        topic: selectedProtocol === "MQTT" ? "test/topic" : undefined,
        message: selectedProtocol === "MQTT" ? "Hello from Trust_Edge" : undefined,
        qos: selectedProtocol === "MQTT" ? 1 : undefined,
        // Common defaults
        headers: [{ key: "Content-Type", value: "application/json" }],
        bodyType: "json",
        body: `{\n  "username": "admin",\n  "password": "123456"\n}`,
      };

      const updateFn = (cols: Collection[]): Collection[] =>
        cols.map(col =>
          col.id === currentParentId
            ? { ...col, requests: [...col.requests, newReq] }
            : { ...col, collections: updateFn(col.collections || []) }
        );

      saveCollections(updateFn(collections));
    }

    setShowNewModal(false);
    setNewName("");
  }, [newName, isCreatingFolder, currentParentId, selectedProtocol, collections, saveCollections]);

  // Fixed handleRequestClick - Supports all protocols
  const handleRequestClick = useCallback((req: RequestItem) => {
    try {
      localStorage.setItem("last_selected_request", JSON.stringify(req));

      let route = "/analyzer";

      switch (req.type) {
        case "HTTP":
          route = "/analyzer/http";
          break;
        case "MQTT":
          route = "/analyzer/mqtt";
          break;
        case "gRPC":
          route = "/analyzer/grpc";
          break;
        case "WebSocket":
          route = "/analyzer/websocket";
          break;
        case "Socket.IO":
          route = "/analyzer/socketio";
          break;
        case "GraphQL":
          route = "/analyzer/graphql";
          break;
        case "AI":
          route = "/analyzer/ai";
          break;
        case "MCP":
          route = "/analyzer/mcp";
          break;
        default:
          route = "/analyzer";
      }

      router.push(route);
    } catch (error) {
      console.error("Failed to open request:", error);
      router.push("/analyzer");
    }
  }, [router]);

  const startEditing = useCallback((id: string | number, name: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingId(id);
    setEditingName(name);
  }, []);

  const saveEdit = useCallback(() => {
    if (!editingId || !editingName.trim()) {
      setEditingId(null);
      setEditingName("");
      return;
    }
    const trimmed = editingName.trim();
    const update = (cols: Collection[]): Collection[] =>
      cols.map(col => ({
        ...(col.id === editingId ? { ...col, name: trimmed } : col),
        requests: col.requests.map(req =>
          req.id === editingId ? { ...req, name: trimmed } : req
        ),
        collections: update(col.collections || [])
      }));

    saveCollections(update(collections));
    setEditingId(null);
    setEditingName("");
  }, [editingId, editingName, collections, saveCollections]);

  const openDeleteModal = useCallback((id: number | string, isFolder: boolean, name: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleteTarget({ id, isFolder, name });
    setShowDeleteModal(true);
  }, []);

  const confirmDelete = useCallback(() => {
    if (!deleteTarget) return;
    setDeletingId(deleteTarget.id);
    setTimeout(() => {
      const update = (cols: Collection[]): Collection[] => {
        if (deleteTarget.isFolder) {
          return cols
            .filter(c => c.id !== deleteTarget.id)
            .map(c => ({ ...c, collections: update(c.collections || []) }));
        }
        return cols.map(c => ({
          ...c,
          requests: c.requests.filter(r => r.id !== deleteTarget.id),
          collections: update(c.collections || [])
        }));
      };
      saveCollections(update(collections));
      setDeletingId(null);
      setShowDeleteModal(false);
      setDeleteTarget(null);
    }, 400);
  }, [deleteTarget, collections, saveCollections]);

  const renderCollection = useCallback((col: Collection, level = 0): JSX.Element => {
    const pl = 16 + level * 22;
    const isDeleting = deletingId === col.id;

    return (
      <div key={col.id} className={`mb-1 transition-all duration-500 ${isDeleting ? 'opacity-0 scale-75 -translate-x-12' : ''}`}>
        <div
          className="te-folder-row group flex items-center justify-between"
          style={{ paddingLeft: `${pl}px` }}
          onClick={() => toggleFolder(col.id)}
        >
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <span className="te-chevron">
              {col.isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            </span>
            <FolderOpen size={19} className="te-folder-icon flex-shrink-0" />
            {editingId === col.id ? (
              <input autoFocus value={editingName} onChange={e => setEditingName(e.target.value)} onBlur={saveEdit} onKeyDown={e => { if (e.key === "Enter") saveEdit(); if (e.key === "Escape") { setEditingId(null); setEditingName(""); } }} className="te-inline-input flex-1" />
            ) : (
              <span className="te-folder-name truncate" onDoubleClick={e => startEditing(col.id, col.name, e)}>
                {col.name}
              </span>
            )}
          </div>

          <div className="te-row-actions flex items-center gap-1 opacity-0 group-hover:opacity-100">
            <button className="te-act-btn" onClick={e => { e.stopPropagation(); openNewModal(col.id, false); }}><Plus size={16} /></button>
            <button className="te-act-btn" onClick={e => { e.stopPropagation(); openNewModal(col.id, true); }}><FolderOpen size={16} /></button>
            <button className="te-act-btn te-red" onClick={e => openDeleteModal(col.id, true, col.name, e)}><Trash2 size={16} /></button>
          </div>
        </div>

        {col.isOpen && (
          <div>
            {col.requests.map(req => {
              const isReqDeleting = deletingId === req.id;
              return (
                <div
                  key={req.id}
                  className={`te-request-row group flex items-center ${isReqDeleting ? 'opacity-0 scale-75 -translate-x-12' : ''}`}
                  style={{ paddingLeft: `${pl + 32}px` }}
                  onClick={() => !isReqDeleting && handleRequestClick(req)}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className="te-method-badge">{req.method}</span>
                    <span className="te-req-type-dot" style={{ backgroundColor: PROTOCOLS.find(p => p.name === req.type)?.color || '#60a5fa' }} />
                    <FileText size={17} className="text-violet-400 flex-shrink-0" />
                    {editingId === req.id ? (
                      <input autoFocus value={editingName} onChange={e => setEditingName(e.target.value)} onBlur={saveEdit} onKeyDown={e => { if (e.key === "Enter") saveEdit(); if (e.key === "Escape") { setEditingId(null); setEditingName(""); } }} className="te-inline-input flex-1" />
                    ) : (
                      <span className="te-req-name truncate" onDoubleClick={e => startEditing(req.id, req.name, e)}>
                        {req.name}
                      </span>
                    )}
                  </div>
                  <button className="te-act-btn te-red opacity-0 group-hover:opacity-100" onClick={e => openDeleteModal(req.id, false, req.name, e)}>
                    <Trash2 size={16} />
                  </button>
                </div>
              );
            })}
            {(col.collections || []).map(sub => renderCollection(sub, level + 1))}
          </div>
        )}
      </div>
    );
  }, [editingId, editingName, deletingId, toggleFolder, openNewModal, openDeleteModal, startEditing, saveEdit, handleRequestClick]);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        .te-sidebar { font-family: 'Inter', sans-serif; width: 290px; background: rgba(10, 11, 20, 0.98); backdrop-filter: blur(28px); border-right: 1px solid rgba(139, 92, 246, 0.2); height: 100vh; display: flex; flex-direction: column; }
        .te-folder-row, .te-request-row { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); border-radius: 10px; margin: 3px 6px; padding: 8px 10px; cursor: pointer; user-select: none; }
        .te-folder-row:hover, .te-request-row:hover { background: rgba(167,139,246,0.15); transform: translateX(8px) scale(1.03); }
        .te-act-btn { width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; border-radius: 7px; color: #94a3b8; transition: all 0.2s; }
        .te-act-btn:hover { color: white; background: rgba(167,139,246,0.3); transform: scale(1.25); }
        .te-red:hover { color: #f87171 !important; }
        .te-folder-icon { color: #c4b5fd; }
        .te-folder-name, .te-req-name { color: #e0e7ff; font-weight: 500; cursor: pointer; }
        .te-method-badge { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 2px 7px; border-radius: 4px; background: rgba(167,139,246,0.2); color: #c4b5fd; }
        .te-req-type-dot { width: 7px; height: 7px; border-radius: 50%; }
        .te-inline-input { background: rgba(255,255,255,0.1); border: 1px solid #7c3aed; color: white; padding: 5px 8px; border-radius: 6px; font-size: 14px; }
        .te-inline-input:focus { outline: none; box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.5); }
      `}</style>

      <div className="te-sidebar">
        <div className="px-6 py-6 border-b border-white/10 flex items-center gap-3 cursor-pointer hover:opacity-90 transition" onClick={() => router.push('/dashboard')}>
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-violet-600 to-fuchsia-600 flex items-center justify-center shadow-xl shadow-purple-500/50">
            <Zap size={28} color="#fff" strokeWidth={2.8} />
          </div>
          <div>
            <div className="text-2xl font-bold tracking-tight text-white">Trust_Edge</div>
            <div className="flex items-center gap-2 text-emerald-400 text-sm mt-0.5">
              <div className="w-2.5 h-2.5 bg-emerald-400 rounded-full animate-pulse" /> Connected
            </div>
          </div>
        </div>

        <div className="px-3 pt-4 space-y-1">
          <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 text-zinc-400 hover:text-white hover:bg-white/5 rounded-xl transition-all text-[15px]">
            <Home size={18} /> Dashboard
          </Link>
          <Link href="/analyzer" className="flex items-center gap-3 px-4 py-3 text-zinc-400 hover:text-white hover:bg-white/5 rounded-xl transition-all text-[15px]">
            <Zap size={18} /> Analyzer
          </Link>
          <Link href="/history" className="flex items-center gap-3 px-4 py-3 text-zinc-400 hover:text-white hover:bg-white/5 rounded-xl transition-all text-[15px]">
            <History size={18} /> History
          </Link>
        </div>

        <div className="px-6 mt-7 mb-3 flex justify-between items-center">
          <span className="uppercase text-xs tracking-widest font-mono text-zinc-400">Collections</span>
          <button onClick={() => openNewModal(null, true)} className="text-violet-400 hover:bg-white/10 p-2 rounded-xl transition-all">
            <Plus size={20} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-1">
          {collections.map(col => renderCollection(col))}
        </div>

        <div className="p-4 border-t border-white/10">
          <Link href="/settings" className="flex items-center gap-3 px-4 py-3 text-zinc-400 hover:text-white hover:bg-white/5 rounded-xl transition-all text-[15px]">
            <Settings size={18} /> Settings
          </Link>
        </div>
      </div>

      {/* New Item Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xl z-[100] flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-white/10 rounded-3xl w-full max-w-[460px] p-8 shadow-2xl">
            <div className="text-2xl font-semibold mb-6 flex items-center gap-3">
              {isCreatingFolder ? <FolderOpen size={28} className="text-amber-400" /> : <Zap size={28} className="text-violet-400" />}
              New {isCreatingFolder ? "Folder" : "Request"}
            </div>

            <input 
              autoFocus 
              className="w-full bg-zinc-900 border border-white/10 rounded-2xl px-5 py-4 text-white placeholder-zinc-500 focus:border-violet-500 outline-none mb-6" 
              placeholder={isCreatingFolder ? "Folder name..." : "Request name..."} 
              value={newName} 
              onChange={e => setNewName(e.target.value)} 
              onKeyDown={e => { 
                if (e.key === "Enter" && newName.trim()) createNewItem(); 
                if (e.key === "Escape") setShowNewModal(false); 
              }} 
            />

            {!isCreatingFolder && (
              <div className="grid grid-cols-2 gap-3 mb-6">
                {PROTOCOLS.map(p => (
                  <button 
                    key={p.name} 
                    onClick={() => setSelectedProtocol(p.name)} 
                    className={`p-4 rounded-2xl border text-left transition-all group ${selectedProtocol === p.name ? 'border-violet-500 bg-violet-500/10' : 'border-white/10 hover:border-white/30'}`}
                  >
                    <span className="text-2xl mb-2 block">{p.icon}</span>
                    <div className="font-medium text-white">{p.name}</div>
                  </button>
                ))}
              </div>
            )}

            <div className="flex gap-3">
              <button onClick={() => setShowNewModal(false)} className="flex-1 py-4 rounded-2xl bg-zinc-900 hover:bg-zinc-800">Cancel</button>
              <button onClick={createNewItem} disabled={!newName.trim()} className="flex-1 py-4 rounded-2xl bg-gradient-to-r from-violet-600 to-fuchsia-600 disabled:opacity-50">Create</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Modal */}
      {showDeleteModal && deleteTarget && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xl z-[100] flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-red-500/30 rounded-3xl w-full max-w-[400px] p-8 text-center shadow-2xl">
            <Trash2 size={48} className="mx-auto text-red-500 mb-4" />
            <h3 className="text-xl font-semibold mb-2">Delete {deleteTarget.isFolder ? "Folder" : "Request"}?</h3>
            <p className="text-zinc-400 mb-6">"{deleteTarget.name}"</p>
            <div className="flex gap-3">
              <button onClick={() => setShowDeleteModal(false)} className="flex-1 py-3.5 rounded-2xl bg-zinc-900 hover:bg-zinc-800">Cancel</button>
              <button onClick={confirmDelete} className="flex-1 py-3.5 rounded-2xl bg-red-600 hover:bg-red-700">Yes, Delete</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
