"use client";
import { useEffect, useState, useCallback } from "react";
import {
  Zap, Home, History, Settings, Plus, Trash2,
  ChevronDown, ChevronRight, FolderOpen, FileText, Save, CheckCircle, AlertCircle
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
  headers?: Record<string, string> | Array<{ key: string; value: string }>;
  bodyType?: BodyType;
  body?: string;
  topic?: string;
  message?: string;
  qos?: number;
  serverUrl?: string;
  serviceName?: string;
  methodName?: string;
  payload?: string;
  brokerUrl?: string;
  clientId?: string;
};

type Collection = {
  id: string;
  name: string;
  requests: RequestItem[];
  collections: Collection[];
  isOpen: boolean;
};

const PROTOCOLS = [
  { name: "HTTP", icon: "🌐", color: "#60a5fa", defaultMethod: "GET", route: "/analyzer" },
  { name: "GraphQL", icon: "⚡", color: "#f472b6", defaultMethod: "POST", route: "/analyzer/graphql" },
  { name: "WebSocket", icon: "🔌", color: "#34d399", defaultMethod: "GET", route: "/analyzer/websocket" },
  { name: "gRPC", icon: "🔄", color: "#22d3ee", defaultMethod: "POST", route: "/analyzer/grpc" },
  { name: "MQTT", icon: "📡", color: "#a78bfa", defaultMethod: "PUBLISH", route: "/analyzer/mqtt" },
  { name: "Socket.IO", icon: "⚡", color: "#fb923c", defaultMethod: "EMIT", route: "/analyzer/socketio" },
  { name: "AI", icon: "🤖", color: "#c084fc", defaultMethod: "POST", route: "/analyzer/ai" },
  { name: "MCP", icon: "🔧", color: "#fbbf24", defaultMethod: "POST", route: "/analyzer/mcp" },
];

const API_BASE = "http://127.0.0.1:8000/api/v1";

export default function Sidebar() {
  const router = useRouter();

  const [collections, setCollections] = useState<Collection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [showNewModal, setShowNewModal] = useState(false);
  const [currentParentId, setCurrentParentId] = useState<string | null>(null);
  const [isCreatingFolder, setIsCreatingFolder] = useState(false);
  const [newName, setNewName] = useState("");
  const [selectedProtocol, setSelectedProtocol] = useState("HTTP");

  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showSaveModal, setShowSaveModal] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; isFolder: boolean; name: string } | null>(null);
  const [saveTarget, setSaveTarget] = useState<{ id: string; isFolder: boolean; name: string } | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const fetchCollections = async (): Promise<any> => {
    const res = await fetch(`${API_BASE}/collections/`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) throw new Error("Failed to fetch collections");
    return await res.json();
  };

  const loadCollections = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchCollections();
      const backendData = res.data || res || [];
      const mapped: Collection[] = backendData.map((c: any) => ({
        id: c.id,
        name: c.name,
        requests: c.requests || [],
        collections: c.collections || [],
        isOpen: true,
      }));
      setCollections(mapped);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to load collections");
      setCollections([{ id: "1", name: "My Collection", requests: [], collections: [], isOpen: true }]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCollections();
  }, []);

  const createNewItem = async () => {
    const trimmedName = newName.trim();
    if (!trimmedName) return;

    if (isCreatingFolder) {
      try {
        await fetch(`${API_BASE}/collections/`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: trimmedName, parentId: currentParentId }),
        });
        await loadCollections();
      } catch (error: any) {
        alert("Failed to create folder: " + error.message);
      }
    } else {
      if (!currentParentId) {
        alert("Please select a folder first to create the request.");
        return;
      }

      const protocol = PROTOCOLS.find(p => p.name === selectedProtocol)!;

      // Convert headers array to object (Fix for 422 error)
      const headersObj = { "Content-Type": "application/json" };

      const payload = {
        name: trimmedName,
        type: selectedProtocol,
        method: protocol.defaultMethod,
        url: selectedProtocol === "HTTP" ? "https://httpbin.org/get" : "",
        headers: headersObj,                    // ← Fixed
        bodyType: "json",
        body: `{\n  "username": "admin",\n  "password": "123456"\n}`,
        ...(selectedProtocol === "gRPC" && {
          serverUrl: "grpc://localhost:50051",
          serviceName: "user.UserService",
          methodName: "CreateUser",
          payload: `{\n  "name": "John Doe",\n  "email": "john@example.com"\n}`
        }),
        ...(selectedProtocol === "MQTT" && {
          topic: "test/topic",
          message: "Hello from Trust_Edge",
          qos: 1,
          brokerUrl: "ws://localhost:9001",
          clientId: `trust_edge_${Date.now()}`
        }),
      };

      try {
        const res = await fetch(`${API_BASE}/collections/${currentParentId}/request`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          const errText = await res.text();
          throw new Error(errText);
        }

        const created = await res.json();
        localStorage.setItem("last_selected_request", JSON.stringify(created.data || created));
        await loadCollections();
      } catch (error: any) {
        console.error(error);
        alert("Failed to create request: " + error.message);
        return;
      }
    }

    setShowNewModal(false);
    setNewName("");
  };

  const handleRequestClick = useCallback((req: RequestItem) => {
    console.log("Clicked Request:", req); // Debug
    try {
      localStorage.setItem("last_selected_request", JSON.stringify(req));
      const protocol = PROTOCOLS.find(p => p.name === req.type);
      const route = protocol?.route || "/analyzer";
      router.push(`${route}?request=${req.id}&t=${Date.now()}`);
    } catch (error) {
      console.error(error);
      router.push("/analyzer");
    }
  }, [router]);

  const toggleFolder = useCallback((id: string) => {
    setCollections(prev =>
      prev.map(col => {
        if (col.id === id) return { ...col, isOpen: !col.isOpen };
        return { ...col, collections: updateIsOpen(col.collections || [], id) };
      })
    );
  }, []);

  const updateIsOpen = (cols: Collection[], targetId: string): Collection[] => {
    return cols.map(col => ({
      ...col,
      isOpen: col.id === targetId ? !col.isOpen : col.isOpen,
      collections: updateIsOpen(col.collections || [], targetId)
    }));
  };

  const openNewModal = useCallback((parentId: string | null, isFolder: boolean) => {
    setCurrentParentId(parentId);
    setIsCreatingFolder(isFolder);
    setNewName("");
    setSelectedProtocol("HTTP");
    setShowNewModal(true);
  }, []);

  const startEditing = useCallback((id: string, name: string, e: React.MouseEvent) => {
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
    setCollections(prev =>
      prev.map(col => ({
        ...(col.id === editingId ? { ...col, name: trimmed } : col),
        requests: col.requests.map(req => req.id === editingId ? { ...req, name: trimmed } : req),
        collections: updateCollectionName(col.collections || [], editingId, trimmed)
      }))
    );
    setEditingId(null);
    setEditingName("");
  }, [editingId, editingName]);

  const updateCollectionName = (cols: Collection[], targetId: string, newName: string): Collection[] => {
    return cols.map(col => ({
      ...(col.id === targetId ? { ...col, name: newName } : col),
      requests: col.requests.map(req => req.id === targetId ? { ...req, name: newName } : req),
      collections: updateCollectionName(col.collections || [], targetId, newName)
    }));
  };

  const openDeleteModal = useCallback((id: string, isFolder: boolean, name: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleteTarget({ id, isFolder, name });
    setShowDeleteModal(true);
  }, []);

  const openSaveModal = useCallback((id: string, isFolder: boolean, name: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSaveTarget({ id, isFolder, name });
    setShowSaveModal(true);
  }, []);

  const confirmSave = useCallback(() => {
    setShowSaveModal(false);
    setSaveTarget(null);
  }, []);

  const confirmDelete = async () => {
    if (!deleteTarget || isDeleting) return;
    setDeletingId(deleteTarget.id);
    try {
      if (deleteTarget.isFolder) {
        await fetch(`${API_BASE}/collections/${deleteTarget.id}`, { method: "DELETE" });
      } else {
        await fetch(`${API_BASE}/collections/request/${deleteTarget.id}`, { method: "DELETE" });
      }
      await loadCollections();
    } catch (error: any) {
      alert("Failed to delete: " + error.message);
    } finally {
      setDeletingId(null);
      setShowDeleteModal(false);
      setDeleteTarget(null);
    }
  };

  const renderCollection = useCallback((col: Collection, level = 0): JSX.Element => {
    const pl = 16 + level * 22;
    const isDeletingItem = deletingId === col.id;

    return (
      <div key={col.id} className={`mb-1 transition-all duration-500 ${isDeletingItem ? 'opacity-0 scale-75 -translate-x-12' : ''}`}>
        <div className="te-folder-row group flex items-center justify-between" style={{ paddingLeft: `${pl}px` }} onClick={() => toggleFolder(col.id)}>
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <span className="te-chevron">{col.isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</span>
            <FolderOpen size={19} className="te-folder-icon flex-shrink-0" />
            {editingId === col.id ? (
              <input autoFocus value={editingName} onChange={e => setEditingName(e.target.value)} onBlur={saveEdit} onKeyDown={e => { if (e.key === "Enter") saveEdit(); if (e.key === "Escape") { setEditingId(null); setEditingName(""); } }} className="te-inline-input flex-1" />
            ) : (
              <span className="te-folder-name truncate" onDoubleClick={e => startEditing(col.id, col.name, e)}>{col.name}</span>
            )}
          </div>

          <div className="te-row-actions flex items-center gap-1 opacity-0 group-hover:opacity-100">
            <button className="te-act-btn" onClick={e => { e.stopPropagation(); openNewModal(col.id, false); }} title="New Request"><Plus size={16} /></button>
            <button className="te-act-btn" onClick={e => { e.stopPropagation(); openNewModal(col.id, true); }} title="New Folder"><FolderOpen size={16} /></button>
            <button className="te-act-btn" onClick={e => openSaveModal(col.id, true, col.name, e)} title="Save"><Save size={16} /></button>
            <button className="te-act-btn te-red" onClick={e => openDeleteModal(col.id, true, col.name, e)} title="Delete" disabled={isDeleting}><Trash2 size={16} /></button>
          </div>
        </div>

        {col.isOpen && (
          <div>
            {col.requests.map(req => (
              <div key={req.id} className={`te-request-row group flex items-center ${deletingId === req.id ? 'opacity-0 scale-75 -translate-x-12' : ''}`} style={{ paddingLeft: `${pl + 32}px` }} onClick={() => handleRequestClick(req)}>
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <span className="te-method-badge">{req.method}</span>
                  <span className="te-req-type-dot" style={{ backgroundColor: PROTOCOLS.find(p => p.name === req.type)?.color || '#60a5fa' }} />
                  <FileText size={17} className="text-violet-400 flex-shrink-0" />
                  {editingId === req.id ? (
                    <input autoFocus value={editingName} onChange={e => setEditingName(e.target.value)} onBlur={saveEdit} onKeyDown={e => { if (e.key === "Enter") saveEdit(); if (e.key === "Escape") { setEditingId(null); setEditingName(""); } }} className="te-inline-input flex-1" />
                  ) : (
                    <span className="te-req-name truncate" onDoubleClick={e => startEditing(req.id, req.name, e)}>{req.name}</span>
                  )}
                </div>
                <div className="te-row-actions flex items-center gap-1 opacity-0 group-hover:opacity-100">
                  <button className="te-act-btn" onClick={e => openSaveModal(req.id, false, req.name, e)} title="Save"><Save size={16} /></button>
                  <button className="te-act-btn te-red" onClick={e => openDeleteModal(req.id, false, req.name, e)} title="Delete" disabled={isDeleting}><Trash2 size={16} /></button>
                </div>
              </div>
            ))}
            {(col.collections || []).map(sub => renderCollection(sub, level + 1))}
          </div>
        )}
      </div>
    );
  }, [editingId, editingName, deletingId, toggleFolder, openNewModal, openDeleteModal, openSaveModal, startEditing, saveEdit, handleRequestClick, isDeleting]);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        .te-sidebar { font-family: 'Inter', sans-serif; width: 290px; background: rgba(10, 11, 20, 0.98); backdrop-filter: blur(28px); border-right: 1px solid rgba(139, 92, 246, 0.2); height: 100vh; display: flex; flex-direction: column; }
        .te-folder-row, .te-request-row { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); border-radius: 10px; margin: 3px 6px; padding: 8px 10px; cursor: pointer; user-select: none; }
        .te-folder-row:hover, .te-request-row:hover { background: rgba(167,139,246,0.15); transform: translateX(8px) scale(1.03); }
        .te-act-btn { width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; border-radius: 7px; color: #94a3b8; transition: all 0.2s; }
        .te-act-btn:hover { color: white; background: rgba(167,139,246,0.3); transform: scale(1.25); }
        .te-act-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .te-red:hover { color: #f87171 !important; }
        .te-folder-icon { color: #c4b5fd; }
        .te-folder-name, .te-req-name { color: #e0e7ff; font-weight: 500; cursor: pointer; }
        .te-method-badge { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 2px 7px; border-radius: 4px; background: rgba(167,139,246,0.2); color: #c4b5fd; }
        .te-req-type-dot { width: 7px; height: 7px; border-radius: 50%; }
        .te-inline-input { background: rgba(255,255,255,0.1); border: 1px solid #7c3aed; color: white; padding: 5px 8px; border-radius: 6px; font-size: 14px; }
        .te-inline-input:focus { outline: none; box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.5); }
      `}</style>

      <div className="te-sidebar">
        {/* Header */}
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

        {/* Navigation */}
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

        {/* Collections Header */}
        <div className="px-6 mt-7 mb-3 flex justify-between items-center">
          <span className="uppercase text-xs tracking-widest font-mono text-zinc-400">Collections</span>
          <button onClick={() => openNewModal(null, true)} className="text-violet-400 hover:bg-white/10 p-2 rounded-xl transition-all" disabled={loading}>
            <Plus size={20} />
          </button>
        </div>

        {/* Collections List */}
        <div className="flex-1 overflow-y-auto px-3 py-1">
          {loading ? (
            <div className="text-zinc-400 text-center py-8">Loading collections...</div>
          ) : error ? (
            <div className="text-red-400 text-center py-8 flex flex-col items-center gap-2">
              <AlertCircle size={24} />
              <p>{error}</p>
              <button onClick={loadCollections} className="text-violet-400 underline">Retry</button>
            </div>
          ) : (
            collections.map(col => renderCollection(col))
          )}
        </div>

        {/* Bottom Settings */}
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
                  <button key={p.name} onClick={() => setSelectedProtocol(p.name)} className={`p-4 rounded-2xl border text-left transition-all group ${selectedProtocol === p.name ? 'border-violet-500 bg-violet-500/10' : 'border-white/10 hover:border-white/30'}`}>
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

      {/* Save Modal */}
      {showSaveModal && saveTarget && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xl z-[100] flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-emerald-500/30 rounded-3xl w-full max-w-[400px] p-8 text-center shadow-2xl">
            <CheckCircle size={48} className="mx-auto text-emerald-500 mb-4" />
            <h3 className="text-xl font-semibold mb-2">Save Changes?</h3>
            <p className="text-zinc-400 mb-6">Do you want to save "<span className="text-white font-medium">{saveTarget.name}</span>"?</p>
            <div className="flex gap-3">
              <button onClick={() => { setShowSaveModal(false); setSaveTarget(null); }} className="flex-1 py-3.5 rounded-2xl bg-zinc-900 hover:bg-zinc-800">Cancel</button>
              <button onClick={confirmSave} className="flex-1 py-3.5 rounded-2xl bg-emerald-600 hover:bg-emerald-700">Yes, Save</button>
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
              <button onClick={confirmDelete} disabled={isDeleting} className="flex-1 py-3.5 rounded-2xl bg-red-600 hover:bg-red-700 disabled:opacity-50">
                {isDeleting ? "Deleting..." : "Yes, Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
