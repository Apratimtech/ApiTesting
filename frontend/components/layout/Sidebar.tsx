"use client";
import { useEffect, useState } from "react";
import {
  Zap, Home, History, Settings, Plus, Trash2,
  ChevronDown, ChevronRight, FolderOpen, FileText
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

type RequestItem = {
  id: string;
  name: string;
  method: string;
  url: string;
  type: string;
};

type Collection = {
  id: number;
  name: string;
  requests: RequestItem[];
  collections: Collection[];
  isOpen: boolean;
};

const PROTOCOLS = [
  { name: "HTTP", icon: "🌐", color: "#60a5fa", defaultMethod: "GET" },
  { name: "GraphQL", icon: "⚡", color: "#f472b6", defaultMethod: "POST" },
  { name: "WebSocket", icon: "🔌", color: "#34d399", defaultMethod: "GET" },
  { name: "gRPC", icon: "🔄", color: "#22d3ee", defaultMethod: "POST" },
  { name: "MQTT", icon: "📡", color: "#a78bfa", defaultMethod: "PUBLISH" },
  { name: "Socket.IO", icon: "⚡", color: "#fb923c", defaultMethod: "EMIT" },
  { name: "AI", icon: "🤖", color: "#c084fc", defaultMethod: "POST" },
  { name: "MCP", icon: "🔧", color: "#fbbf24", defaultMethod: "POST" },
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

  useEffect(() => {
    const saved = localStorage.getItem("trustedge_collections");
    if (saved) {
      setCollections(JSON.parse(saved));
    } else {
      const defaults: Collection[] = [{ id: 1, name: "My Collection", requests: [], collections: [], isOpen: true }];
      setCollections(defaults);
      localStorage.setItem("trustedge_collections", JSON.stringify(defaults));
    }
  }, []);

  const saveCollections = (updated: Collection[]) => {
    setCollections(updated);
    localStorage.setItem("trustedge_collections", JSON.stringify(updated));
  };

  const toggleFolder = (id: number) => {
    const update = (cols: Collection[]): Collection[] =>
      cols.map(col => col.id === id
        ? { ...col, isOpen: !col.isOpen }
        : { ...col, collections: update(col.collections || []) });
    saveCollections(update(collections));
  };

  const openNewModal = (parentId: number | null, isFolder: boolean) => {
    setCurrentParentId(parentId);
    setIsCreatingFolder(isFolder);
    setNewName("");
    setSelectedProtocol("HTTP");
    setShowNewModal(true);
  };

  const createNewItem = () => {
    if (!newName.trim()) return;

    if (isCreatingFolder) {
      const newFolder: Collection = {
        id: Date.now(),
        name: newName.trim(),
        requests: [],
        collections: [],
        isOpen: true
      };
      if (currentParentId === null) {
        saveCollections([...collections, newFolder]);
      } else {
        const update = (cols: Collection[]): Collection[] =>
          cols.map(col => col.id === currentParentId
            ? { ...col, collections: [...(col.collections || []), newFolder] }
            : { ...col, collections: update(col.collections || []) });
        saveCollections(update(collections));
      }
    } else {
      const protocol = PROTOCOLS.find(p => p.name === selectedProtocol);
      const newReq: RequestItem = {
        id: Date.now().toString(),
        name: newName.trim(),
        method: protocol?.defaultMethod || "GET",
        url: "",
        type: selectedProtocol
      };
      const update = (cols: Collection[]): Collection[] =>
        cols.map(col => col.id === currentParentId
          ? { ...col, requests: [...col.requests, newReq] }
          : { ...col, collections: update(col.collections || []) });
      saveCollections(update(collections));
    }
    setShowNewModal(false);
  };

  const startEditing = (id: string | number, name: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingId(id);
    setEditingName(name);
  };

  const saveEdit = () => {
    if (!editingId || !editingName.trim()) {
      setEditingId(null);
      return;
    }
    const update = (cols: Collection[]): Collection[] =>
      cols.map(col => ({
        ...(col.id === editingId ? { ...col, name: editingName.trim() } : col),
        requests: col.requests.map(req =>
          req.id === editingId ? { ...req, name: editingName.trim() } : req
        ),
        collections: update(col.collections || [])
      }));
    saveCollections(update(collections));
    setEditingId(null);
  };

  const openDeleteModal = (id: number | string, isFolder: boolean, name: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleteTarget({ id, isFolder, name });
    setShowDeleteModal(true);
  };

  const confirmDelete = () => {
    if (!deleteTarget) return;
    setDeletingId(deleteTarget.id);
    setTimeout(() => {
      const updateTree = (cols: Collection[]): Collection[] => {
        if (deleteTarget.isFolder) {
          return cols.filter(c => c.id !== deleteTarget.id)
            .map(c => ({ ...c, collections: updateTree(c.collections || []) }));
        }
        return cols.map(c => ({
          ...c,
          requests: c.requests.filter(r => r.id !== deleteTarget.id),
          collections: updateTree(c.collections || [])
        }));
      };
      saveCollections(updateTree(collections));
      setDeletingId(null);
      setShowDeleteModal(false);
      setDeleteTarget(null);
    }, 400);
  };

  const handleRequestClick = (req: RequestItem) => {
    localStorage.setItem("last_selected_request", JSON.stringify(req));
    router.push("/analyzer");
  };

  function renderCollection(col: Collection, level = 0) {
    const pl = 16 + level * 22;
    const isDeleting = deletingId === col.id;

    return (
      <div key={col.id} className={`mb-1 transition-all duration-500 ${isDeleting ? 'opacity-0 scale-75 -translate-x-12' : ''}`}>
        <div className="te-folder-row group flex items-center justify-between" style={{ paddingLeft: pl }} onClick={() => toggleFolder(col.id)}>
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <span className="te-chevron">{col.isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</span>
            <FolderOpen size={19} className="te-folder-icon flex-shrink-0" />
            {editingId === col.id ? (
              <input
                autoFocus
                value={editingName}
                onChange={e => setEditingName(e.target.value)}
                onBlur={saveEdit}
                onKeyDown={e => e.key === "Enter" && saveEdit()}
                onClick={e => e.stopPropagation()}
                className="te-inline-input flex-1"
              />
            ) : (
              <span className="te-folder-name truncate" onDoubleClick={e => startEditing(col.id, col.name, e)}>
                {col.name}
              </span>
            )}
          </div>

          <div className="te-row-actions flex items-center gap-1 opacity-0 group-hover:opacity-100">
            <button className="te-act-btn" onClick={e => { e.stopPropagation(); openNewModal(col.id, false); }}>
              <Plus size={16} />
            </button>
            <button className="te-act-btn" onClick={e => { e.stopPropagation(); openNewModal(col.id, true); }}>
              <FolderOpen size={16} />
            </button>
            <button className="te-act-btn te-red" onClick={e => openDeleteModal(col.id, true, col.name, e)}>
              <Trash2 size={16} />
            </button>
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
                  style={{ paddingLeft: pl + 32 }}
                  onClick={() => !isReqDeleting && handleRequestClick(req)}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className="te-method-badge">{req.method}</span>
                    <span className="te-req-type-dot" style={{ backgroundColor: PROTOCOLS.find(p => p.name === req.type)?.color }} />
                    <FileText size={17} className="text-violet-400 flex-shrink-0" />
                    {editingId === req.id ? (
                      <input
                        autoFocus
                        value={editingName}
                        onChange={e => setEditingName(e.target.value)}
                        onBlur={saveEdit}
                        onKeyDown={e => e.key === "Enter" && saveEdit()}
                        onClick={e => e.stopPropagation()}
                        className="te-inline-input flex-1"
                      />
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
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        .te-sidebar {
          font-family: 'Inter', sans-serif;
          width: 290px;
          background: rgba(10, 11, 20, 0.98);
          backdrop-filter: blur(28px);
          border-right: 1px solid rgba(139, 92, 246, 0.2);
          height: 100vh;
          display: flex;
          flex-direction: column;
        }

        .te-folder-row, .te-request-row {
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          border-radius: 10px;
          margin: 3px 6px;
          padding: 8px 10px;
        }
        .te-folder-row:hover, .te-request-row:hover {
          background: rgba(167,139,246,0.15);
          transform: translateX(8px) scale(1.03);
        }

        .te-row-actions { transition: opacity 0.25s; }
        .te-act-btn {
          width: 30px; height: 30px;
          display: flex; align-items: center; justify-content: center;
          border-radius: 7px; color: #94a3b8; transition: all 0.2s;
        }
        .te-act-btn:hover {
          color: white;
          background: rgba(167,139,246,0.3);
          transform: scale(1.25);
        }
        .te-red:hover { color: #f87171 !important; }

        .te-folder-icon { color: #c4b5fd; }
        .te-folder-name, .te-req-name { color: #e0e7ff; font-weight: 500; }
        .te-method-badge {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px; padding: 2px 7px; border-radius: 4px;
          background: rgba(167,139,246,0.2); color: #c4b5fd;
        }
        .te-req-type-dot { width: 7px; height: 7px; border-radius: 50%; }
        .te-inline-input {
          background: rgba(255,255,255,0.1);
          border: 1px solid #7c3aed;
          color: white;
          padding: 5px 8px;
          border-radius: 6px;
          font-size: 14px;
        }
      `}</style>

      <div className="te-sidebar">
        {/* Logo Area - Clickable */}
        <div 
          className="px-6 py-6 border-b border-white/10 flex items-center gap-3 cursor-pointer hover:opacity-90 transition" 
          onClick={() => router.push('/dashboard')}
        >
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-violet-600 to-fuchsia-600 flex items-center justify-center shadow-xl shadow-purple-500/50">
            <Zap size={28} color="#fff" strokeWidth={2.8} />
          </div>
          <div>
            <div className="text-2xl font-bold tracking-tight text-white">Trust_Edge</div>
            <div className="flex items-center gap-2 text-emerald-400 text-sm mt-0.5">
              <div className="w-2.5 h-2.5 bg-emerald-400 rounded-full animate-pulse" />
              Connected
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
          <button onClick={() => openNewModal(null, true)} className="text-violet-400 hover:bg-white/10 p-2 rounded-xl">
            <Plus size={20} />
          </button>
        </div>

        {/* Collections Tree */}
        <div className="flex-1 overflow-y-auto px-3 py-1">
          {collections.map(col => renderCollection(col))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10">
          <Link href="/settings" className="flex items-center gap-3 px-4 py-3 text-zinc-400 hover:text-white hover:bg-white/5 rounded-xl transition-all text-[15px]">
            <Settings size={18} /> Settings
          </Link>
        </div>
      </div>

      {/* New Item Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xl z-[100] flex items-center justify-center">
          <div className="bg-zinc-950 border border-white/10 rounded-3xl w-[460px] p-8 shadow-2xl">
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
              onKeyDown={e => e.key === "Enter" && createNewItem()}
            />

            {!isCreatingFolder && (
              <div className="grid grid-cols-2 gap-3 mb-6">
                {PROTOCOLS.map(p => (
                  <button
                    key={p.name}
                    onClick={() => setSelectedProtocol(p.name)}
                    className={`p-4 rounded-2xl border text-left transition-all ${selectedProtocol === p.name ? 'border-violet-500 bg-violet-500/10' : 'border-white/10 hover:border-white/30'}`}
                  >
                    <span className="text-2xl mb-2 block">{p.icon}</span>
                    <div className="font-medium">{p.name}</div>
                    <div className="text-xs text-zinc-500">Default: {p.defaultMethod}</div>
                  </button>
                ))}
              </div>
            )}

            <div className="flex gap-3">
              <button onClick={() => setShowNewModal(false)} className="flex-1 py-4 rounded-2xl bg-zinc-900 hover:bg-zinc-800 font-medium">Cancel</button>
              <button onClick={createNewItem} disabled={!newName.trim()} className="flex-1 py-4 rounded-2xl bg-gradient-to-r from-violet-600 to-fuchsia-600 font-semibold disabled:opacity-50">Create</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xl z-[100] flex items-center justify-center">
          <div className="bg-zinc-950 border border-red-500/30 rounded-3xl w-[400px] p-8 text-center">
            <Trash2 size={48} className="mx-auto text-red-500 mb-4" />
            <h3 className="text-xl font-semibold mb-2">Delete {deleteTarget?.isFolder ? "Folder" : "Request"}?</h3>
            <p className="text-zinc-400 mb-6">"{deleteTarget?.name}"</p>
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
