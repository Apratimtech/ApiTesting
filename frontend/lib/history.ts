// frontend/lib/history.ts

export const saveScan = (scan: any) => {
  try {
    const existing = JSON.parse(localStorage.getItem("scan_history") || "[]");
    const updated = [scan, ...existing].slice(0, 20);
    localStorage.setItem("scan_history", JSON.stringify(updated));
  } catch (err) {
    console.error("Save history failed", err);
  }
};

export const getScans = () => {
  try {
    return JSON.parse(localStorage.getItem("scan_history") || "[]");
  } catch {
    return [];
  }
};

export const clearScans = () => {
  localStorage.removeItem("scan_history");
};
