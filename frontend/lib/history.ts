// frontend/lib/history.ts
export interface ScanHistory {
  id: number | string;
  url: string;
  method: string;
  risk: number;
  time: string;
  timestamp?: number;
  status?: number;
}

/**
 * Save a new scan to history (keeps only latest 20)
 */
export const saveScan = (scan: ScanHistory) => {
  try {
    const existing: ScanHistory[] = JSON.parse(
      localStorage.getItem("scan_history") || "[]"
    );

    const updated = [scan, ...existing].slice(0, 20);
    localStorage.setItem("scan_history", JSON.stringify(updated));
  } catch (err) {
    console.error("Save history failed:", err);
  }
};

/**
 * Get all scans from history
 */
export const getScans = (): ScanHistory[] => {
  try {
    return JSON.parse(localStorage.getItem("scan_history") || "[]");
  } catch {
    return [];
  }
};

/**
 * Remove a single scan by ID
 */
export const removeScan = (id: string): void => {
  try {
    const existing: ScanHistory[] = getScans();
    const filtered = existing.filter((scan) => scan.id !== id);
    localStorage.setItem("scan_history", JSON.stringify(filtered));
  } catch (err) {
    console.error("Remove scan failed:", err);
  }
};

/**
 * Clear all history
 */
export const clearScans = (): void => {
  try {
    localStorage.removeItem("scan_history");
  } catch (err) {
    console.error("Clear history failed:", err);
  }
};

/**
 * Get scan by ID
 */
export const getScanById = (id: string): ScanHistory | undefined => {
  return getScans().find(scan => scan.id === id);
};
