// Persisted, ordered list of panel ids shown on the main C2 console.
// Survives reloads via localStorage; falls back to DEFAULT_LAYOUT and drops any
// stale ids no longer in the catalog (so removing a panel never breaks restore).

import { useCallback, useEffect, useState } from "react";
import { DEFAULT_LAYOUT, PANEL_BY_ID } from "./dashboardPanels";

const KEY = "openelia.dash.layout.v1";

function sanitize(ids: unknown): string[] | null {
  if (!Array.isArray(ids)) return null;
  const valid = ids.filter((id): id is string => typeof id === "string" && id in PANEL_BY_ID);
  return valid.length ? Array.from(new Set(valid)) : null;
}

function load(): string[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const parsed = sanitize(JSON.parse(raw));
      if (parsed) return parsed;
    }
  } catch {
    /* corrupt / unavailable storage → defaults */
  }
  return [...DEFAULT_LAYOUT];
}

export type DashboardLayout = {
  ids: string[];
  add: (id: string) => void;
  remove: (id: string) => void;
  move: (id: string, dir: -1 | 1) => void;
  reset: () => void;
};

export function useDashboardLayout(): DashboardLayout {
  const [ids, setIds] = useState<string[]>(load);

  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(ids));
    } catch {
      /* storage full / blocked — layout still works in-session */
    }
  }, [ids]);

  const add = useCallback((id: string) => {
    if (!(id in PANEL_BY_ID)) return;
    setIds((c) => (c.includes(id) ? c : [...c, id]));
  }, []);

  const remove = useCallback((id: string) => {
    setIds((c) => c.filter((x) => x !== id));
  }, []);

  const move = useCallback((id: string, dir: -1 | 1) => {
    setIds((c) => {
      const i = c.indexOf(id);
      const j = i + dir;
      if (i < 0 || j < 0 || j >= c.length) return c;
      const next = [...c];
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
  }, []);

  const reset = useCallback(() => setIds([...DEFAULT_LAYOUT]), []);

  return { ids, add, remove, move, reset };
}
