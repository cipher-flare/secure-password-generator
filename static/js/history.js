// history.js — localStorage CRUD for password history + JSON import/export.

const STORAGE_KEY = "spg.history.v1";
const MAX_ENTRIES = 200;

export function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch (err) {
    console.warn("Could not read history:", err);
    return [];
  }
}

export function saveHistory(entries) {
  try {
    const trimmed = entries.slice(-MAX_ENTRIES);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    return true;
  } catch (err) {
    console.warn("Could not save history:", err);
    return false;
  }
}

export function addEntry(password, stats) {
  const entries = loadHistory();
  // De-dupe by password value (don't re-add the same plaintext).
  const exists = entries.some((e) => e.password === password);
  if (exists) return entries;
  entries.push({
    password,
    stats,
    savedAt: new Date().toISOString(),
  });
  saveHistory(entries);
  return entries;
}

export function removeEntry(index) {
  const entries = loadHistory();
  if (index < 0 || index >= entries.length) return entries;
  entries.splice(index, 1);
  saveHistory(entries);
  return entries;
}

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEY);
  return [];
}

export function exportJSON(entries) {
  // If no entries were passed in, fall back to what's persisted in storage.
  const data = Array.isArray(entries) ? entries : loadHistory();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `password-history-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function importJSON(file) {
  const text = await file.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("File is not valid JSON.");
  }
  if (!Array.isArray(parsed)) {
    throw new Error("Expected a JSON array of history entries.");
  }
  const valid = parsed.filter(
    (e) => e && typeof e.password === "string" && e.password.length > 0
  );
  const existing = loadHistory();
  const seen = new Set(existing.map((e) => e.password));
  let added = 0;
  for (const e of valid) {
    if (!seen.has(e.password)) {
      existing.push({
        password: e.password,
        stats: e.stats || null,
        savedAt: e.savedAt || new Date().toISOString(),
      });
      seen.add(e.password);
      added++;
    }
  }
  saveHistory(existing);
  return { imported: valid.length, added, total: existing.length };
}
