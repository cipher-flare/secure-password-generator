// ui.js — DOM wiring, validation, toasts, modal, copy, and the live entropy preview.

import { generateBatch, generatePasswordClient, CHAR_SETS } from "./crypto.js";
import {
  poolSize,
  calculateEntropy,
  passwordStats,
  calculateStrength,
  nistScore,
  analyzePassword,
} from "./strength.js";
import {
  addEntry,
  clearHistory,
  exportJSON,
  importJSON,
  loadHistory,
  removeEntry,
} from "./history.js";
import { checkBreach, abortBreach } from "./breach.js";

/* -------------------------- DOM helpers -------------------------- */
const $ = (id) => document.getElementById(id);
const els = {
  form: $("generator-form"),
  lengthSlider: $("length-slider"),
  lengthInput: $("length-input"),
  lengthReadout: $("length-readout"),
  entropyReadout: $("entropy-readout"),
  countInput: $("count-input"),
  avoidAmbiguous: $("avoid-ambiguous"),
  categoryInputs: Array.from(document.querySelectorAll("[data-category]")),
  generateBtn: $("generate-btn"),
  copyAllBtn: $("copy-all-btn"),
  downloadBtn: $("download-btn"),
  clearBtn: $("clear-btn"),
  resultsList: $("results-list"),
  formError: $("form-error"),
  strengthLabel: $("strength-label"),
  entropyValue: $("entropy-value"),
  crackTime: $("crack-time"),
  nistScore: $("nist-score"),
  strengthBar: $("strength-bar-fill"),
  auditInput: $("audit-input"),
  auditToggle: $("audit-toggle"),
  auditFeedback: $("audit-feedback"),
  breachBtn: $("breach-check-btn"),
  breachResult: $("breach-result"),
  historyList: $("history-list"),
  exportBtn: $("export-btn"),
  importBtn: $("import-btn"),
  importInput: $("import-input"),
  clearHistoryBtn: $("clear-history-btn"),
  toastContainer: $("toast-container"),
  modal: $("modal"),
  modalTitle: $("modal-title"),
  modalBody: $("modal-body"),
  modalConfirm: $("modal-confirm"),
  modalCancel: $("modal-cancel"),
  apiStatus: $("api-status"),
};

const state = {
  results: [],          // [{password, stats}]
  history: loadHistory(),
  clipboardTimer: null,
  breachBusy: false,     // re-entrancy guard for handleBreachCheck
};

const STRENGTH_CLASS = {
  Weak: "strength-pill--weak",
  Medium: "strength-pill--medium",
  Strong: "strength-pill--strong",
  "Very Strong": "strength-pill--very-strong",
};

const BAR_CLASS = {
  Weak: "strength-bar-fill--weak",
  Medium: "strength-bar-fill--medium",
  Strong: "strength-bar-fill--strong",
  "Very Strong": "strength-bar-fill--very-strong",
};

/* -------------------------- Toasts -------------------------- */
export function toast(message, type = "info", timeout = 3000) {
  const node = document.createElement("div");
  node.className = `toast toast--${type}`;
  node.textContent = message;
  els.toastContainer.appendChild(node);
  setTimeout(() => {
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), 200);
  }, timeout);
}

/* -------------------------- Modal -------------------------- */
export function confirmDialog({ title, body, confirmText = "Confirm", cancelText = "Cancel" }) {
  return new Promise((resolve) => {
    els.modalTitle.textContent = title;
    els.modalBody.textContent = body;
    els.modalConfirm.textContent = confirmText;
    els.modalCancel.textContent = cancelText;
    els.modal.hidden = false;

    const cleanup = (result) => {
      els.modal.hidden = true;
      els.modalConfirm.removeEventListener("click", onConfirm);
      els.modalCancel.removeEventListener("click", onCancel);
      els.modal.querySelector(".modal-backdrop").removeEventListener("click", onCancel);
      document.removeEventListener("keydown", onKey);
      resolve(result);
    };
    const onConfirm = () => cleanup(true);
    const onCancel = () => cleanup(false);
    const onKey = (e) => {
      if (e.key === "Escape") cleanup(false);
      if (e.key === "Enter") cleanup(true);
    };

    els.modalConfirm.addEventListener("click", onConfirm);
    els.modalCancel.addEventListener("click", onCancel);
    els.modal.querySelector(".modal-backdrop").addEventListener("click", onCancel);
    document.addEventListener("keydown", onKey);
    setTimeout(() => els.modalConfirm.focus(), 0);
  });
}

/* -------------------------- Clipboard -------------------------- */
async function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      /* fall through */
    }
  }
  // Fallback for non-HTTPS contexts.
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.left = "-10000px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}

function scheduleClipboardClear() {
  if (state.clipboardTimer) clearTimeout(state.clipboardTimer);
  state.clipboardTimer = setTimeout(async () => {
    try {
      await navigator.clipboard.writeText("");
    } catch {
      /* ignore */
    }
  }, 30_000);
}

/* -------------------------- Validation -------------------------- */
function readForm() {
  const length = parseInt(els.lengthInput.value, 10);
  const count = parseInt(els.countInput.value, 10);
  const categories = els.categoryInputs.filter((cb) => cb.checked).map((cb) => cb.dataset.category);
  const avoidAmbiguous = els.avoidAmbiguous.checked;
  return { length, count, categories, avoidAmbiguous };
}

function showFormError(message) {
  els.formError.textContent = message;
  els.formError.hidden = false;
}
function clearFormError() {
  els.formError.textContent = "";
  els.formError.hidden = true;
}

function validate({ length, count, categories }) {
  if (!Number.isFinite(length) || isNaN(length)) {
    return "Password length must be a whole number.";
  }
  if (length < 4) return "Password length must be at least 4.";
  if (length > 128) return "Password length cannot exceed 128.";
  if (!Number.isFinite(count) || isNaN(count)) {
    return "Number of passwords must be a whole number.";
  }
  if (count < 1) return "Number of passwords must be at least 1.";
  if (count > 50) return "Cannot generate more than 50 passwords at once.";
  if (categories.length === 0) {
    return "Select at least one character category.";
  }
  return null;
}

/* -------------------------- Generation -------------------------- */
function handleGenerate(ev) {
  if (ev) ev.preventDefault();
  clearFormError();
  const form = readForm();
  const err = validate(form);
  if (err) {
    showFormError(err);
    return;
  }

  try {
    const passwords = generateBatch(form.length, form.count, form.categories, form.avoidAmbiguous);
    state.results = passwords.map((pwd) => ({
      password: pwd,
      stats: passwordStats(pwd, form.categories),
    }));
    renderResults();
    renderStrength(state.results[0]?.stats);
    els.copyAllBtn.disabled = state.results.length === 0;
    els.downloadBtn.disabled = state.results.length === 0;
    toast(`Generated ${state.results.length} password${state.results.length > 1 ? "s" : ""} ✔`, "success");
  } catch (e) {
    showFormError(e.message);
  }
}

function renderResults() {
  els.resultsList.innerHTML = "";
  if (state.results.length === 0) {
    const li = document.createElement("li");
    li.className = "results-empty";
    li.textContent = "No passwords generated yet.";
    els.resultsList.appendChild(li);
    return;
  }
  state.results.forEach((entry, idx) => {
    const li = document.createElement("li");
    li.className = "result-row";

    const index = document.createElement("div");
    index.className = "result-index";
    index.textContent = `${idx + 1}.`;

    const pwd = document.createElement("button");
    pwd.className = "result-password";
    pwd.type = "button";
    pwd.textContent = entry.password;
    pwd.title = "Click to copy";
    pwd.addEventListener("click", () => handleCopyOne(entry.password));

    const actions = document.createElement("div");
    actions.className = "result-actions";

    const copyBtn = document.createElement("button");
    copyBtn.className = "icon-btn";
    copyBtn.type = "button";
    copyBtn.title = "Copy";
    copyBtn.setAttribute("aria-label", "Copy password");
    copyBtn.innerHTML = '<span aria-hidden="true">📋</span>';
    copyBtn.addEventListener("click", () => handleCopyOne(entry.password));

    const regenBtn = document.createElement("button");
    regenBtn.className = "icon-btn";
    regenBtn.type = "button";
    regenBtn.title = "Regenerate this one";
    regenBtn.setAttribute("aria-label", "Regenerate this password");
    regenBtn.innerHTML = '<span aria-hidden="true">🔄</span>';
    regenBtn.addEventListener("click", () => handleRegenerateOne(idx));

    const saveBtn = document.createElement("button");
    saveBtn.className = "icon-btn";
    saveBtn.type = "button";
    saveBtn.title = "Save to history";
    saveBtn.setAttribute("aria-label", "Save to history");
    saveBtn.innerHTML = '<span aria-hidden="true">🔒</span>';
    saveBtn.addEventListener("click", () => handleSaveOne(entry));

    actions.append(copyBtn, regenBtn, saveBtn);

    const meta = document.createElement("div");
    meta.className = "result-meta";
    meta.innerHTML = `
      <span><strong>Strength:</strong> ${entry.stats.strength}</span>
      <span><strong>Entropy:</strong> ${entry.stats.entropyBits} bits</span>
      <span><strong>Crack:</strong> ${entry.stats.crackTime}</span>
    `;

    li.append(index, pwd, actions, meta);
    els.resultsList.appendChild(li);
  });
}

/**
 * Auto-save a result to history. Returns true if a new entry was added
 * (false when the password was already saved, so the caller can suppress
 * the "saved" toast on re-copy).
 */
function autoSaveToHistory(result) {
  const before = state.history.length;
  state.history = addEntry(result.password, result.stats);
  return state.history.length > before;
}

async function handleCopyOne(text) {
  const ok = await copyToClipboard(text);
  if (!ok) {
    toast("Copy failed — please copy manually.", "error");
    return;
  }
  // Copying implicitly saves to history so the user can re-find it later.
  const result = state.results.find((r) => r.password === text);
  if (result) {
    const added = autoSaveToHistory(result);
    if (added) renderHistory();
  }
  toast("Password copied to clipboard ✔", "success");
  scheduleClipboardClear();
}

async function handleCopyAll() {
  if (state.results.length === 0) return;
  const text = state.results.map((r) => r.password).join("\n");
  const ok = await copyToClipboard(text);
  if (!ok) {
    toast("Copy failed", "error");
    return;
  }
  // Save every freshly generated password to history on bulk copy.
  let anyAdded = false;
  for (const r of state.results) {
    if (autoSaveToHistory(r)) anyAdded = true;
  }
  if (anyAdded) renderHistory();
  toast("All passwords copied ✔", "success");
  scheduleClipboardClear();
}

function handleDownload() {
  if (state.results.length === 0) return;
  const header = `# Secure Password Generator export\n# ${new Date().toISOString()}\n\n`;
  const body = state.results
    .map((r, i) => `${i + 1}. ${r.password}    [${r.stats.strength}, ${r.stats.entropyBits} bits]`)
    .join("\n");
  const blob = new Blob([header + body], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `passwords-${new Date().toISOString().slice(0, 10)}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast("Downloaded .txt file", "success");
}

function handleRegenerateOne(idx) {
  const form = readForm();
  if (validate(form)) return;
  const { categories, length, avoidAmbiguous } = form;
  const pwd = generatePasswordClient(length, categories, avoidAmbiguous);
  const stats = passwordStats(pwd, categories);
  state.results[idx] = { password: pwd, stats };
  renderResults();
  if (idx === 0) renderStrength(stats);
  toast(`Regenerated password #${idx + 1}`, "info");
}

function handleSaveOne(entry) {
  const added = autoSaveToHistory(entry);
  renderHistory();
  toast(added ? "Saved to history" : "Already in history", added ? "success" : "info");
}

/* -------------------------- Strength dashboard -------------------------- */
function renderStrength(stats) {
  if (!stats) {
    els.strengthLabel.textContent = "—";
    els.strengthLabel.className = "strength-tile-value strength-pill strength-pill--weak";
    els.entropyValue.textContent = "—";
    els.crackTime.textContent = "—";
    els.strengthBar.style.width = "0%";
    els.strengthBar.className = "strength-bar-fill";
    els.nistScore.textContent = "— / 8";
    return;
  }
  els.strengthLabel.textContent = stats.strength;
  els.strengthLabel.className = `strength-tile-value strength-pill ${STRENGTH_CLASS[stats.strength] || ""}`;
  els.entropyValue.textContent = stats.entropyBits.toString();
  els.crackTime.textContent = stats.crackTime;

  // NIST bar — score the first generated password (or the audited one if any).
  const sample = state.results[0]?.password || els.auditInput.value || "";
  const score = nistScore(sample);
  const pct = Math.min(100, (score / 8) * 100);
  els.strengthBar.style.width = `${pct}%`;
  els.strengthBar.className = `strength-bar-fill ${BAR_CLASS[stats.strength] || ""}`;
  els.nistScore.textContent = `${score} / 8`;
}

function handleClearAll() {
  state.results = [];
  renderResults();
  renderStrength(null);
  els.copyAllBtn.disabled = true;
  els.downloadBtn.disabled = true;
  clearFormError();
  // Reset form to defaults
  els.lengthInput.value = 16;
  els.lengthSlider.value = 16;
  els.lengthReadout.textContent = "16";
  els.countInput.value = 1;
  els.categoryInputs.forEach((cb, i) => (cb.checked = i < 3));
  els.avoidAmbiguous.checked = false;
  updateEntropyReadout();
  toast("Cleared", "info");
}

/* -------------------------- Live entropy preview -------------------------- */
function updateEntropyReadout() {
  const length = parseInt(els.lengthInput.value, 10) || 0;
  const cats = els.categoryInputs.filter((cb) => cb.checked).map((cb) => cb.dataset.category);
  const avoid = els.avoidAmbiguous.checked;
  const pool = poolSize(cats, avoid);
  if (length < 1 || pool < 1) {
    els.entropyReadout.textContent = "— bits";
    return;
  }
  const e = calculateEntropy("x".repeat(length), pool);
  els.entropyReadout.textContent = `${e.toFixed(1)} bits`;
}

/* -------------------------- Auditor -------------------------- */
function handleAuditInput() {
  const pwd = els.auditInput.value;
  // Cancel any in-flight breach check; the result for the previous password
  // is meaningless against the new input and would be dropped by the staleness
  // check in handleBreachCheck anyway, but cancelling is cheaper and cleaner.
  if (state.breachBusy) abortBreach();
  els.breachBtn.disabled = pwd.length === 0;
  els.breachResult.hidden = true;

  els.auditFeedback.innerHTML = "";
  if (!pwd) {
    const li = document.createElement("li");
    li.className = "audit-empty";
    li.textContent = "Type a password above to see detailed feedback.";
    els.auditFeedback.appendChild(li);
    return;
  }
  const feedback = analyzePassword(pwd);
  for (const f of feedback) {
    const li = document.createElement("li");
    li.className = `audit-${f.type}`;
    li.textContent = f.message;
    els.auditFeedback.appendChild(li);
  }
  // Also show entropy & strength for the audited password
  const categories = ["uppercase", "lowercase", "numbers", "special"];
  const stats = passwordStats(pwd, categories);
  const li = document.createElement("li");
  li.className = "audit-positive";
  li.innerHTML = `Strength: <strong>${stats.strength}</strong> · Entropy: <strong>${stats.entropyBits} bits</strong> · Crack: <strong>${stats.crackTime}</strong>`;
  els.auditFeedback.appendChild(li);
}

async function handleBreachCheck() {
  const pwd = els.auditInput.value;
  if (!pwd || state.breachBusy) return;
  maybeShowBreachIntro();
  state.breachBusy = true;
  const originalLabel = els.breachBtn.innerHTML;
  els.breachBtn.innerHTML = '<span aria-hidden="true">⏳</span><span>Checking…</span>';
  els.breachBtn.disabled = true;
  els.breachResult.hidden = false;
  els.breachResult.innerHTML =
    '<span class="breach-badge breach-badge--pending">Checking HIBP…</span>';

  const { count, error } = await checkBreach(pwd);

  // If the input changed (or the box was cleared) while we were in flight,
  // abortBreach() already ran and the result is "Cancelled" — drop it.
  const current = els.auditInput.value;
  if (pwd !== current) {
    state.breachBusy = false;
    els.breachBtn.innerHTML = originalLabel;
    els.breachBtn.disabled = current.length === 0;
    return;
  }

  if (error && error !== "Cancelled") {
    els.breachResult.innerHTML =
      `<span class="breach-badge breach-badge--error">Network error</span>` +
      `<div class="breach-result-detail">${escapeHtml(error)}</div>`;
  } else if (count > 0) {
    const formatted = count.toLocaleString();
    const noun = count === 1 ? "breach" : "breaches";
    els.breachResult.innerHTML =
      `<span class="breach-badge breach-badge--breached">` +
      `Found in ${formatted} ${noun}</span>` +
      `<div class="breach-result-detail">` +
      `Checked SHA-1 prefix locally — only the first 5 hex chars leave your browser.` +
      `</div>`;
  } else if (error !== "Cancelled") {
    els.breachResult.innerHTML =
      `<span class="breach-badge breach-badge--clean">Not found in known breaches</span>` +
      `<div class="breach-result-detail">` +
      `Checked SHA-1 prefix locally — only the first 5 hex chars leave your browser.` +
      `</div>`;
  }

  state.breachBusy = false;
  els.breachBtn.innerHTML = originalLabel;
  els.breachBtn.disabled = current.length === 0;
}

function maybeShowBreachIntro() {
  // One-time privacy note. localStorage may be disabled (private mode); the
  // catch makes this a no-op rather than crashing the click handler.
  try {
    if (localStorage.getItem("spg.breach.introSeen") === "1") return;
    toast(
      "Heads up: the breach check sends only the first 5 hex chars of the SHA-1 hash, never your password.",
      "info",
      6000
    );
    localStorage.setItem("spg.breach.introSeen", "1");
  } catch {
    /* ignore */
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function handleAuditToggle() {
  const isHidden = els.auditInput.type === "password";
  els.auditInput.type = isHidden ? "text" : "password";
  els.auditToggle.setAttribute("aria-pressed", isHidden ? "true" : "false");
  els.auditToggle.textContent = isHidden ? "🙈" : "👁";
}

/* -------------------------- History -------------------------- */
function renderHistory() {
  els.historyList.innerHTML = "";
  if (state.history.length === 0) {
    const li = document.createElement("li");
    li.className = "results-empty";
    li.textContent = "No history yet. Save passwords from the results panel to start tracking them.";
    els.historyList.appendChild(li);
    return;
  }
  state.history.forEach((entry, idx) => {
    const li = document.createElement("li");
    li.className = "history-item";

    const valueWrap = document.createElement("div");
    const value = document.createElement("div");
    value.className = "history-value masked";
    value.textContent = entry.password;
    value.title = "Click to reveal / hide";
    value.style.cursor = "pointer";
    value.addEventListener("click", () => value.classList.toggle("masked"));

    const meta = document.createElement("div");
    meta.className = "history-meta";
    const date = new Date(entry.savedAt).toLocaleString();
    const stats = entry.stats || {};
    meta.innerHTML = `
      <span><strong>${date}</strong></span>
      <span>·</span>
      <span>Strength: <strong>${stats.strength || "—"}</strong></span>
      <span>·</span>
      <span>Entropy: <strong>${stats.entropyBits ?? "—"} bits</strong></span>
    `;
    valueWrap.append(value, meta);

    const actions = document.createElement("div");
    actions.className = "history-actions-row";
    const copyBtn = document.createElement("button");
    copyBtn.className = "icon-btn";
    copyBtn.type = "button";
    copyBtn.title = "Copy";
    copyBtn.setAttribute("aria-label", "Copy password");
    copyBtn.innerHTML = '<span aria-hidden="true">📋</span>';
    copyBtn.addEventListener("click", () => handleCopyOne(entry.password));
    const delBtn = document.createElement("button");
    delBtn.className = "icon-btn";
    delBtn.type = "button";
    delBtn.title = "Delete";
    delBtn.setAttribute("aria-label", "Delete history entry");
    delBtn.innerHTML = '<span aria-hidden="true">🗑</span>';
    delBtn.addEventListener("click", () => {
      state.history = removeEntry(idx);
      renderHistory();
    });
    actions.append(copyBtn, delBtn);

    li.append(valueWrap, actions);
    els.historyList.appendChild(li);
  });
}

async function handleClearHistory() {
  const ok = await confirmDialog({
    title: "Clear all history?",
    body: "This permanently removes every saved password from this browser. This cannot be undone.",
    confirmText: "Clear history",
  });
  if (!ok) return;
  state.history = clearHistory();
  renderHistory();
  toast("History cleared", "info");
}

async function handleImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const { imported, added, total } = await importJSON(file);
    state.history = loadHistory();
    renderHistory();
    toast(
      `Imported ${imported} entries (${added} new). History now has ${total} entries.`,
      "success"
    );
  } catch (err) {
    toast(`Import failed: ${err.message}`, "error");
  } finally {
    e.target.value = ""; // allow re-import of same file
  }
}

function handleExport() {
  if (state.history.length === 0) {
    toast("History is empty — nothing to export.", "warn");
    return;
  }
  // Pass the in-memory state through so the export always matches what the
  // user is currently seeing in the History list.
  exportJSON(state.history);
  toast("Exported history as JSON", "success");
}

/* -------------------------- API status -------------------------- */
async function checkApiStatus() {
  els.apiStatus.className = "api-status api-status--checking";
  els.apiStatus.querySelector(".api-label").textContent = "Checking API…";
  try {
    const res = await fetch("/api/health", { cache: "no-store" });
    if (!res.ok) throw new Error("not ok");
    const data = await res.json();
    if (data.status === "ok") {
      els.apiStatus.className = "api-status api-status--ok";
      els.apiStatus.querySelector(".api-label").textContent = "API online";
      return true;
    }
    throw new Error("unexpected response");
  } catch {
    els.apiStatus.className = "api-status api-status--down";
    els.apiStatus.querySelector(".api-label").textContent = "API offline (client mode)";
    return false;
  }
}

/* -------------------------- Wiring -------------------------- */
function wire() {
  // Form
  els.form.addEventListener("submit", handleGenerate);
  els.lengthSlider.addEventListener("input", () => {
    els.lengthInput.value = els.lengthSlider.value;
    els.lengthReadout.textContent = els.lengthSlider.value;
    updateEntropyReadout();
  });
  els.lengthInput.addEventListener("input", () => {
    const v = Math.max(4, Math.min(128, parseInt(els.lengthInput.value, 10) || 4));
    els.lengthSlider.value = v;
    els.lengthReadout.textContent = v;
    updateEntropyReadout();
  });
  els.categoryInputs.forEach((cb) => cb.addEventListener("change", updateEntropyReadout));
  els.avoidAmbiguous.addEventListener("change", updateEntropyReadout);

  els.copyAllBtn.addEventListener("click", handleCopyAll);
  els.downloadBtn.addEventListener("click", handleDownload);
  els.clearBtn.addEventListener("click", (e) => {
    e.preventDefault();
    handleClearAll();
  });

  // Auditor
  els.auditInput.addEventListener("input", handleAuditInput);
  els.auditToggle.addEventListener("click", handleAuditToggle);
  els.breachBtn.addEventListener("click", handleBreachCheck);

  // History
  els.exportBtn.addEventListener("click", handleExport);
  els.importBtn.addEventListener("click", () => els.importInput.click());
  els.importInput.addEventListener("change", handleImport);
  els.clearHistoryBtn.addEventListener("click", handleClearHistory);

  // Keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea")) return;
    if (e.key === "g" || e.key === "G") {
      e.preventDefault();
      handleGenerate();
    } else if (e.key === "c" || e.key === "C") {
      if (state.results[0]) handleCopyOne(state.results[0].password);
    } else if (e.key === "?") {
      toast("G: generate · C: copy first · ?: this hint", "info", 5000);
    }
  });

  // Auto-blur when tab hidden for >30s (defense-in-depth for kiosk demos)
  let hideTimer = null;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      hideTimer = setTimeout(() => {
        // Clear visible passwords from DOM
        state.results = [];
        renderResults();
        renderStrength(null);
        els.copyAllBtn.disabled = true;
        els.downloadBtn.disabled = true;
      }, 30_000);
    } else {
      clearTimeout(hideTimer);
    }
  });
}

export function init() {
  wire();
  renderResults();
  renderHistory();
  renderStrength(null);
  updateEntropyReadout();
  checkApiStatus();
  // The template still ships the older "offline stub" label; rewrite it now
  // that the breach module is real. No-op if the button isn't present.
  if (els.breachBtn) {
    els.breachBtn.innerHTML =
      '<span aria-hidden="true">🔒</span><span>Check breach status</span>';
  }
  // Expose state for the bootstrap
  window.__spg = state;
}
