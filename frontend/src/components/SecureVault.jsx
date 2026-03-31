import { useState, useEffect, useCallback, useRef } from "react";

// ─── Crypto Utilities (Web Crypto API) ───────────────────────────────────────

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex
    ? hexToBytes(saltHex)
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  return {
    hash: bytesToHex(new Uint8Array(bits)),
    salt: bytesToHex(salt),
  };
}

async function encryptData(plaintext, masterPassword) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(masterPassword, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext),
  );
  return {
    ciphertext: bytesToHex(new Uint8Array(encrypted)),
    iv: bytesToHex(iv),
    salt: bytesToHex(salt),
  };
}

async function decryptData(ciphertext, iv, salt, masterPassword) {
  const key = await deriveKey(masterPassword, hexToBytes(salt));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(iv) },
    key,
    hexToBytes(ciphertext),
  );
  return new TextDecoder().decode(decrypted);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  return arr;
}

// ─── Password Strength Analyzer ──────────────────────────────────────────────

function analyzeStrength(pw) {
  if (!pw) return { score: 0, label: "Empty", color: "#444", checks: [] };
  const checks = [
    { label: "8+ characters", pass: pw.length >= 8 },
    { label: "12+ characters", pass: pw.length >= 12 },
    { label: "Uppercase letter", pass: /[A-Z]/.test(pw) },
    { label: "Lowercase letter", pass: /[a-z]/.test(pw) },
    { label: "Number", pass: /[0-9]/.test(pw) },
    { label: "Special character", pass: /[^A-Za-z0-9]/.test(pw) },
    {
      label: "No common patterns",
      pass: !/^(password|123456|qwerty|abc123)/i.test(pw),
    },
  ];
  const score = checks.filter((c) => c.pass).length;
  const labels = [
    "",
    "Very Weak",
    "Weak",
    "Fair",
    "Good",
    "Strong",
    "Very Strong",
    "Excellent",
  ];
  const colors = [
    "#444",
    "#ef4444",
    "#f97316",
    "#eab308",
    "#84cc16",
    "#22c55e",
    "#10b981",
    "#06b6d4",
  ];
  return {
    score,
    label: labels[score] || "Excellent",
    color: colors[Math.min(score, 7)],
    checks,
  };
}

// ─── Password Generator ───────────────────────────────────────────────────────

function generatePassword(opts = {}) {
  const {
    length = 16,
    upper = true,
    lower = true,
    numbers = true,
    symbols = true,
  } = opts;
  let chars = "";
  if (upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lower) chars += "abcdefghijklmnopqrstuvwxyz";
  if (numbers) chars += "0123456789";
  if (symbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
  if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((n) => chars[n % chars.length])
    .join("");
}

// ─── Storage Helpers ──────────────────────────────────────────────────────────

const STORE_KEY = "sv_vault";
const LOGS_KEY = "sv_logs";

function loadVault() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY) || "null");
  } catch {
    return null;
  }
}
function saveVault(v) {
  localStorage.setItem(STORE_KEY, JSON.stringify(v));
}
function loadLogs() {
  try {
    return JSON.parse(localStorage.getItem(LOGS_KEY) || "[]");
  } catch {
    return [];
  }
}
function saveLogs(l) {
  localStorage.setItem(LOGS_KEY, JSON.stringify(l.slice(-100)));
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [screen, setScreen] = useState("splash"); // splash | setup | login | vault
  const [masterPassword, setMasterPassword] = useState("");
  const [vaultMeta, setVaultMeta] = useState(null);
  const [entries, setEntries] = useState([]); // decrypted in-memory
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState("passwords");
  const [showAdd, setShowAdd] = useState(false);
  const [editEntry, setEditEntry] = useState(null);
  const [viewEntry, setViewEntry] = useState(null);
  const [searchQ, setSearchQ] = useState("");
  const [toast, setToast] = useState(null);
  const [loading, setLoading] = useState(false);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [locked, setLocked] = useState(false);
  const lockTimer = useRef(null);
  const [genOpts, setGenOpts] = useState({
    length: 16,
    upper: true,
    lower: true,
    numbers: true,
    symbols: true,
  });
  const [generatedPw, setGeneratedPw] = useState("");

  const addLog = useCallback((msg, type = "info") => {
    const entry = { msg, type, time: new Date().toISOString() };
    setLogs((prev) => {
      const next = [entry, ...prev].slice(0, 100);
      saveLogs(next);
      return next;
    });
  }, []);

  const showToast = useCallback((msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // Auto-lock after 5 minutes of inactivity
  const resetLockTimer = useCallback(() => {
    if (lockTimer.current) clearTimeout(lockTimer.current);
    lockTimer.current = setTimeout(
      () => {
        if (screen === "vault") {
          setScreen("login");
          setEntries([]);
          setMasterPassword("");
          addLog("Session auto-locked after inactivity", "warning");
          showToast("Session locked due to inactivity", "warning");
        }
      },
      5 * 60 * 1000,
    );
  }, [screen, addLog, showToast]);

  useEffect(() => {
    document.addEventListener("mousemove", resetLockTimer);
    document.addEventListener("keydown", resetLockTimer);
    return () => {
      document.removeEventListener("mousemove", resetLockTimer);
      document.removeEventListener("keydown", resetLockTimer);
    };
  }, [resetLockTimer]);

  useEffect(() => {
    const vault = loadVault();
    const savedLogs = loadLogs();
    setLogs(savedLogs);
    if (vault) {
      setVaultMeta(vault);
      setTimeout(() => setScreen("login"), 1200);
    } else {
      setTimeout(() => setScreen("setup"), 1200);
    }
  }, []);

  // ─── Setup master password ────────────────────────────────────────────────
  const [setupPw, setSetupPw] = useState("");
  const [setupConfirm, setSetupConfirm] = useState("");

  const handleSetup = async () => {
    if (setupPw.length < 8)
      return showToast("Master password must be 8+ chars", "error");
    if (setupPw !== setupConfirm)
      return showToast("Passwords do not match", "error");
    setLoading(true);
    try {
      const { hash, salt } = await hashPassword(setupPw);
      const vault = {
        hash,
        salt,
        entries: [],
        created: new Date().toISOString(),
      };
      saveVault(vault);
      setVaultMeta(vault);
      addLog("Vault created successfully", "success");
      showToast("Vault created! Please log in.");
      setScreen("login");
    } catch (e) {
      showToast("Setup failed: " + e.message, "error");
    }
    setLoading(false);
  };

  // ─── Login ────────────────────────────────────────────────────────────────
  const [loginPw, setLoginPw] = useState("");

  const handleLogin = async () => {
    if (locked) return showToast("Account locked. Wait 30 seconds.", "error");
    setLoading(true);
    try {
      const vault = loadVault();
      const { hash } = await hashPassword(loginPw, vault.salt);
      if (hash !== vault.hash) {
        const attempts = failedAttempts + 1;
        setFailedAttempts(attempts);
        addLog(`Failed login attempt #${attempts}`, "alert");
        if (attempts >= 5) {
          setLocked(true);
          addLog("Account temporarily locked after 5 failed attempts", "alert");
          showToast("Too many attempts! Locked for 30s", "error");
          setTimeout(() => {
            setLocked(false);
            setFailedAttempts(0);
          }, 30000);
        } else {
          showToast(
            `Invalid password. ${5 - attempts} attempts left.`,
            "error",
          );
        }
        setLoading(false);
        return;
      }
      // Decrypt all entries
      const decrypted = [];
      for (const e of vault.entries || []) {
        const pw = await decryptData(e.ciphertext, e.iv, e.salt, loginPw);
        decrypted.push({ ...e, password: pw });
      }
      setEntries(decrypted);
      setMasterPassword(loginPw);
      setFailedAttempts(0);
      addLog("Successful login", "success");
      setScreen("vault");
      resetLockTimer();
    } catch (e) {
      showToast("Login error: " + e.message, "error");
    }
    setLoading(false);
    setLoginPw("");
  };

  // ─── Save entry ───────────────────────────────────────────────────────────
  const handleSaveEntry = async (form) => {
    setLoading(true);
    try {
      const encrypted = await encryptData(form.password, masterPassword);
      const vault = loadVault();
      const newEntry = {
        id: editEntry?.id || crypto.randomUUID(),
        title: form.title,
        username: form.username,
        url: form.url,
        notes: form.notes,
        category: form.category,
        ...encrypted,
        created: editEntry?.created || new Date().toISOString(),
        modified: new Date().toISOString(),
      };
      let updatedEntries;
      if (editEntry) {
        updatedEntries = vault.entries.map((e) =>
          e.id === editEntry.id ? newEntry : e,
        );
        addLog(`Updated entry: ${form.title}`, "info");
      } else {
        updatedEntries = [...(vault.entries || []), newEntry];
        addLog(`Added new entry: ${form.title}`, "info");
      }
      vault.entries = updatedEntries;
      saveVault(vault);
      const decryptedEntries = updatedEntries.map((e) => {
        const found = entries.find((d) => d.id === e.id);
        if (e.id === newEntry.id)
          return { ...newEntry, password: form.password };
        return found || e;
      });
      setEntries(decryptedEntries);
      showToast(editEntry ? "Entry updated!" : "Entry saved securely!");
      setShowAdd(false);
      setEditEntry(null);
    } catch (e) {
      showToast("Save failed: " + e.message, "error");
    }
    setLoading(false);
  };

  // ─── Delete entry ─────────────────────────────────────────────────────────
  const handleDelete = (id, title) => {
    const vault = loadVault();
    vault.entries = vault.entries.filter((e) => e.id !== id);
    saveVault(vault);
    setEntries((prev) => prev.filter((e) => e.id !== id));
    addLog(`Deleted entry: ${title}`, "warning");
    showToast("Entry deleted", "warning");
    setViewEntry(null);
  };

  // ─── Filtered entries ─────────────────────────────────────────────────────
  const filtered = entries.filter(
    (e) =>
      !searchQ ||
      e.title?.toLowerCase().includes(searchQ.toLowerCase()) ||
      e.username?.toLowerCase().includes(searchQ.toLowerCase()) ||
      e.url?.toLowerCase().includes(searchQ.toLowerCase()),
  );

  const categories = [
    "All",
    ...new Set(entries.map((e) => e.category || "General")),
  ];

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div style={styles.root}>
      <style>{css}</style>
      {toast && <Toast msg={toast.msg} type={toast.type} />}

      {screen === "splash" && <Splash />}
      {screen === "setup" && (
        <SetupScreen
          setupPw={setupPw}
          setSetupPw={setSetupPw}
          setupConfirm={setupConfirm}
          setSetupConfirm={setSetupConfirm}
          onSetup={handleSetup}
          loading={loading}
        />
      )}
      {screen === "login" && (
        <LoginScreen
          loginPw={loginPw}
          setLoginPw={setLoginPw}
          onLogin={handleLogin}
          loading={loading}
          locked={locked}
          failedAttempts={failedAttempts}
        />
      )}
      {screen === "vault" && (
        <VaultScreen
          entries={filtered}
          allEntries={entries}
          logs={logs}
          searchQ={searchQ}
          setSearchQ={setSearchQ}
          categories={categories}
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          onAdd={() => {
            setEditEntry(null);
            setShowAdd(true);
          }}
          onEdit={(e) => {
            setEditEntry(e);
            setShowAdd(true);
          }}
          onView={setViewEntry}
          onLock={() => {
            setScreen("login");
            setEntries([]);
            setMasterPassword("");
            addLog("Manual lock", "info");
          }}
          genOpts={genOpts}
          setGenOpts={setGenOpts}
          generatedPw={generatedPw}
          setGeneratedPw={setGeneratedPw}
          showToast={showToast}
        />
      )}

      {showAdd && (
        <EntryModal
          entry={editEntry}
          onSave={handleSaveEntry}
          onClose={() => {
            setShowAdd(false);
            setEditEntry(null);
          }}
          loading={loading}
          showToast={showToast}
        />
      )}
      {viewEntry && (
        <ViewModal
          entry={viewEntry}
          onClose={() => setViewEntry(null)}
          onEdit={() => {
            setEditEntry(viewEntry);
            setViewEntry(null);
            setShowAdd(true);
          }}
          onDelete={() => handleDelete(viewEntry.id, viewEntry.title)}
          showToast={showToast}
        />
      )}
    </div>
  );
}

// ─── Splash ───────────────────────────────────────────────────────────────────

function Splash() {
  return (
    <div style={styles.splash}>
      <div className="splash-icon">🔐</div>
      <h1 style={styles.splashTitle}>SecureVault</h1>
      <p style={styles.splashSub}>Initializing encryption engine…</p>
      <div className="spinner" />
    </div>
  );
}

// ─── Setup Screen ─────────────────────────────────────────────────────────────

function SetupScreen({
  setupPw,
  setSetupPw,
  setupConfirm,
  setSetupConfirm,
  onSetup,
  loading,
}) {
  const str = analyzeStrength(setupPw);
  return (
    <div style={styles.authWrap}>
      <div style={styles.authCard}>
        <div style={styles.authLogo}>🔐</div>
        <h2 style={styles.authTitle}>Create Your Vault</h2>
        <p style={styles.authSub}>
          Your master password encrypts everything. It cannot be recovered.
        </p>
        <label style={styles.label}>Master Password</label>
        <input
          style={styles.input}
          type="password"
          placeholder="Choose a strong password"
          value={setupPw}
          onChange={(e) => setSetupPw(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onSetup()}
        />
        {setupPw && (
          <div style={styles.strengthBar}>
            <div
              style={{
                ...styles.strengthFill,
                width: `${(str.score / 7) * 100}%`,
                background: str.color,
              }}
            />
          </div>
        )}
        {setupPw && (
          <p style={{ color: str.color, fontSize: 12, marginBottom: 8 }}>
            {str.label}
          </p>
        )}
        <label style={styles.label}>Confirm Password</label>
        <input
          style={styles.input}
          type="password"
          placeholder="Repeat master password"
          value={setupConfirm}
          onChange={(e) => setSetupConfirm(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onSetup()}
        />
        <button
          style={styles.btn}
          onClick={onSetup}
          disabled={loading}
          className="btn-primary"
        >
          {loading ? "Creating vault…" : "Create Vault"}
        </button>
        <div style={styles.secNote}>
          🔒 AES-256-GCM encryption · PBKDF2 key derivation · 310,000 iterations
        </div>
      </div>
    </div>
  );
}

// ─── Login Screen ─────────────────────────────────────────────────────────────

function LoginScreen({
  loginPw,
  setLoginPw,
  onLogin,
  loading,
  locked,
  failedAttempts,
}) {
  return (
    <div style={styles.authWrap}>
      <div style={styles.authCard}>
        <div style={styles.authLogo}>🔐</div>
        <h2 style={styles.authTitle}>Unlock Vault</h2>
        <p style={styles.authSub}>
          Enter your master password to access your credentials.
        </p>
        {failedAttempts > 0 && (
          <div style={styles.alertBanner}>
            ⚠️ {failedAttempts} failed attempt{failedAttempts > 1 ? "s" : ""}
            {locked
              ? " — Account locked for 30 seconds"
              : ` — ${5 - failedAttempts} remaining`}
          </div>
        )}
        <label style={styles.label}>Master Password</label>
        <input
          style={styles.input}
          type="password"
          placeholder="Enter master password"
          value={loginPw}
          onChange={(e) => setLoginPw(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onLogin()}
          disabled={locked}
        />
        <button
          style={styles.btn}
          onClick={onLogin}
          disabled={loading || locked}
          className="btn-primary"
        >
          {locked ? "🔒 Locked" : loading ? "Verifying…" : "Unlock"}
        </button>
        <div style={styles.secNote}>
          🛡️ PBKDF2-SHA256 · Brute-force protection · Auto-lock enabled
        </div>
      </div>
    </div>
  );
}

// ─── Vault Screen ─────────────────────────────────────────────────────────────

function VaultScreen({
  entries,
  allEntries,
  logs,
  searchQ,
  setSearchQ,
  categories,
  activeTab,
  setActiveTab,
  onAdd,
  onEdit,
  onView,
  onLock,
  genOpts,
  setGenOpts,
  generatedPw,
  setGeneratedPw,
  showToast,
}) {
  const [selCat, setSelCat] = useState("All");
  const filteredByCat =
    selCat === "All"
      ? entries
      : entries.filter((e) => (e.category || "General") === selCat);

  return (
    <div style={styles.vaultRoot}>
      {/* Sidebar */}
      <div style={styles.sidebar}>
        <div style={styles.sidebarLogo}>
          🔐 <span>SecureVault</span>
        </div>
        <nav style={styles.sideNav}>
          {[
            { id: "passwords", icon: "🔑", label: "Passwords" },
            { id: "generator", icon: "⚡", label: "Generator" },
            { id: "logs", icon: "📋", label: "Activity" },
          ].map((t) => (
            <button
              key={t.id}
              style={{
                ...styles.navBtn,
                ...(activeTab === t.id ? styles.navBtnActive : {}),
              }}
              onClick={() => setActiveTab(t.id)}
              className="nav-btn"
            >
              <span>{t.icon}</span> {t.label}
            </button>
          ))}
        </nav>
        <div style={styles.sideStats}>
          <div style={styles.statBox}>
            <span style={styles.statNum}>{allEntries.length}</span>
            <span style={styles.statLabel}>Stored</span>
          </div>
          <div style={styles.statBox}>
            <span style={styles.statNum}>
              {
                allEntries.filter((e) => analyzeStrength(e.password).score <= 3)
                  .length
              }
            </span>
            <span style={styles.statLabel}>Weak</span>
          </div>
        </div>
        <button style={styles.lockBtn} onClick={onLock} className="lock-btn">
          🔒 Lock Vault
        </button>
      </div>

      {/* Main */}
      <div style={styles.main}>
        {activeTab === "passwords" && (
          <>
            <div style={styles.topBar}>
              <div>
                <h2 style={styles.pageTitle}>Password Vault</h2>
                <p style={styles.pageSub}>
                  {allEntries.length} credentials stored
                </p>
              </div>
              <button
                style={styles.addBtn}
                onClick={onAdd}
                className="btn-primary"
              >
                + Add New
              </button>
            </div>
            <div style={styles.searchRow}>
              <input
                style={styles.searchInput}
                placeholder="🔍  Search entries…"
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
              />
              <div style={styles.catRow}>
                {categories.map((c) => (
                  <button
                    key={c}
                    style={{
                      ...styles.catBtn,
                      ...(selCat === c ? styles.catBtnActive : {}),
                    }}
                    onClick={() => setSelCat(c)}
                    className="cat-btn"
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>
            {filteredByCat.length === 0 ? (
              <div style={styles.empty}>
                <div style={styles.emptyIcon}>🗝️</div>
                <p>No entries found. Add your first password!</p>
              </div>
            ) : (
              <div style={styles.grid}>
                {filteredByCat.map((e) => (
                  <EntryCard
                    key={e.id}
                    entry={e}
                    onView={onView}
                    showToast={showToast}
                  />
                ))}
              </div>
            )}
          </>
        )}

        {activeTab === "generator" && (
          <GeneratorPanel
            genOpts={genOpts}
            setGenOpts={setGenOpts}
            generatedPw={generatedPw}
            setGeneratedPw={setGeneratedPw}
            showToast={showToast}
          />
        )}

        {activeTab === "logs" && <LogsPanel logs={logs} />}
      </div>
    </div>
  );
}

// ─── Entry Card ───────────────────────────────────────────────────────────────

function EntryCard({ entry, onView, showToast }) {
  const str = analyzeStrength(entry.password);
  const favicon = entry.url
    ? `https://www.google.com/s2/favicons?sz=32&domain=${entry.url}`
    : null;
  return (
    <div
      style={styles.card}
      onClick={() => onView(entry)}
      className="entry-card"
    >
      <div style={styles.cardTop}>
        <div style={styles.cardIcon}>
          {favicon ? (
            <img
              src={favicon}
              style={{ width: 24, height: 24 }}
              onError={(e) => (e.target.style.display = "none")}
            />
          ) : (
            "🔑"
          )}
        </div>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <div style={styles.cardTitle}>{entry.title}</div>
          <div style={styles.cardUser}>{entry.username}</div>
        </div>
        <div
          style={{ ...styles.strengthDot, background: str.color }}
          title={str.label}
        />
      </div>
      <div style={styles.cardFooter}>
        <span style={styles.catTag}>{entry.category || "General"}</span>
        <button
          style={styles.copyBtn}
          onClick={(e) => {
            e.stopPropagation();
            navigator.clipboard.writeText(entry.password);
            showToast("Password copied!");
          }}
          className="copy-btn"
        >
          📋 Copy
        </button>
      </div>
    </div>
  );
}

// ─── Entry Modal (Add/Edit) ───────────────────────────────────────────────────

function EntryModal({ entry, onSave, onClose, loading, showToast }) {
  const [form, setForm] = useState({
    title: entry?.title || "",
    username: entry?.username || "",
    password: entry?.password || "",
    url: entry?.url || "",
    notes: entry?.notes || "",
    category: entry?.category || "General",
  });
  const [showPw, setShowPw] = useState(false);
  const str = analyzeStrength(form.password);

  const genAndFill = () => {
    const pw = generatePassword({
      length: 16,
      upper: true,
      lower: true,
      numbers: true,
      symbols: true,
    });
    setForm((f) => ({ ...f, password: pw }));
    showToast("Strong password generated!");
  };

  return (
    <div
      style={styles.overlay}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div style={styles.modal}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>
            {entry ? "Edit Entry" : "Add New Entry"}
          </h3>
          <button style={styles.closeBtn} onClick={onClose}>
            ✕
          </button>
        </div>
        <div style={styles.modalBody}>
          {[
            { label: "Title *", key: "title", placeholder: "e.g. Gmail" },
            {
              label: "Username / Email *",
              key: "username",
              placeholder: "user@example.com",
            },
            {
              label: "Website URL",
              key: "url",
              placeholder: "https://example.com",
            },
            { label: "Category", key: "category", placeholder: "General" },
          ].map((f) => (
            <div key={f.key} style={styles.formGroup}>
              <label style={styles.label}>{f.label}</label>
              <input
                style={styles.input}
                placeholder={f.placeholder}
                value={form[f.key]}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, [f.key]: e.target.value }))
                }
              />
            </div>
          ))}
          <div style={styles.formGroup}>
            <label style={styles.label}>Password *</label>
            <div style={styles.pwRow}>
              <input
                style={{ ...styles.input, flex: 1, marginBottom: 0 }}
                type={showPw ? "text" : "password"}
                placeholder="Enter or generate password"
                value={form.password}
                onChange={(e) =>
                  setForm((f) => ({ ...f, password: e.target.value }))
                }
              />
              <button
                style={styles.iconBtn}
                onClick={() => setShowPw((v) => !v)}
                title="Toggle visibility"
              >
                {showPw ? "🙈" : "👁️"}
              </button>
              <button
                style={styles.iconBtn}
                onClick={genAndFill}
                title="Generate strong password"
              >
                ⚡
              </button>
            </div>
            {form.password && (
              <>
                <div style={styles.strengthBar}>
                  <div
                    style={{
                      ...styles.strengthFill,
                      width: `${(str.score / 7) * 100}%`,
                      background: str.color,
                    }}
                  />
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: 8,
                    flexWrap: "wrap",
                    marginTop: 6,
                  }}
                >
                  {str.checks.map((c) => (
                    <span
                      key={c.label}
                      style={{
                        fontSize: 11,
                        color: c.pass ? "#22c55e" : "#666",
                      }}
                    >
                      {c.pass ? "✓" : "✗"} {c.label}
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
          <div style={styles.formGroup}>
            <label style={styles.label}>Notes</label>
            <textarea
              style={styles.textarea}
              placeholder="Optional notes…"
              value={form.notes}
              onChange={(e) =>
                setForm((f) => ({ ...f, notes: e.target.value }))
              }
            />
          </div>
        </div>
        <div style={styles.modalFooter}>
          <button style={styles.btnSecondary} onClick={onClose}>
            Cancel
          </button>
          <button
            style={styles.btn}
            onClick={() => {
              if (!form.title || !form.username || !form.password)
                return showToast("Fill required fields", "error");
              onSave(form);
            }}
            disabled={loading}
            className="btn-primary"
          >
            {loading ? "Encrypting…" : "Save Securely 🔒"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── View Modal ───────────────────────────────────────────────────────────────

function ViewModal({ entry, onClose, onEdit, onDelete, showToast }) {
  const [showPw, setShowPw] = useState(false);
  const str = analyzeStrength(entry.password);
  return (
    <div
      style={styles.overlay}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div style={styles.modal}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>{entry.title}</h3>
          <button style={styles.closeBtn} onClick={onClose}>
            ✕
          </button>
        </div>
        <div style={styles.modalBody}>
          <InfoRow
            label="Username"
            value={entry.username}
            copy
            showToast={showToast}
          />
          <div style={styles.formGroup}>
            <label style={styles.label}>Password</label>
            <div style={styles.pwRow}>
              <input
                style={{ ...styles.input, flex: 1, marginBottom: 0 }}
                type={showPw ? "text" : "password"}
                value={entry.password}
                readOnly
              />
              <button
                style={styles.iconBtn}
                onClick={() => setShowPw((v) => !v)}
              >
                {showPw ? "🙈" : "👁️"}
              </button>
              <button
                style={styles.iconBtn}
                onClick={() => {
                  navigator.clipboard.writeText(entry.password);
                  showToast("Password copied!");
                }}
              >
                📋
              </button>
            </div>
            <div style={{ ...styles.strengthBar, marginTop: 8 }}>
              <div
                style={{
                  ...styles.strengthFill,
                  width: `${(str.score / 7) * 100}%`,
                  background: str.color,
                }}
              />
            </div>
            <p style={{ fontSize: 12, color: str.color, margin: "4px 0 0" }}>
              Strength: {str.label}
            </p>
          </div>
          {entry.url && (
            <InfoRow label="URL" value={entry.url} showToast={showToast} />
          )}
          {entry.notes && (
            <InfoRow label="Notes" value={entry.notes} showToast={showToast} />
          )}
          <InfoRow
            label="Category"
            value={entry.category || "General"}
            showToast={showToast}
          />
          <InfoRow
            label="Last Modified"
            value={new Date(entry.modified).toLocaleString()}
            showToast={showToast}
          />
          <div style={styles.encNote}>
            🔒 Encrypted with AES-256-GCM · Unique IV &amp; salt per entry
          </div>
        </div>
        <div style={styles.modalFooter}>
          <button
            style={{
              ...styles.btnSecondary,
              color: "#ef4444",
              borderColor: "#ef444440",
            }}
            onClick={() => {
              if (confirm("Delete this entry?")) onDelete();
            }}
          >
            🗑️ Delete
          </button>
          <button style={styles.btnSecondary} onClick={onEdit}>
            ✏️ Edit
          </button>
          <button style={styles.btn} onClick={onClose} className="btn-primary">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value, copy, showToast }) {
  return (
    <div style={styles.formGroup}>
      <label style={styles.label}>{label}</label>
      <div style={styles.infoRow}>
        <span style={styles.infoVal}>{value}</span>
        {copy && (
          <button
            style={styles.iconBtn}
            onClick={() => {
              navigator.clipboard.writeText(value);
              showToast(`${label} copied!`);
            }}
          >
            📋
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Generator Panel ──────────────────────────────────────────────────────────

function GeneratorPanel({
  genOpts,
  setGenOpts,
  generatedPw,
  setGeneratedPw,
  showToast,
}) {
  const generate = () => setGeneratedPw(generatePassword(genOpts));
  const str = analyzeStrength(generatedPw);

  return (
    <div style={styles.genPanel}>
      <div style={styles.topBar}>
        <div>
          <h2 style={styles.pageTitle}>Password Generator</h2>
          <p style={styles.pageSub}>
            Generate cryptographically secure passwords
          </p>
        </div>
      </div>
      <div style={styles.genCard}>
        <div style={styles.genOutput}>
          <span style={styles.genPw}>{generatedPw || "Click Generate →"}</span>
          {generatedPw && (
            <button
              style={styles.iconBtn}
              onClick={() => {
                navigator.clipboard.writeText(generatedPw);
                showToast("Copied!");
              }}
            >
              📋
            </button>
          )}
        </div>
        {generatedPw && (
          <>
            <div style={styles.strengthBar}>
              <div
                style={{
                  ...styles.strengthFill,
                  width: `${(str.score / 7) * 100}%`,
                  background: str.color,
                }}
              />
            </div>
            <p style={{ color: str.color, fontSize: 13, margin: "4px 0 0" }}>
              Strength: {str.label}
            </p>
          </>
        )}
        <div style={styles.genOpts}>
          <div style={styles.sliderRow}>
            <label style={styles.label}>Length: {genOpts.length}</label>
            <input
              type="range"
              min={8}
              max={64}
              value={genOpts.length}
              onChange={(e) =>
                setGenOpts((o) => ({ ...o, length: +e.target.value }))
              }
              style={styles.slider}
            />
          </div>
          {[
            { key: "upper", label: "Uppercase (A-Z)" },
            { key: "lower", label: "Lowercase (a-z)" },
            { key: "numbers", label: "Numbers (0-9)" },
            { key: "symbols", label: "Symbols (!@#…)" },
          ].map((opt) => (
            <label key={opt.key} style={styles.checkRow}>
              <input
                type="checkbox"
                checked={genOpts[opt.key]}
                onChange={(e) =>
                  setGenOpts((o) => ({ ...o, [opt.key]: e.target.checked }))
                }
                style={{ accentColor: "#00d4ff" }}
              />
              {opt.label}
            </label>
          ))}
        </div>
        <button
          style={{ ...styles.btn, width: "100%" }}
          onClick={generate}
          className="btn-primary"
        >
          ⚡ Generate Password
        </button>
      </div>
    </div>
  );
}

// ─── Logs Panel ───────────────────────────────────────────────────────────────

function LogsPanel({ logs }) {
  const typeIcon = { success: "✅", info: "ℹ️", warning: "⚠️", alert: "🚨" };
  return (
    <div>
      <div style={styles.topBar}>
        <div>
          <h2 style={styles.pageTitle}>Activity Log</h2>
          <p style={styles.pageSub}>{logs.length} security events recorded</p>
        </div>
      </div>
      {logs.length === 0 ? (
        <div style={styles.empty}>
          <div style={styles.emptyIcon}>📋</div>
          <p>No activity yet.</p>
        </div>
      ) : (
        <div style={styles.logList}>
          {logs.map((l, i) => (
            <div
              key={i}
              style={{
                ...styles.logItem,
                borderLeft: `3px solid ${l.type === "alert" ? "#ef4444" : l.type === "warning" ? "#f97316" : l.type === "success" ? "#22c55e" : "#555"}`,
              }}
            >
              <span style={styles.logIcon}>{typeIcon[l.type] || "ℹ️"}</span>
              <span style={styles.logMsg}>{l.msg}</span>
              <span style={styles.logTime}>
                {new Date(l.time).toLocaleTimeString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ msg, type }) {
  const bg =
    type === "error" ? "#ef4444" : type === "warning" ? "#f97316" : "#22c55e";
  return <div style={{ ...styles.toast, background: bg }}>{msg}</div>;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const C = {
  bg: "#0a0a0f",
  surface: "#11111a",
  card: "#16161f",
  border: "#1e1e2e",
  accent: "#00d4ff",
  accentDim: "#00d4ff20",
  text: "#e8e8f0",
  muted: "#6b6b85",
  danger: "#ef4444",
};

const styles = {
  root: {
    fontFamily: "'Syne', 'Space Grotesk', monospace",
    background: C.bg,
    minHeight: "100vh",
    color: C.text,
  },
  splash: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    height: "100vh",
    gap: 16,
  },
  splashTitle: {
    fontSize: 36,
    fontWeight: 800,
    letterSpacing: "-1px",
    color: C.accent,
    margin: 0,
  },
  splashSub: { color: C.muted, fontSize: 14 },
  authWrap: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    padding: 20,
  },
  authCard: {
    background: C.surface,
    border: `1px solid ${C.border}`,
    borderRadius: 16,
    padding: 40,
    width: "100%",
    maxWidth: 440,
    display: "flex",
    flexDirection: "column",
  },
  authLogo: { fontSize: 40, textAlign: "center", marginBottom: 8 },
  authTitle: {
    fontSize: 26,
    fontWeight: 800,
    textAlign: "center",
    margin: "0 0 8px",
    color: C.text,
  },
  authSub: {
    color: C.muted,
    textAlign: "center",
    fontSize: 13,
    marginBottom: 24,
  },
  label: {
    fontSize: 12,
    color: C.muted,
    fontWeight: 600,
    letterSpacing: "0.5px",
    textTransform: "uppercase",
    display: "block",
    marginBottom: 6,
  },
  input: {
    background: "#0d0d18",
    border: `1px solid ${C.border}`,
    borderRadius: 8,
    color: C.text,
    padding: "10px 14px",
    fontSize: 14,
    width: "100%",
    boxSizing: "border-box",
    outline: "none",
    marginBottom: 16,
  },
  btn: {
    background: C.accent,
    color: "#000",
    border: "none",
    borderRadius: 8,
    padding: "12px 20px",
    fontSize: 14,
    fontWeight: 700,
    cursor: "pointer",
    width: "100%",
  },
  btnSecondary: {
    background: "transparent",
    color: C.text,
    border: `1px solid ${C.border}`,
    borderRadius: 8,
    padding: "10px 16px",
    fontSize: 13,
    cursor: "pointer",
  },
  secNote: { color: C.muted, fontSize: 11, textAlign: "center", marginTop: 16 },
  strengthBar: {
    height: 4,
    background: C.border,
    borderRadius: 2,
    overflow: "hidden",
    marginBottom: 4,
  },
  strengthFill: { height: "100%", transition: "width 0.3s, background 0.3s" },
  alertBanner: {
    background: "#ef444415",
    border: "1px solid #ef444430",
    color: "#fca5a5",
    borderRadius: 8,
    padding: "10px 14px",
    fontSize: 13,
    marginBottom: 16,
  },
  vaultRoot: { display: "flex", height: "100vh", overflow: "hidden" },
  sidebar: {
    width: 220,
    background: C.surface,
    borderRight: `1px solid ${C.border}`,
    display: "flex",
    flexDirection: "column",
    padding: 20,
    gap: 8,
  },
  sidebarLogo: {
    fontSize: 16,
    fontWeight: 800,
    color: C.accent,
    display: "flex",
    gap: 8,
    alignItems: "center",
    marginBottom: 16,
  },
  sideNav: { display: "flex", flexDirection: "column", gap: 4, flex: 1 },
  navBtn: {
    background: "transparent",
    border: "none",
    color: C.muted,
    textAlign: "left",
    padding: "10px 12px",
    borderRadius: 8,
    cursor: "pointer",
    fontSize: 13,
    fontWeight: 600,
    display: "flex",
    gap: 10,
    alignItems: "center",
  },
  navBtnActive: { background: C.accentDim, color: C.accent },
  sideStats: { display: "flex", gap: 8, marginBottom: 8 },
  statBox: {
    flex: 1,
    background: C.card,
    borderRadius: 8,
    padding: "10px 8px",
    textAlign: "center",
  },
  statNum: { display: "block", fontSize: 22, fontWeight: 800, color: C.accent },
  statLabel: { fontSize: 10, color: C.muted, textTransform: "uppercase" },
  lockBtn: {
    background: "transparent",
    border: `1px solid ${C.border}`,
    color: C.muted,
    padding: "10px",
    borderRadius: 8,
    cursor: "pointer",
    fontSize: 13,
  },
  main: { flex: 1, overflow: "auto", padding: 32 },
  topBar: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 24,
  },
  pageTitle: { fontSize: 24, fontWeight: 800, margin: 0 },
  pageSub: { color: C.muted, margin: "4px 0 0", fontSize: 13 },
  addBtn: {
    background: C.accent,
    color: "#000",
    border: "none",
    borderRadius: 8,
    padding: "10px 20px",
    fontSize: 13,
    fontWeight: 700,
    cursor: "pointer",
    whiteSpace: "nowrap",
  },
  searchRow: { marginBottom: 20 },
  searchInput: {
    background: "#0d0d18",
    border: `1px solid ${C.border}`,
    borderRadius: 8,
    color: C.text,
    padding: "10px 16px",
    fontSize: 14,
    width: "100%",
    boxSizing: "border-box",
    outline: "none",
    marginBottom: 12,
  },
  catRow: { display: "flex", gap: 8, flexWrap: "wrap" },
  catBtn: {
    background: "transparent",
    border: `1px solid ${C.border}`,
    color: C.muted,
    borderRadius: 20,
    padding: "4px 14px",
    fontSize: 12,
    cursor: "pointer",
  },
  catBtnActive: {
    background: C.accentDim,
    borderColor: C.accent,
    color: C.accent,
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))",
    gap: 16,
  },
  card: {
    background: C.card,
    border: `1px solid ${C.border}`,
    borderRadius: 12,
    padding: 16,
    cursor: "pointer",
    transition: "border-color 0.2s, transform 0.15s",
  },
  cardTop: { display: "flex", gap: 12, alignItems: "center", marginBottom: 12 },
  cardIcon: {
    width: 36,
    height: 36,
    background: C.surface,
    borderRadius: 8,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 18,
  },
  cardTitle: {
    fontWeight: 700,
    fontSize: 14,
    marginBottom: 2,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  cardUser: {
    color: C.muted,
    fontSize: 12,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  strengthDot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },
  cardFooter: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  catTag: {
    background: C.accentDim,
    color: C.accent,
    borderRadius: 10,
    padding: "2px 10px",
    fontSize: 11,
  },
  copyBtn: {
    background: "transparent",
    border: `1px solid ${C.border}`,
    color: C.muted,
    borderRadius: 6,
    padding: "4px 10px",
    fontSize: 11,
    cursor: "pointer",
  },
  empty: { textAlign: "center", padding: "80px 20px", color: C.muted },
  emptyIcon: { fontSize: 48, marginBottom: 16 },
  overlay: {
    position: "fixed",
    inset: 0,
    background: "rgba(0,0,0,0.8)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 100,
    padding: 20,
  },
  modal: {
    background: C.surface,
    border: `1px solid ${C.border}`,
    borderRadius: 16,
    width: "100%",
    maxWidth: 520,
    maxHeight: "90vh",
    display: "flex",
    flexDirection: "column",
  },
  modalHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "20px 24px",
    borderBottom: `1px solid ${C.border}`,
  },
  modalTitle: { margin: 0, fontSize: 18, fontWeight: 800 },
  closeBtn: {
    background: "transparent",
    border: "none",
    color: C.muted,
    cursor: "pointer",
    fontSize: 18,
    lineHeight: 1,
  },
  modalBody: { padding: 24, overflowY: "auto", flex: 1 },
  modalFooter: {
    padding: "16px 24px",
    borderTop: `1px solid ${C.border}`,
    display: "flex",
    gap: 12,
    justifyContent: "flex-end",
  },
  formGroup: { marginBottom: 16 },
  pwRow: { display: "flex", gap: 8, alignItems: "center" },
  iconBtn: {
    background: C.card,
    border: `1px solid ${C.border}`,
    color: C.text,
    borderRadius: 8,
    padding: "10px",
    cursor: "pointer",
    fontSize: 14,
    flexShrink: 0,
  },
  textarea: {
    background: "#0d0d18",
    border: `1px solid ${C.border}`,
    borderRadius: 8,
    color: C.text,
    padding: "10px 14px",
    fontSize: 14,
    width: "100%",
    boxSizing: "border-box",
    outline: "none",
    minHeight: 80,
    resize: "vertical",
  },
  infoRow: { display: "flex", alignItems: "center", gap: 8 },
  infoVal: {
    background: "#0d0d18",
    border: `1px solid ${C.border}`,
    borderRadius: 8,
    color: C.text,
    padding: "10px 14px",
    fontSize: 14,
    flex: 1,
    wordBreak: "break-all",
  },
  encNote: {
    background: C.accentDim,
    color: C.accent,
    borderRadius: 8,
    padding: "10px 14px",
    fontSize: 12,
    marginTop: 8,
  },
  genPanel: {},
  genCard: {
    background: C.card,
    border: `1px solid ${C.border}`,
    borderRadius: 16,
    padding: 28,
    maxWidth: 540,
  },
  genOutput: {
    background: "#0d0d18",
    border: `1px solid ${C.border}`,
    borderRadius: 10,
    padding: "14px 16px",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 12,
  },
  genPw: {
    fontFamily: "monospace",
    fontSize: 15,
    color: C.accent,
    wordBreak: "break-all",
    flex: 1,
  },
  genOpts: { margin: "20px 0" },
  sliderRow: { marginBottom: 16 },
  slider: { width: "100%", accentColor: C.accent, marginTop: 8 },
  checkRow: {
    display: "flex",
    gap: 10,
    alignItems: "center",
    marginBottom: 12,
    cursor: "pointer",
    fontSize: 14,
    color: C.text,
  },
  logList: { display: "flex", flexDirection: "column", gap: 8 },
  logItem: {
    background: C.card,
    borderRadius: 8,
    padding: "12px 16px",
    display: "flex",
    gap: 12,
    alignItems: "center",
  },
  logIcon: { fontSize: 16, flexShrink: 0 },
  logMsg: { flex: 1, fontSize: 13 },
  logTime: { color: C.muted, fontSize: 11, flexShrink: 0 },
  toast: {
    position: "fixed",
    top: 20,
    right: 20,
    color: "#fff",
    padding: "12px 20px",
    borderRadius: 10,
    fontWeight: 700,
    fontSize: 14,
    zIndex: 200,
    boxShadow: "0 4px 20px rgba(0,0,0,0.5)",
    animation: "slideIn 0.2s ease",
  },
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&display=swap');
  * { box-sizing: border-box; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #2a2a3a; border-radius: 3px; }
  input::placeholder { color: #44445a; }
  .btn-primary:hover { background: #33ddff !important; transform: translateY(-1px); }
  .btn-primary:active { transform: translateY(0); }
  .entry-card:hover { border-color: #00d4ff40 !important; transform: translateY(-2px); }
  .copy-btn:hover { background: #00d4ff15 !important; color: #00d4ff !important; border-color: #00d4ff40 !important; }
  .nav-btn:hover { background: #00d4ff12 !important; color: #ccc !important; }
  .lock-btn:hover { background: #ef444410 !important; color: #fca5a5 !important; border-color: #ef444430 !important; }
  .cat-btn:hover { background: #00d4ff10 !important; }
  .splash-icon { font-size: 64px; animation: pulse 1.5s ease infinite; }
  .spinner { width: 32px; height: 32px; border: 3px solid #1e1e2e; border-top-color: #00d4ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.1)} }
  @keyframes slideIn { from { transform: translateX(20px); opacity: 0; } to { transform: none; opacity: 1; } }
`;
