import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Activity,
  AlertTriangle,
  ArrowUpCircle,
  Ban,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  History,
  KeyRound,
  Loader2,
  Minus,
  Power,
  Settings as SettingsIcon,
  ShieldCheck,
  ShieldAlert,
  X,
  XCircle,
} from "lucide-react";
import {
  api,
  isFullyVerified,
  onAttestation,
  onStatus,
  type AttestationSummary,
  type ModelInfo,
  type ProxyConfig,
  type ProxyStatus,
  type RequestLogEntry,
  type UpdateInfo,
} from "./lib/tauri";

function withWindow(action: (window: ReturnType<typeof getCurrentWindow>) => Promise<void>) {
  try {
    void action(getCurrentWindow()).catch(() => {});
  } catch {
    /* no-op outside the Tauri shell */
  }
}

function dragWindow() {
  withWindow((window) => window.startDragging());
}

function minimizeWindow() {
  withWindow((window) => window.minimize());
}

function closeWindow() {
  withWindow((window) => window.close());
}

export function App() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [apiKeyPresent, setApiKeyPresent] = useState(false);
  const [masked, setMasked] = useState<string | null>(null);
  const [tab, setTab] = useState<"home" | "trust" | "history" | "settings">("home");
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [updateOpen, setUpdateOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .checkForUpdate()
      .then((info) => {
        if (!cancelled && info.available) setUpdateInfo(info);
      })
      .catch(() => {
        /* offline, rate-limited, or unavailable — stay silent */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [s, k] = await Promise.all([api.getStatus(), api.getApiKeyStatus()]);
      setStatus(s);
      setApiKeyPresent(k.present);
      setMasked(k.masked);
    } catch {
      /* backend not ready yet */
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(refresh, 2000);
    const unlisten = onStatus((s) => setStatus(s));
    return () => {
      clearInterval(timer);
      void unlisten.then((u) => u());
    };
  }, [refresh]);

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[var(--color-bg-base)]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-32 cherry-glow" />

      <header className="relative z-10 flex h-8 shrink-0 items-center border-b border-[var(--color-border)] bg-[var(--color-bg-surface)]/80 px-2">
        <div
          data-tauri-drag-region
          onMouseDown={(event) => {
            if (event.button === 0) dragWindow();
          }}
          className="flex min-w-0 flex-1 items-center self-stretch"
        >
          <div data-tauri-drag-region className="truncate text-[12.5px] font-medium tracking-tight">
            AxiomIO
          </div>
        </div>
        {updateInfo && (
          <button
            onClick={() => setUpdateOpen(true)}
            aria-label={`Update available: v${updateInfo.latestVersion}`}
            title={`Update available: v${updateInfo.latestVersion}`}
            className="ml-1 flex shrink-0 items-center gap-1 rounded-full border border-[var(--color-border-accent)] bg-[var(--color-cherry-glow)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-cherry-bright)] transition-colors hover:bg-[var(--color-bg-surface-hover)]"
          >
            <ArrowUpCircle size={11} />
            Update
          </button>
        )}
        <nav className="ml-1 flex shrink-0 items-center gap-0.5" role="tablist" aria-label="Sections">
          <TabButton
            active={tab === "home"}
            onClick={() => setTab("home")}
            icon={<Activity size={13} />}
            label="Home"
          />
          <TabButton
            active={tab === "trust"}
            onClick={() => setTab("trust")}
            icon={<ShieldCheck size={13} />}
            label="Trust"
          />
          <TabButton
            active={tab === "history"}
            onClick={() => setTab("history")}
            icon={<History size={13} />}
            label="Request history"
          />
          <TabButton
            active={tab === "settings"}
            onClick={() => setTab("settings")}
            icon={<SettingsIcon size={13} />}
            label="Settings"
          />
        </nav>
        <div className="ml-1 flex shrink-0 items-center gap-0.5 border-l border-[var(--color-border)] pl-1">
          <WindowButton label="Minimize" onClick={minimizeWindow} icon={<Minus size={12} />} />
          <WindowButton label="Close" onClick={closeWindow} icon={<X size={12} />} />
        </div>
      </header>

      <main className="relative min-h-0 flex-1 overflow-y-auto px-3 py-3">
        {tab === "home" && (
          <HomeTab
            status={status}
            apiKeyPresent={apiKeyPresent}
            masked={masked}
            onKeyChange={refresh}
            onToggle={refresh}
          />
        )}
        {tab === "trust" && <TrustTab running={status?.running ?? false} />}
        {tab === "history" && <HistoryTab open={tab === "history"} />}
        {tab === "settings" && <SettingsTab />}
      </main>

      <AnimatePresence>
        {updateOpen && updateInfo && (
          <UpdatePanel info={updateInfo} onClose={() => setUpdateOpen(false)} />
        )}
      </AnimatePresence>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      role="tab"
      aria-selected={active}
      aria-label={label}
      title={label}
      onClick={onClick}
      className={`flex h-7 w-7 items-center justify-center rounded-lg transition-colors ${
        active
          ? "bg-[var(--color-bg-surface)] text-[var(--color-cherry-bright)]"
          : "text-[var(--color-text-tertiary)] hover:bg-[var(--color-bg-surface)] hover:text-[var(--color-text-secondary)]"
      }`}
    >
      {icon}
    </button>
  );
}

function WindowButton({ label, onClick, icon }: { label: string; onClick: () => void; icon: React.ReactNode }) {
  return (
    <button
      aria-label={label}
      title={label}
      onClick={onClick}
      className="flex h-6 w-6 items-center justify-center rounded-md text-[var(--color-text-tertiary)] transition-colors hover:bg-[var(--color-bg-surface-hover)] hover:text-[var(--color-text-primary)]"
    >
      {icon}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Update — dismissible popover with the exact platform update command
// ---------------------------------------------------------------------------

function UpdatePanel({ info, onClose }: { info: UpdateInfo; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(info.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard access may be unavailable; keep the command selectable */
    }
  };

  return (
    <>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.15 }}
        className="absolute inset-0 z-20"
        onClick={onClose}
      />
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-label="Update available"
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -6 }}
        transition={{ duration: 0.15 }}
        className="absolute inset-x-2 top-9 z-30 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-surface)] px-3 py-2.5 shadow-lg"
      >
        <div className="flex items-center justify-between gap-2">
          <div className="text-[12px] font-medium">Update to v{info.latestVersion}</div>
          <button
            onClick={onClose}
            aria-label="Dismiss"
            className="rounded-md p-0.5 text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-text-primary)]"
          >
            <X size={13} />
          </button>
        </div>
        <p className="mt-1 text-[10.5px] leading-[14px] text-[var(--color-text-tertiary)]">
          Quit AxiomIO, then run:
        </p>
        <div className="mt-1.5 flex items-start gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2 py-1.5">
          <code className="min-w-0 flex-1 break-all font-mono text-[10.5px] leading-[14px] text-[var(--color-text-secondary)]">
            {info.command}
          </code>
          <button
            onClick={copyCommand}
            aria-label={copied ? "Copied" : "Copy update command"}
            title={copied ? "Copied" : "Copy update command"}
            className="shrink-0 rounded-md p-1 text-[var(--color-text-tertiary)] transition-colors hover:bg-[var(--color-bg-surface-hover)] hover:text-[var(--color-text-secondary)]"
          >
            {copied ? <Check size={12} className="text-[var(--color-cherry-bright)]" /> : <Copy size={12} />}
          </button>
        </div>
      </motion.div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Home — hero status, setup, activity
// ---------------------------------------------------------------------------

function HomeTab({
  status,
  apiKeyPresent,
  masked,
  onKeyChange,
  onToggle,
}: {
  status: ProxyStatus | null;
  apiKeyPresent: boolean;
  masked: string | null;
  onKeyChange: () => void;
  onToggle: () => void;
}) {
  const running = status?.running ?? false;
  const connectionFailed = !running && apiKeyPresent && Boolean(status?.error);
  const protectedNow = running && apiKeyPresent && !status?.error;
  const blockedByKey = !running && !apiKeyPresent;
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const toggle = async () => {
    if (blockedByKey) return;
    setBusy(true);
    try {
      if (running) await api.stopServer();
      else await api.startServer();
      onToggle();
    } catch (e) {
      alert(String(e));
    } finally {
      setBusy(false);
    }
  };

  const copyBase = async () => {
    if (!status) return;
    await navigator.clipboard.writeText(status.baseUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="flex min-h-full flex-col gap-2.5">
      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="relative flex shrink-0 flex-col items-center gap-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-surface)]/60 px-3.5 py-3"
      >
        <div className="relative flex h-11 w-11 items-center justify-center">
          {protectedNow && (
            <div className="animate-pulse-glow absolute inset-0 rounded-full bg-[var(--color-cherry)] blur-2xl opacity-40" />
          )}
          <div
            className={`relative flex h-9 w-9 items-center justify-center rounded-full border ${
              protectedNow
                ? "border-[var(--color-border-accent)] bg-[var(--color-cherry-glow)] text-[var(--color-cherry-bright)]"
                : "border-[var(--color-border)] bg-[var(--color-bg-input)] text-[var(--color-text-tertiary)]"
            }`}
          >
            {protectedNow ? <ShieldCheck size={18} /> : <ShieldAlert size={16} />}
          </div>
        </div>

        <div className="text-center">
          <div className="text-[14px] font-medium">
            {protectedNow
              ? "Protected"
              : connectionFailed
                ? "Connection failed"
                : running
                  ? "Waiting for a key"
                  : blockedByKey
                    ? "API key required"
                    : "Proxy off"}
          </div>
          <div className="mt-1 max-w-[240px] break-words text-[11px] leading-[16px] text-[var(--color-text-tertiary)]">
            {protectedNow
              ? "Requests are end-to-end encrypted to the attested model TEE."
              : connectionFailed
                ? status?.error
                : running
                  ? "Add your API key below to start serving requests."
                  : blockedByKey
                    ? "Add an API key below before starting the proxy."
                    : "Start the proxy to accept OpenAI-compatible requests locally."}
          </div>
        </div>

        {/* Base URL */}
        <button
          onClick={copyBase}
          className="group flex max-w-full items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2.5 py-1.5 text-[11px] transition-colors hover:border-[var(--color-border-accent)]"
        >
          <code className="max-w-[245px] truncate font-mono text-[var(--color-text-secondary)]">
            {status?.baseUrl ?? "http://127.0.0.1:8484/v1"}
          </code>
          {copied ? (
            <Check size={13} className="text-[var(--color-cherry-bright)]" />
          ) : (
            <Copy size={13} className="text-[var(--color-text-tertiary)] group-hover:text-[var(--color-text-secondary)]" />
          )}
        </button>

        <button
          onClick={toggle}
          disabled={busy || blockedByKey}
          title={blockedByKey ? "Add an API key first" : undefined}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-[12px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
            running
              ? "border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-surface-hover)]"
              : "bg-[var(--color-cherry)] text-[#140709] hover:bg-[var(--color-cherry-bright)]"
          }`}
        >
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Power size={14} />}
          {running ? "Stop proxy" : blockedByKey ? "Add API key to start" : "Start proxy"}
        </button>
      </motion.div>

      <ApiKeyCard present={apiKeyPresent} masked={masked} onChange={onKeyChange} />

      {status && <ActivityCard status={status} />}
    </div>
  );
}

function ApiKeyCard({
  present,
  masked,
  onChange,
}: {
  present: boolean;
  masked: string | null;
  onChange: () => void;
}) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.setApiKey(value.trim());
      setValue("");
      onChange();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    await api.clearApiKey();
    onChange();
  };

  return (
    <div className="shrink-0 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-surface)]/60 px-3.5 py-2.5">
      <div className="flex items-center gap-2 text-[12.5px] font-medium">
        <KeyRound size={13} className="text-[var(--color-text-tertiary)]" />
        API key
        {!present && (
          <span className="rounded-full border border-[var(--color-border-accent)] bg-[var(--color-cherry-glow)] px-1.5 py-0.5 text-[9.5px] font-medium uppercase tracking-wide text-[var(--color-cherry-bright)]">
            Required
          </span>
        )}
      </div>
      {present ? (
        <div className="mt-2 flex items-center justify-between gap-2">
          <code className="font-mono text-[12px] text-[var(--color-text-secondary)]">{masked}</code>
          <button
            onClick={clear}
            className="rounded-md border border-[var(--color-border)] px-2 py-1 text-[11.5px] text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-accent)] hover:text-[var(--color-cherry-bright)]"
          >
            Remove
          </button>
        </div>
      ) : (
        <>
          <div className="mt-2 flex items-center gap-2">
            <input
              type="password"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="axm_…"
              className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2.5 py-1.5 font-mono text-[12px] text-[var(--color-text-primary)] outline-none transition-colors placeholder:text-[var(--color-text-muted)] focus:border-[var(--color-border-accent)]"
            />
            <button
              onClick={save}
              disabled={busy || !value.trim()}
              className="flex shrink-0 items-center gap-1.5 rounded-lg bg-[var(--color-cherry)] px-2.5 py-1.5 text-[12px] font-medium text-[#140709] transition-colors hover:bg-[var(--color-cherry-bright)] disabled:opacity-50"
            >
              {busy && <Loader2 size={13} className="animate-spin" />}
              Save
            </button>
          </div>
          <p className="mt-1 text-[10.5px] leading-[14px] text-[var(--color-text-tertiary)]">
            Required to start the proxy. Create a key in Axiom → Settings → API. Stored in your OS keychain.
          </p>
          {error && <p className="mt-1 text-[11.5px] text-[var(--color-cherry-bright)]">{error}</p>}
        </>
      )}
    </div>
  );
}

function ActivityCard({ status }: { status: ProxyStatus }) {
  const [requests, setRequests] = useState<RequestLogEntry[]>([]);

  useEffect(() => {
    const load = () => api.getRecentRequests(2).then(setRequests).catch(() => {});
    load();
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="shrink-0 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-surface)]/60 px-3.5 py-2.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-[12.5px] font-medium">
          <Activity size={13} className="text-[var(--color-text-tertiary)]" />
          Activity
        </div>
        {status.activeRequests > 0 && (
          <span className="flex items-center gap-1.5 text-[11px] text-[var(--color-cherry-bright)]">
            <span className="h-1.5 w-1.5 animate-pulse-glow rounded-full bg-[var(--color-cherry)]" />
            {status.activeRequests} active
          </span>
        )}
      </div>

      <div className="mt-2 grid grid-cols-3 gap-1.5">
        <Metric label="Requests" value={status.totalRequests.toLocaleString()} />
        <Metric label="Prompt tok" value={compact(status.totalPromptTokens)} />
        <Metric label="Output tok" value={compact(status.totalCompletionTokens)} />
      </div>

      <div className="mt-2 flex flex-col gap-1.5 overflow-hidden">
        <AnimatePresence initial={false}>
          {requests.map((r) => (
            <motion.div
              key={r.id}
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="flex items-center justify-between rounded-md bg-[var(--color-bg-input)] px-2.5 py-1.5 text-[11px]"
            >
              <span className="min-w-0 truncate text-[var(--color-text-secondary)]">{r.model}</span>
              <span className="shrink-0 text-[var(--color-text-tertiary)]">
                {r.completion_tokens} tok{r.stream ? " · stream" : ""}
              </span>
            </motion.div>
          ))}
        </AnimatePresence>
        {requests.length === 0 && (
          <div className="rounded-md bg-[var(--color-bg-input)] px-3 py-2.5 text-center text-[10.5px] text-[var(--color-text-tertiary)]">
            No requests yet. Point any OpenAI-compatible tool at the URL above.
          </div>
        )}
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2 py-1">
      <div className="truncate text-[9.5px] uppercase tracking-[0.06em] text-[var(--color-text-tertiary)]">{label}</div>
      <div className="truncate text-[12.5px] font-medium">{value}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Trust — attestation panel
// ---------------------------------------------------------------------------

function TrustTab({ running }: { running: boolean }) {
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [summaries, setSummaries] = useState<Record<string, AttestationSummary>>({});
  const [verifying, setVerifying] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loaded = useRef(false);

  useEffect(() => {
    const unlisten = onAttestation((s) =>
      setSummaries((prev) => ({ ...prev, [s.model_id]: s })),
    );
    return () => void unlisten.then((u) => u());
  }, []);

  useEffect(() => {
    if (loaded.current || !running) return;
    loaded.current = true;
    api
      .listModels()
      .then((m) => {
        setModels(m);
        return api.getAttestations();
      })
      .then((cached) => {
        const map: Record<string, AttestationSummary> = {};
        for (const s of cached) map[s.model_id] = s;
        setSummaries(map);
      })
      .catch((e) => setError(String(e)));
  }, [running]);

  const verify = async (id: string) => {
    setVerifying(id);
    try {
      const s = await api.verifyModel(id, true);
      setSummaries((prev) => ({ ...prev, [id]: s }));
    } catch (e) {
      setError(String(e));
    } finally {
      setVerifying(null);
    }
  };
  const visibleModels = models.slice(0, 3);

  if (!running) {
    return (
      <div className="mt-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3.5 py-6 text-center text-[11.5px] text-[var(--color-text-tertiary)]">
        Start the proxy to inspect model attestations.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-2 overflow-hidden">
      <p className="text-[11.5px] leading-[16px] text-[var(--color-text-tertiary)]">
        Each model runs in a TEE whose key is verified on this machine, with a TLS binding to the
        live connection. Your prompts are encrypted to that verified key.
      </p>
      {error && <p className="text-[11px] text-[var(--color-cherry-bright)]">{error}</p>}
      {visibleModels.map((m) => (
        <ModelRow
          key={m.id}
          model={m}
          summary={summaries[m.id]}
          verifying={verifying === m.id}
          onVerify={() => verify(m.id)}
        />
      ))}
    </div>
  );
}

function ModelRow({
  model,
  summary,
  verifying,
  onVerify,
}: {
  model: ModelInfo;
  summary?: AttestationSummary;
  verifying: boolean;
  onVerify: () => void;
}) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-surface)]/60 px-3.5 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[12.5px] font-medium">{model.label}</div>
          <div className="truncate text-[10.5px] text-[var(--color-text-tertiary)]">{model.model}</div>
        </div>
        <button
          onClick={onVerify}
          disabled={verifying}
          className="shrink-0 rounded-md border border-[var(--color-border)] px-2 py-1 text-[11px] text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-accent)] disabled:opacity-50"
        >
          {verifying ? "Verifying…" : summary ? "Re-verify" : "Verify"}
        </button>
      </div>

      {verifying ? (
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-bg-input)]">
          <div className="shimmer h-full w-full" />
        </div>
      ) : summary ? (
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {summary.checks.length > 0 ? (
            summary.checks.map((check) => (
              <Chip
                key={check.id}
                label={check.label}
                ok={summary.verified && check.ok}
                detail={check.status}
              />
            ))
          ) : (
            <Chip label="Attestation" ok={false} detail={summary.verified ? "verified" : "failed"} />
          )}
          {summary.error && (
            <span className="text-[11px] text-[var(--color-cherry-bright)]">{summary.error}</span>
          )}
        </div>
      ) : (
        <div className="mt-2 text-[11px] text-[var(--color-text-muted)]">Not yet verified this session.</div>
      )}
    </div>
  );
}

function Chip({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] ${
        ok
          ? "border-[rgba(52,211,153,0.3)] bg-[var(--color-emerald-glow)] text-[var(--color-emerald)]"
          : "border-[var(--color-border)] bg-[var(--color-bg-input)] text-[var(--color-text-tertiary)]"
      }`}
    >
      {ok && <Check size={10} />}
      {label}
      <span className="opacity-60">· {detail}</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// History — metadata-only request log
// ---------------------------------------------------------------------------

const HISTORY_LIMIT = 100;
const HISTORY_POLL_MS = 2000;

type HistoryTone = "verified" | "failed" | "cancelled" | "unverified";

const TONE_STYLE: Record<
  HistoryTone,
  { label: string; icon: typeof CheckCircle2; text: string; border: string; bg: string }
> = {
  verified: {
    label: "E2EE + TEE verified",
    icon: CheckCircle2,
    text: "text-[var(--color-emerald)]",
    border: "border-[rgba(52,211,153,0.3)]",
    bg: "bg-[var(--color-emerald-glow)]",
  },
  failed: {
    label: "Failed",
    icon: XCircle,
    text: "text-[var(--color-cherry-bright)]",
    border: "border-[var(--color-border-accent)]",
    bg: "bg-[var(--color-cherry-glow)]",
  },
  cancelled: {
    label: "Cancelled",
    icon: Ban,
    text: "text-[var(--color-amber)]",
    border: "border-[rgba(245,182,76,0.3)]",
    bg: "bg-[var(--color-amber-glow)]",
  },
  unverified: {
    label: "Incomplete evidence",
    icon: AlertTriangle,
    text: "text-[var(--color-amber)]",
    border: "border-[rgba(245,182,76,0.3)]",
    bg: "bg-[var(--color-amber-glow)]",
  },
};

function toneOf(entry: RequestLogEntry): HistoryTone {
  if (entry.status === "failed") return "failed";
  if (entry.status === "cancelled") return "cancelled";
  return isFullyVerified(entry) ? "verified" : "unverified";
}

function formatClock(ms: number): string {
  return new Date(ms).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatDateTime(ms: number): string {
  return new Date(ms).toLocaleString();
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
}

function formatAge(ms?: number): string {
  if (ms === undefined) return "unknown age";
  if (ms < 1000) return "just now";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s old`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m old`;
  return `${Math.round(ms / 3_600_000)}h old`;
}

function truncateFingerprint(hash?: string): string {
  if (!hash) return "not recorded";
  return hash.length <= 18 ? hash : `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

function HistoryTab({ open }: { open: boolean }) {
  const [entries, setEntries] = useState<RequestLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const loadedOnce = useRef(false);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;

    const load = async () => {
      try {
        const rows = await api.getRecentRequests(HISTORY_LIMIT);
        if (cancelled) return;
        setEntries(rows);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(String(e));
      } finally {
        if (!cancelled) {
          loadedOnce.current = true;
          setLoading(false);
        }
      }
    };

    setLoading(!loadedOnce.current);
    void load();
    const timer = setInterval(load, HISTORY_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [open]);

  const counts = useMemo(() => {
    let completed = 0;
    let verified = 0;
    let failed = 0;
    let cancelled = 0;
    for (const entry of entries) {
      if (entry.status === "completed") completed += 1;
      if (entry.status === "failed") failed += 1;
      if (entry.status === "cancelled") cancelled += 1;
      if (isFullyVerified(entry)) verified += 1;
    }
    return { total: entries.length, completed, verified, failed, cancelled };
  }, [entries]);

  return (
    <div className="flex h-full flex-col gap-2 overflow-hidden">
      <div className="flex shrink-0 flex-col gap-1">
        <div className="grid grid-cols-3 gap-1">
          <Metric label="Total" value={String(counts.total)} />
          <Metric label="Completed" value={String(counts.completed)} />
          <Metric label="E2EE+TEE" value={String(counts.verified)} />
        </div>
        <div className="grid grid-cols-2 gap-1">
          <Metric label="Failed" value={String(counts.failed)} />
          <Metric label="Cancelled" value={String(counts.cancelled)} />
        </div>
      </div>

      {loading ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-input)] text-[11.5px] text-[var(--color-text-tertiary)]">
          <Loader2 size={16} className="motion-safe:animate-spin" />
          Loading history…
        </div>
      ) : error && entries.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-1 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-input)] px-4 text-center text-[11.5px] text-[var(--color-cherry-bright)]">
          <AlertTriangle size={16} />
          Couldn't load request history
          <span className="text-[10.5px] text-[var(--color-text-tertiary)]">{error}</span>
        </div>
      ) : entries.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-1 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-input)] px-4 text-center text-[11.5px] text-[var(--color-text-tertiary)]">
          No requests yet. History appears here once you send a request.
        </div>
      ) : (
        <>
          {error && (
            <p className="shrink-0 text-[10.5px] text-[var(--color-cherry-bright)]">
              Refresh failed, showing last known data: {error}
            </p>
          )}
          <div className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto pr-0.5">
            {entries.map((entry) => (
              <HistoryRow key={entry.id} entry={entry} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function HistoryRow({ entry }: { entry: RequestLogEntry }) {
  const tone = toneOf(entry);
  const style = TONE_STYLE[tone];
  const ToneIcon = style.icon;
  const protocolLabel = entry.e2ee.protocol
    ? `${entry.e2ee.protocol} v${entry.e2ee.encryption_version ?? "?"}`
    : "No protocol";
  const teeLabel = entry.tee.verified ? `TEE · ${formatAge(entry.tee.age_ms)}` : "TEE unverified";
  const tokenTotal = entry.prompt_tokens + entry.completion_tokens;

  return (
    <details className="group rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2.5 py-1.5">
      <summary className="flex cursor-pointer items-start gap-2 rounded-md outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-border-accent)]">
        <span
          className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${style.border} ${style.bg} ${style.text}`}
        >
          <ToneIcon size={10} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-[11px]">
            <span className="shrink-0 tabular-nums text-[var(--color-text-tertiary)]">
              {formatClock(entry.completed_at_unix_ms)}
            </span>
            <span className="min-w-0 flex-1 truncate font-medium text-[var(--color-text-secondary)]">
              {entry.model}
            </span>
            <span className="shrink-0 tabular-nums text-[var(--color-text-tertiary)]">
              {formatDuration(entry.duration_ms)}
            </span>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-[var(--color-text-tertiary)]">
            <span className={`font-medium ${style.text}`}>{style.label}</span>
            <span>{protocolLabel}</span>
            <span>{teeLabel}</span>
            <span>{tokenTotal.toLocaleString()} tok</span>
          </div>
        </div>
        <ChevronDown
          size={12}
          className="mt-0.5 shrink-0 text-[var(--color-text-tertiary)] motion-safe:transition-transform group-open:rotate-180"
        />
      </summary>

      <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 border-t border-[var(--color-border)] pt-2 text-[10.5px]">
        <DetailField label="Request ID" value={entry.id} mono />
        <DetailField label="Provider" value={entry.provider} />
        <DetailField label="Mode" value={entry.stream ? "Streaming" : "Single response"} />
        <DetailField label="Status" value={entry.status} />
        <DetailField label="Started" value={formatDateTime(entry.started_at_unix_ms)} />
        <DetailField label="Completed" value={formatDateTime(entry.completed_at_unix_ms)} />
        <DetailField label="Prompt tokens" value={entry.prompt_tokens.toLocaleString()} />
        <DetailField label="Output tokens" value={entry.completion_tokens.toLocaleString()} />
        {entry.finish_reason && <DetailField label="Finish reason" value={entry.finish_reason} />}
        {entry.error_kind && <DetailField label="Error kind" value={entry.error_kind} />}
      </div>

      <div className="mt-2 border-t border-[var(--color-border)] pt-2">
        <div className="text-[9px] uppercase tracking-wide text-[var(--color-text-tertiary)]">
          End-to-end encryption
        </div>
        <div className="mt-1 flex flex-wrap gap-1">
          <BoolTag label="Request encrypted" ok={entry.e2ee.request_encrypted} />
          <BoolTag label="Backend key accepted" ok={entry.e2ee.backend_key_accepted} />
          <BoolTag label="Response decrypted" ok={entry.e2ee.response_decrypted} />
          <BoolTag label="Ephemeral client key" ok={entry.e2ee.ephemeral_client_key} />
        </div>
      </div>

      <div className="mt-2 border-t border-[var(--color-border)] pt-2">
        <div className="text-[9px] uppercase tracking-wide text-[var(--color-text-tertiary)]">
          TEE attestation
        </div>
        <div className="mt-1 flex flex-col gap-0.5 text-[10.5px] text-[var(--color-text-secondary)]">
          <div>
            Model key <code className="font-mono text-[var(--color-text-tertiary)]">
              {truncateFingerprint(entry.tee.model_key_sha256)}
            </code>
          </div>
          <div>
            TLS SPKI <code className="font-mono text-[var(--color-text-tertiary)]">
              {truncateFingerprint(entry.tee.tls_spki_sha256)}
            </code>
          </div>
        </div>
        {entry.tee.checks.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {entry.tee.checks.map((check) => (
              <Chip key={check.id} label={check.label} ok={entry.tee.verified && check.ok} detail={check.status} />
            ))}
          </div>
        )}
      </div>
    </details>
  );
}

function DetailField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[9px] uppercase tracking-wide text-[var(--color-text-tertiary)]">{label}</div>
      <div className={`truncate text-[var(--color-text-secondary)] ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function BoolTag({ label, ok }: { label: string; ok: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] ${
        ok
          ? "border-[rgba(52,211,153,0.3)] bg-[var(--color-emerald-glow)] text-[var(--color-emerald)]"
          : "border-[var(--color-border)] bg-[var(--color-bg-surface)] text-[var(--color-text-tertiary)]"
      }`}
    >
      {ok ? <Check size={9} /> : <X size={9} />}
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

function SettingsTab() {
  const [config, setConfig] = useState<ProxyConfig | null>(null);
  const [port, setPort] = useState("");
  const [backend, setBackend] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getConfig().then((c) => {
      setConfig(c);
      setPort(String(c.port));
      setBackend(c.backend_url);
    });
  }, []);

  const save = async (patch: Partial<ProxyConfig>) => {
    setSaving(true);
    try {
      const updated = await api.setConfig(patch);
      setConfig(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 1400);
    } finally {
      setSaving(false);
    }
  };

  if (!config) return null;

  return (
    <div className="flex h-full flex-col gap-3 overflow-hidden">
      <Field label="Local port">
        <div className="flex items-center gap-2">
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            className="w-20 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2.5 py-1.5 text-[12px] outline-none focus:border-[var(--color-border-accent)]"
          />
          <button
            onClick={() => save({ port: Number(port) })}
            disabled={saving || Number(port) === config.port}
            className="rounded-lg border border-[var(--color-border)] px-2.5 py-1.5 text-[11.5px] text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-accent)] disabled:opacity-40"
          >
            Apply
          </button>
        </div>
      </Field>

      <Field label="Backend URL">
        <div className="flex items-center gap-2">
          <input
            value={backend}
            onChange={(e) => setBackend(e.target.value)}
            className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2.5 py-1.5 font-mono text-[11.5px] outline-none focus:border-[var(--color-border-accent)]"
          />
          <button
            onClick={() => save({ backend_url: backend.trim() })}
            disabled={saving || backend.trim() === config.backend_url}
            className="shrink-0 rounded-lg border border-[var(--color-border)] px-2.5 py-1.5 text-[11.5px] text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-accent)] disabled:opacity-40"
          >
            Apply
          </button>
        </div>
      </Field>

      <Toggle
        label="Close to tray"
        detail="Keep the proxy running when the window is closed."
        value={config.close_to_tray}
        onChange={(v) => save({ close_to_tray: v })}
      />
      <Toggle
        label="Start minimized"
        detail="Launch to the tray without opening the window."
        value={config.start_minimized}
        onChange={(v) => save({ start_minimized: v })}
      />

      {saved && <div className="text-[11px] text-[var(--color-cherry-bright)]">Saved</div>}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[11.5px] font-medium text-[var(--color-text-secondary)]">{label}</div>
      {children}
    </div>
  );
}

function Toggle({
  label,
  detail,
  value,
  onChange,
}: {
  label: string;
  detail: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      onClick={() => onChange(!value)}
      className="flex items-center justify-between gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-surface)]/60 px-3.5 py-2.5 text-left"
    >
      <div className="min-w-0">
        <div className="text-[12px] font-medium">{label}</div>
        <div className="text-[10.5px] leading-[14px] text-[var(--color-text-tertiary)]">{detail}</div>
      </div>
      <div
        className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
          value ? "bg-[var(--color-cherry)]" : "bg-[var(--color-bg-elevated)]"
        }`}
      >
        <div
          className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
            value ? "translate-x-4" : "translate-x-0.5"
          }`}
        />
      </div>
    </button>
  );
}

function compact(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}
