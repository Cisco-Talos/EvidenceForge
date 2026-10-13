import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { StudioApi } from "./api";

interface CodexAccount { type?: string; email?: string }
export interface CodexStatus { available: boolean; account_ready?: boolean; error?: string; account?: { account?: CodexAccount | null } }

export function codexAccountIdentity(status: CodexStatus | null, loginPending: boolean): string {
  const account = status?.account?.account;
  if (!status) return "Checking Codex…";
  if (!status.available) return status.error || "Codex unavailable";
  if (!account) return loginPending ? "Waiting for sign-in…" : "Signed out";
  if (account.type === "chatgpt") return account.email || "ChatGPT account";
  if (account.type === "apiKey") return "API key authentication";
  if (account.type === "amazonBedrock") return "Amazon Bedrock";
  return "Signed in";
}

export function useCodexAccount(api: StudioApi, enabled: boolean, onError: (message: string) => void) {
  const [codexStatus, setCodexStatus] = useState<CodexStatus | null>(null);
  const [loginPending, setLoginPending] = useState(false);
  const [loginStarting, setLoginStarting] = useState(false);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    void api.request<CodexStatus>("/v1/codex/status").then((status) => {
      if (!cancelled) setCodexStatus(status);
    }).catch((error) => { if (!cancelled) onError(String(error)); });
    return () => { cancelled = true; };
  }, [api, enabled, onError]);

  useEffect(() => {
    if (!loginPending || !enabled) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const deadline = Date.now() + 120_000;
    async function poll() {
      try {
        const status = await api.request<CodexStatus>("/v1/codex/status");
        if (cancelled) return;
        setCodexStatus(status);
        if (status.account?.account) { setLoginPending(false); return; }
      } catch (error) { if (!cancelled) onError(String(error)); }
      if (!cancelled && Date.now() < deadline) timer = setTimeout(() => void poll(), 2500);
      else if (!cancelled) setLoginPending(false);
    }
    timer = setTimeout(() => void poll(), 2500);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [api, enabled, loginPending, onError]);

  async function login(): Promise<void> {
    if (loginStarting) return;
    setLoginStarting(true);
    try {
      const response = await api.request<{ authUrl?: string }>("/v1/codex/account/login", "POST");
      if (!response.authUrl) throw new Error("Codex did not provide a login URL. Try reconnecting.");
      if (isTauri()) await openUrl(response.authUrl);
      else window.open(response.authUrl, "_blank", "noopener,noreferrer");
      setLoginPending(true);
      setCodexStatus(await api.request<CodexStatus>("/v1/codex/status"));
    } catch (error) { onError(String(error)); }
    finally { setLoginStarting(false); }
  }

  async function logout(): Promise<void> {
    try {
      await api.request("/v1/codex/account/logout", "POST");
      setLoginPending(false);
      setCodexStatus(await api.request<CodexStatus>("/v1/codex/status"));
    } catch (error) { onError(String(error)); }
  }

  return { codexStatus, setCodexStatus, loginPending, loginStarting, login, logout };
}
