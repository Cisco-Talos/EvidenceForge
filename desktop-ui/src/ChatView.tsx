import { Fragment, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ArrowUp, ChevronDown, CirclePause, Sparkles } from "lucide-react";
import { CatalogItem, CodexHealth, Conversation, StudioApi, StudioEvent, type TurnSubmission } from "./api";

interface HistoryItem { type: string; text?: string; content?: { type: string; text?: string }[]; [key: string]: unknown }
interface HistoryTurn { id?: string; status?: string; items?: HistoryItem[] }
interface CodexHistory { thread?: { turns?: HistoryTurn[] }; history_pending?: boolean }
interface CodexModel { id: string; displayName?: string; isDefault?: boolean; defaultReasoningEffort?: string; supportedReasoningEfforts?: { reasoningEffort: string }[] }
interface CodexStatus { available: boolean; account_ready?: boolean; error?: string; models?: { data?: CodexModel[] }; skills?: { data?: { skills?: { name: string; enabled?: boolean }[] }[] } }
interface PendingRequest { request_id: number | string; method: string; params: Record<string, unknown> }
interface Message { id: string; role: "user" | "agent"; text: string }
interface LocalTurn { localId: string; turnId: string | null; userText: string; agentText: string; completed: boolean; afterTurnCount: number }

function startLocalTurn(turns: LocalTurn[], turnId: string, localId: string): LocalTurn[] {
  if (turns.some((turn) => turn.turnId === turnId)) return turns;
  const pendingIndex = turns.findIndex((turn) => turn.turnId === null && !turn.completed);
  if (pendingIndex >= 0) return turns.map((turn, index) => index === pendingIndex ? { ...turn, turnId } : turn);
  return [...turns, { localId, turnId, userText: "", agentText: "", completed: false, afterTurnCount: 0 }];
}

function appendAgentDelta(turns: LocalTurn[], turnId: string, delta: string, localId: string): LocalTurn[] {
  const started = startLocalTurn(turns, turnId, localId);
  return started.map((turn) => turn.turnId === turnId ? { ...turn, agentText: turn.agentText + delta } : turn);
}

function flattenHistory(history: CodexHistory, localTurns: LocalTurn[]): { messages: Message[]; activities: HistoryItem[] } {
  const messages: Message[] = [];
  const activities: HistoryItem[] = [];
  const localTurnIds = new Set(localTurns.filter((turn) => turn.userText).map((turn) => turn.turnId).filter(Boolean));
  for (const turn of history.thread?.turns || []) {
    if (turn.id && localTurnIds.has(turn.id)) continue;
    for (const [index, item] of (turn.items || []).entries()) {
      if (item.type === "userMessage") {
        const text = (item.content || []).filter((part) => part.type === "text").map((part) => part.text || "").join("\n");
        if (text) messages.push({ id: `${turn.id}-${index}`, role: "user", text });
      } else if (item.type === "agentMessage" && item.text) {
        messages.push({ id: `${turn.id}-${index}`, role: "agent", text: item.text });
      } else if (item.type !== "userMessage" && item.type !== "agentMessage") {
        activities.push(item);
      }
    }
  }
  return { messages, activities };
}

function activityLabel(item: HistoryItem): string {
  if (item.type === "commandExecution") return "Command";
  if (item.type === "fileChange") return "File change";
  if (item.type === "reasoning") return "Reasoning";
  return item.type.replace(/([a-z])([A-Z])/g, "$1 $2");
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

export function ChatView({ item, conversation, codexHealth, api, subscribeEvents, initialDraft, onDraftSubmitted, onError }: {
  item: Pick<CatalogItem, "name" | "kind">;
  conversation: Conversation | null;
  codexHealth: CodexHealth;
  api: StudioApi;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  initialDraft?: string;
  onDraftSubmitted?: (conversationId: string) => void;
  onError: (error: string) => void;
}) {
  const [history, setHistory] = useState<CodexHistory>({});
  const [status, setStatus] = useState<CodexStatus | null>(null);
  const [pending, setPending] = useState<PendingRequest[]>([]);
  const [draft, setDraft] = useState("");
  const [skill, setSkill] = useState("");
  const [sending, setSending] = useState(false);
  const [localTurns, setLocalTurns] = useState<LocalTurn[]>([]);
  const [liveActivity, setLiveActivity] = useState<HistoryItem[]>([]);
  const [historyPending, setHistoryPending] = useState(false);
  const [historyWarning, setHistoryWarning] = useState(false);
  const [answer, setAnswer] = useState("");
  const conversationId = conversation?.id;
  const historyRequest = useRef(0);
  const historyAttempts = useRef(0);
  const historyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const expectedTurnId = useRef<string | null>(null);
  const completedTurnIds = useRef(new Set<string>());
  const nextLocalId = useRef(0);
  const chatBody = useRef<HTMLDivElement | null>(null);
  const followBottom = useRef(true);
  const shownConversation = useRef<string | undefined>(undefined);
  const activeRef = useRef(conversation?.active);
  const previousActivity = useRef({ id: conversationId, active: conversation?.active });
  const previousHealth = useRef(codexHealth.state);
  activeRef.current = conversation?.active;

  const loadHistory = useCallback(async (completedTurnId?: string, retry = false) => {
    if (!conversationId) return;
    if (historyTimer.current) clearTimeout(historyTimer.current);
    historyTimer.current = null;
    if (!retry) {
      historyAttempts.current = 0;
      expectedTurnId.current = completedTurnId || null;
      setHistoryWarning(false);
    }
    const requestId = ++historyRequest.current;
    try {
      const result = await api.request<CodexHistory>(`/v1/conversations/${conversationId}/history`);
      if (requestId !== historyRequest.current) return;
      const turns = result.thread?.turns || [];
      const completedTurnSaved = !completedTurnId || turns.some(
        (turn) => turn.id === completedTurnId && ["completed", "failed", "interrupted"].includes(turn.status || ""),
      );
      if (result.history_pending || !completedTurnSaved) {
        setHistoryPending(true);
        if (historyAttempts.current < 6) {
          const delay = Math.min(350 * 2 ** historyAttempts.current, 3000);
          historyAttempts.current += 1;
          historyTimer.current = setTimeout(() => void loadHistory(completedTurnId, true), delay);
        } else {
          setHistoryWarning(true);
        }
        return;
      }
      expectedTurnId.current = null;
      setHistory(result);
      setHistoryPending(false);
      setHistoryWarning(false);
      const savedTurnIds = new Set(turns.filter(
        (turn) => ["completed", "failed", "interrupted"].includes(turn.status || ""),
      ).map((turn) => turn.id));
      setLocalTurns((current) => current.filter((turn) => {
        if (turn.turnId) return !savedTurnIds.has(turn.turnId);
        if (!turn.userText || activeRef.current) return true;
        return !turns.slice(turn.afterTurnCount).some((saved) => {
          if (!["completed", "failed", "interrupted"].includes(saved.status || "")) return false;
          return (saved.items || []).some((item) => item.type === "userMessage"
            && (item.content || []).filter((part) => part.type === "text").map((part) => part.text || "").join("\n") === turn.userText);
        });
      }));
    } catch (error) {
      if (requestId === historyRequest.current && !(activeRef.current && isAbortError(error))) onError(String(error));
    }
  }, [api, conversationId, onError]);

  useEffect(() => {
    let cancelled = false;
    expectedTurnId.current = null;
    completedTurnIds.current.clear();
    setHistory({}); setLocalTurns([]); setLiveActivity([]); setSkill("");
    setHistoryPending(false); setHistoryWarning(false);
    if (!conversationId) return;
    void loadHistory();
    const reportError = (error: unknown) => {
      if (!cancelled && !(activeRef.current && isAbortError(error))) onError(String(error));
    };
    void api.request<CodexStatus>("/v1/codex/status").then((result) => { if (!cancelled) setStatus(result); }).catch(reportError);
    void api.request<PendingRequest[]>("/v1/codex/pending").then((result) => { if (!cancelled) setPending(result); }).catch(reportError);
    return () => {
      cancelled = true;
      historyRequest.current += 1;
      if (historyTimer.current) clearTimeout(historyTimer.current);
      historyTimer.current = null;
    };
  }, [api, conversationId, loadHistory, onError]);

  useEffect(() => { setDraft(""); }, [conversationId]);
  useEffect(() => { if (initialDraft) setDraft(initialDraft); }, [conversationId, initialDraft]);

  useEffect(() => {
    const recovered = previousHealth.current !== "connected" && codexHealth.state === "connected";
    previousHealth.current = codexHealth.state;
    if (recovered && conversationId) {
      void loadHistory();
      void api.request<CodexStatus>("/v1/codex/status").then(setStatus).catch((error) => onError(String(error)));
    }
  }, [api, codexHealth.state, conversationId, loadHistory, onError]);

  useEffect(() => {
    const previous = previousActivity.current;
    previousActivity.current = { id: conversationId, active: conversation?.active };
    if (previous.id === conversationId && previous.active && !conversation?.active) {
      void loadHistory(expectedTurnId.current || undefined);
    }
  }, [conversationId, conversation?.active, loadHistory]);

  useEffect(() => {
    if (!conversationId) return;
    return subscribeEvents((event) => {
      if (event.kind === "codex.input_answered" || event.kind === "codex.input_cleared") {
        setPending((current) => current.filter((entry) => entry.request_id !== event.payload.request_id));
        return;
      }
      if (event.entity_id !== conversationId) return;
      if (event.kind === "codex.input_requested") {
        setPending((current) => [...current, event.payload as unknown as PendingRequest]);
        return;
      }
      if (event.kind !== "conversation.event") return;
      const method = event.payload.method as string;
      const params = event.payload.params as Record<string, unknown>;
      const turnId = typeof params.turnId === "string" ? params.turnId : null;
      if (method === "turn/started") {
        const startedId = (params.turn as { id?: string } | undefined)?.id;
        if (startedId) setLocalTurns((current) => startLocalTurn(current, startedId, `event-${event.seq}`));
        setLiveActivity([]);
      } else if (method === "item/agentMessage/delta" && turnId) {
        setLocalTurns((current) => appendAgentDelta(current, turnId, String(params.delta || ""), `event-${event.seq}`));
      } else if (method === "turn/completed") {
        const completedId = (params.turn as { id?: string } | undefined)?.id;
        if (completedId) {
          completedTurnIds.current.add(completedId);
          setLocalTurns((current) => {
            const pending = current.some((turn) => turn.turnId === completedId)
              ? null : current.find((turn) => !turn.turnId && !turn.completed);
            return current.map((turn) => turn.turnId === completedId || turn === pending
              ? { ...turn, turnId: completedId, completed: true } : turn);
          });
        }
        setLiveActivity([]);
        void loadHistory(completedId);
      } else if (method === "item/started" || method === "item/completed") {
        const activity = params.item as HistoryItem;
        if (activity && activity.type !== "agentMessage" && activity.type !== "userMessage") {
          setLiveActivity((current) => [...current, activity]);
        }
      }
    });
  }, [conversationId, loadHistory, subscribeEvents]);

  const { messages, activities } = useMemo(() => flattenHistory(history, localTurns), [history, localTurns]);

  useLayoutEffect(() => {
    if (shownConversation.current !== conversationId) {
      shownConversation.current = conversationId;
      followBottom.current = true;
    }
    if (chatBody.current && followBottom.current) {
      chatBody.current.scrollTop = chatBody.current.scrollHeight;
    }
  }, [conversationId, history, localTurns, liveActivity, pending, historyPending, conversation?.active]);

  useEffect(() => {
    const body = chatBody.current;
    const list = body?.firstElementChild;
    if (!body || !list || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      if (followBottom.current) body.scrollTop = body.scrollHeight;
    });
    observer.observe(body);
    observer.observe(list);
    return () => observer.disconnect();
  }, [conversationId]);

  function trackChatScroll(): void {
    const body = chatBody.current;
    if (!body) return;
    followBottom.current = body.scrollHeight - body.scrollTop - body.clientHeight <= 2;
  }

  const models = status?.models?.data || [];
  const defaultModel = models.find((model) => model.isDefault) || models[0];
  const selectedModel = models.find((model) => model.id === conversation?.model_id) || defaultModel;
  const efforts = selectedModel?.supportedReasoningEfforts || [];
  const selectedEffort = conversation?.reasoning_effort || selectedModel?.defaultReasoningEffort || efforts[0]?.reasoningEffort || "medium";
  const skills = Array.from(new Map((status?.skills?.data || [])
    .flatMap((group) => group.skills || [])
    .filter((entry) => entry.enabled !== false && entry.name.startsWith("eforge-"))
    .map((entry) => [entry.name, entry])).values());
  const threadPending = pending.filter((entry) => !entry.params.threadId || entry.params.threadId === conversation?.thread_id);
  const draftKindLabel = item.kind === "scenario" ? "Scenario" : item.kind === "industry_pack" ? "Industry pack" : "Organization pack";
  const isNewDraft = !!conversation?.draft_kind && !conversation.item_id;

  async function updatePreferences(changes: Record<string, string | null>) {
    if (!conversationId) return;
    try { await api.request(`/v1/conversations/${conversationId}`, "PATCH", changes); }
    catch (error) { onError(String(error)); }
  }

  async function send() {
    const text = draft.trim();
    if (!conversationId || !text || sending || conversation?.active || codexHealth.state !== "connected" || status?.account_ready === false) return;
    const localId = `send-${++nextLocalId.current}`;
    setLocalTurns((current) => [...current, { localId, turnId: null, userText: text, agentText: "", completed: false, afterTurnCount: history.thread?.turns?.length || 0 }]);
    setDraft("");
    setSending(true);
    try {
      const submitted = await api.request<TurnSubmission>(`/v1/conversations/${conversationId}/turns`, "POST", { text, skill_name: skill || null });
      if (submitted.turn_id) {
        expectedTurnId.current = submitted.turn_id;
        setLocalTurns((current) => current.map((turn) => turn.localId === localId
          ? { ...turn, turnId: submitted.turn_id || null, completed: !submitted.active }
          : turn));
      }
      if (!submitted.active || (submitted.turn_id && completedTurnIds.current.has(submitted.turn_id))) {
        void loadHistory(submitted.turn_id || undefined);
      }
      setSkill("");
      onDraftSubmitted?.(conversationId);
    } catch (error) {
      setLocalTurns((current) => current.filter((turn) => turn.localId !== localId));
      setDraft((current) => current || text);
      onError(String(error));
    }
    finally { setSending(false); }
  }

  async function answerRequest(entry: PendingRequest, result: Record<string, unknown>) {
    try {
      await api.request("/v1/codex/reply", "POST", { request_id: entry.request_id, result });
      setPending((current) => current.filter((candidate) => candidate.request_id !== entry.request_id));
      setAnswer("");
    } catch (error) { onError(String(error)); }
  }

  if (!conversation) return <section className="chat-panel"><div className="chat-body"><div className="chat-welcome"><Sparkles size={26} /><h2>Select a conversation</h2><p>Every conversation stays connected to {item.name}.</p></div></div></section>;

  return <section className="chat-panel">
    <div className="chat-topline"><div><strong>{conversation.title}</strong><span>{item.name}</span></div><div className="chat-pickers"><label>Model<select aria-label="Model" value={conversation.model_id || defaultModel?.id || ""} onChange={(event) => void updatePreferences({ model_id: event.target.value })}>{models.map((model) => <option key={model.id} value={model.id}>{model.displayName || model.id}</option>)}</select></label><label>Reasoning<select aria-label="Reasoning" value={selectedEffort} onChange={(event) => void updatePreferences({ reasoning_effort: event.target.value })}>{efforts.map((effort) => <option key={effort.reasoningEffort} value={effort.reasoningEffort}>{effort.reasoningEffort}</option>)}</select></label></div></div>
    {conversation.connection_note && <p className="chat-connection-note" role="status">{conversation.connection_note}</p>}
    <div className="chat-body" ref={chatBody} onScroll={trackChatScroll}><div className="message-list">
      {!messages.length && !localTurns.length && !conversation.active && <div className="chat-welcome"><div className="chat-symbol"><Sparkles size={25} /></div><h2>{isNewDraft ? `Create a ${draftKindLabel.toLowerCase()}` : `Work on ${item.name}`}</h2><p>{isNewDraft ? "Describe what you want to build. Codex will use the appropriate EvidenceForge skill and save the authored file in this workspace." : `Ask Codex to build, revise, or explain this ${item.kind === "scenario" ? "scenario" : "pack"}. Its source path is already in conversation context.`}</p></div>}
      {messages.map((message) => <div key={message.id} className={`message-row ${message.role}`}><div className="message-bubble"><span className="message-author">{message.role === "user" ? "You" : "Codex"}</span><p>{message.text}</p></div></div>)}
      {!!activities.length && <details className="tool-activity"><summary><ChevronDown size={15} /> {activities.length} earlier activities</summary>{activities.map((activity, index) => <div key={index}>{activityLabel(activity)} · {String(activity.status || "complete")}</div>)}</details>}
      {localTurns.map((turn) => <Fragment key={turn.localId}>{turn.userText && <div className="message-row user"><div className="message-bubble"><span className="message-author">You</span><p>{turn.userText}</p></div></div>}{turn.agentText && <div className="message-row agent"><div className="message-bubble"><span className="message-author">Codex</span><p>{turn.agentText}</p></div></div>}</Fragment>)}
      {!!liveActivity.length && <details className="tool-activity"><summary><ChevronDown size={15} /> Working · {liveActivity.length} activities</summary>{liveActivity.map((activity, index) => <div key={index}>{activityLabel(activity)} · {String(activity.status || "in progress")}</div>)}</details>}
      {conversation.active && !localTurns.some((turn) => !turn.completed && turn.agentText) && <p className="working-note"><span className="active-pulse" /> {codexHealth.state === "connected" ? "Codex is working…" : "Codex connection is uncertain…"}</p>}
      {historyPending && <p className="history-sync" role="status">{historyWarning ? "Conversation history is still unavailable. " : "Syncing conversation history…"}{historyWarning && <button type="button" onClick={() => void loadHistory(expectedTurnId.current || undefined)}>Retry</button>}</p>}
      {threadPending.map((entry) => <div className="approval-card" key={entry.request_id}><strong>{entry.method.includes("requestUserInput") ? "Codex needs your input" : "Codex requests approval"}</strong><p>{String(entry.params.reason || entry.params.command || entry.method)}</p>{entry.method.includes("requestUserInput") ? <><input aria-label="Answer Codex" value={answer} onChange={(event) => setAnswer(event.target.value)} /><button className="button-primary" onClick={() => void answerRequest(entry, { answers: Object.fromEntries(((entry.params.questions as {id: string}[]) || []).map((question) => [question.id, { answers: [answer] }])) })}>Send answer</button></> : <div className="approval-actions"><button className="button-quiet" onClick={() => void answerRequest(entry, { decision: "decline" })}>Decline</button><button className="button-primary" onClick={() => void answerRequest(entry, { decision: "accept", permissions: entry.params.permissions || {} })}>Approve</button></div>}</div>)}
    </div></div>
    <div className="composer-wrap"><div className="composer"><textarea placeholder={isNewDraft ? `Describe your new ${draftKindLabel.toLowerCase()}…` : `Ask about ${item.name}…`} aria-label="Message to Codex" value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey && !event.altKey && !event.nativeEvent.isComposing) { event.preventDefault(); void send(); } }} /><div className="composer-bottom"><div className="composer-options"><select aria-label="Skill for this turn" value={skill} onChange={(event) => setSkill(event.target.value)}><option value="">{conversation.thread_id ? "Automatic skill" : `${draftKindLabel} skill`}</option>{skills.map((entry) => <option key={entry.name} value={entry.name}>{entry.name}</option>)}</select><span>Enter to send · Shift/Alt+Enter for a new line</span></div><div className="composer-actions">{conversation.active && <button className="interrupt-button" aria-label="Stop Codex turn" onClick={() => void api.request(`/v1/conversations/${conversationId}/interrupt`, "POST").catch((error) => onError(String(error)))}><CirclePause size={17} /></button>}<button aria-label="Send message" disabled={!draft.trim() || sending || conversation.active || !status?.available || status.account_ready === false || codexHealth.state !== "connected"} onClick={() => void send()}><ArrowUp size={16} /></button></div></div></div>{codexHealth.state !== "connected" && <p className="chat-unavailable">Codex {codexHealth.state}: {codexHealth.detail}. Use the status dot above to reconnect.</p>}{status && !status.available && codexHealth.state === "connected" && <p className="chat-unavailable">{status.error || "Codex is unavailable"}</p>}{status?.account_ready === false && <p className="chat-unavailable">Sign in to Codex under Settings → Authoring & tools before sending a message.</p>}</div>
  </section>;
}
