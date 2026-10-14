import { Fragment, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowUp, Check, ChevronDown, CirclePause, Pencil, MessageSquareText, X } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import { CatalogItem, CodexHealth, Conversation, StudioApi, StudioEvent, type ChatAccess } from "./api";
import { ChatActivity, type ActivityItem } from "./ChatActivity";
import { ChatMarkdown } from "./ChatMarkdown";
import { ChatCopyButton } from "./ChatCopyButton";
import { ChatQuestions, type ChatQuestion } from "./ChatQuestions";
import { ChatResults } from "./ChatResults";
import { applyChatEvent, finalItemId, formatDuration, historyTurns, mergeTurns, terminalTurn, type TimelineTurn, type TimelineItem } from "./chatTimeline";

interface TurnError { message?: string }
interface CodexHistory { thread?: { turns?: Record<string, unknown>[] }; history_pending?: boolean }
interface CodexModel { id: string; displayName?: string; isDefault?: boolean; defaultReasoningEffort?: string; supportedReasoningEfforts?: { reasoningEffort: string }[] }
interface CodexStatus { available: boolean; account_ready?: boolean; error?: string; models?: { data?: CodexModel[] }; skills?: { data?: { skills?: { name: string; enabled?: boolean }[] }[] } }
interface PendingRequest { request_id: number | string; method: string; params: Record<string, unknown> }
interface SavedView { draft: string; skill_name: string; follow_bottom: boolean; anchor: { turn_id: string; item_id: string; offset: number } | null; answers: Record<string, Record<string, string>>; pending_message?: { text: string; mode: SendMode; id: string } | null }
interface QueueMessage { id: string; text: string; skill_name?: string | null; state: string; turn_id?: string | null; error?: string | null }
interface ChatState { seq: number; turns: TimelineTurn[]; queue: QueueMessage[]; queue_paused: boolean; active_turn_id: string | null; view: SavedView; history_pending?: boolean }
type SendMode = "start" | "queue" | "steer";
const emptyView = (): SavedView => ({ draft: "", skill_name: "", follow_bottom: true, anchor: null, answers: {} });

function failedTurnText(status?: string, error?: TurnError | null): string | undefined {
  if (status !== "failed" && !error?.message) return undefined;
  const message = error?.message || "Codex could not complete this turn. Try again or choose another model.";
  try { const detail = JSON.parse(message) as { error?: { message?: unknown } }; if (typeof detail?.error?.message === "string") return detail.error.message; } catch { /* Plain errors remain readable. */ }
  return message;
}
function userText(item: TimelineItem): string { return (item.content || []).filter((part) => part.type === "text").map((part) => part.text || "").join("\n"); }

export function ChatView({ item, conversation, codexHealth, api, subscribeEvents, initialDraft, followupMode = "queue", onDraftSubmitted, onRenamed, onError }: {
  item: Pick<CatalogItem, "name" | "kind"> & Partial<Pick<CatalogItem, "path">>; conversation: Conversation | null;
  codexHealth: CodexHealth; api: StudioApi; subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  initialDraft?: string; followupMode?: "queue" | "steer"; onDraftSubmitted?: (conversationId: string) => void;
  onRenamed?: () => Promise<void>; onError: (error: string) => void;
}) {
  const conversationId = conversation?.id;
  const currentConversation = useRef(conversationId); currentConversation.current = conversationId;
  const initialDraftRef = useRef(initialDraft); initialDraftRef.current = initialDraft;
  const [turns, setTurns] = useState<TimelineTurn[]>([]); const [queue, setQueue] = useState<QueueMessage[]>([]);
  const [queuePaused, setQueuePaused] = useState(false); const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [draft, setDraft] = useState(""); const [skill, setSkill] = useState(""); const [sending, setSending] = useState(false);
  const [status, setStatus] = useState<CodexStatus | null>(null); const [access, setAccess] = useState<ChatAccess | null>(null);
  const [pending, setPending] = useState<PendingRequest[]>([]); const [answers, setAnswers] = useState<SavedView["answers"]>({});
  const [editingTitle, setEditingTitle] = useState(false); const [title, setTitle] = useState(conversation?.title || "");
  const [titleDraft, setTitleDraft] = useState(""); const [savingTitle, setSavingTitle] = useState(false);
  const [historyPending, setHistoryPending] = useState(false); const [historyWarning, setHistoryWarning] = useState(false);
  const [following, setFollowing] = useState(true); const [now, setNow] = useState(Date.now()); const [sendMenu, setSendMenu] = useState(false);
  const [editingQueue, setEditingQueue] = useState<string | null>(null); const [queueText, setQueueText] = useState("");
  const [answeredAsync, setAnsweredAsync] = useState<string[]>([]);
  const body = useRef<HTMLDivElement>(null); const savedView = useRef<SavedView>(emptyView());
  const composerTouched = useRef(false);
  const answersTouched = useRef(false);
  const loadedView = useRef(false); const restoring = useRef(false); const followBottom = useRef(true);
  const eventBuffer = useRef<StudioEvent[]>([]); const cursor = useRef(0); const requestId = useRef(0);
  const historyTimer = useRef<ReturnType<typeof setTimeout> | null>(null); const attempts = useRef(0);
  const expectedTurn = useRef<string | null>(null); const completedTurns = useRef(new Set<string>());
  const activeRef = useRef(conversation?.active); activeRef.current = conversation?.active;
  const previousHealth = useRef(codexHealth.state); const previousActive = useRef({ id: conversationId, active: conversation?.active });
  const previousAccount = useRef({ availability: codexHealth.availability, label: codexHealth.account_label });
  const optimistic = useRef(new Map<string, { turnId: string; text: string }>());
  const scrollSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryId = useRef<{ text: string; mode: SendMode; id: string } | null>(null);

  function restoreOptimistic(incoming: TimelineTurn[]): TimelineTurn[] {
    let result = [...incoming];
    for (const [id, entry] of optimistic.current) {
      const actual = result.find((turn) => turn.items.some((item) => item.type === "userMessage" && (item.clientId === id || (!item.clientId && userText(item) === entry.text))));
      if (actual) { optimistic.current.delete(id); continue; }
      const turn = result.find((turn) => turn.id === entry.turnId);
      const message: TimelineItem = { id, clientId: id, type: "userMessage", content: [{ type: "text", text: entry.text }] };
      if (turn) result = result.map((current) => current.id === turn.id ? { ...current, items: [message, ...current.items.filter((item) => item.id !== id)] } : current);
      else result.push({ id: entry.turnId, status: "inProgress", items: [message] });
    }
    return result;
  }

  const loadHistory = useCallback(async (completedId?: string, retry = false) => {
    if (!conversationId) return;
    const identity = ++requestId.current;
    if (historyTimer.current) clearTimeout(historyTimer.current);
    if (!retry) { attempts.current = 0; setHistoryWarning(false); }
    try {
      let snapshot: ChatState | null = null;
      try { snapshot = await api.request<ChatState>(`/v1/conversations/${conversationId}/chat`); } catch { /* A previous helper can still supply history. */ }
      if (identity !== requestId.current) return;
      let incoming: TimelineTurn[]; let historyIsPending = false;
      if (Array.isArray(snapshot?.turns)) {
        incoming = snapshot.turns.map((turn) => ({ ...turn, items: (turn.items || []).map((entry, position) => ({ ...entry, id: entry.id || `${turn.id}-${position}` })) }));
        const replay = eventBuffer.current.filter((event) => event.seq > snapshot.seq);
        incoming = replay.reduce(applyChatEvent, incoming);
        cursor.current = Math.max(snapshot.seq, ...replay.map((event) => event.seq));
        eventBuffer.current = replay;
        let replayActive = snapshot.active_turn_id;
        for (const event of replay) {
          const nativeTurn = (event.payload.params as { turn?: { id: string } })?.turn;
          if (event.payload.method === "turn/started" && nativeTurn?.id) replayActive = nativeTurn.id;
          if (event.payload.method === "turn/completed" && nativeTurn?.id === replayActive) replayActive = null;
        }
        setQueue(snapshot.queue || []); setQueuePaused(snapshot.queue_paused); setActiveTurnId(replayActive);
        historyIsPending = !!snapshot.history_pending;
        if (!loadedView.current) {
          const local = savedView.current;
          savedView.current = { ...emptyView(), ...snapshot.view,
            ...(composerTouched.current ? { draft: local.draft, skill_name: local.skill_name } : {}),
            ...(answersTouched.current ? { answers: { ...(snapshot.view?.answers || {}), ...local.answers } } : {}),
          };
          setDraft(savedView.current.draft || initialDraftRef.current || ""); setSkill(savedView.current.skill_name);
          const retained = savedView.current.pending_message;
          retryId.current = retained?.text === savedView.current.draft.trim() ? retained : null;
          setAnswers(savedView.current.answers); followBottom.current = savedView.current.follow_bottom;
          setFollowing(followBottom.current); loadedView.current = true; restoring.current = true;
        }
        setTurns(restoreOptimistic(incoming));
      } else {
        // Keep compatibility with a previous helper while the app is handed off.
        const history = await api.request<CodexHistory>(`/v1/conversations/${conversationId}/history`);
        if (identity !== requestId.current) return;
        incoming = historyTurns(history); historyIsPending = !!history.history_pending;
        setTurns((current) => restoreOptimistic(mergeTurns(incoming, current.filter((turn) => !incoming.some((entry) => entry.id === turn.id && terminalTurn(entry))))));
        if (!loadedView.current) { loadedView.current = true; setDraft(initialDraftRef.current || ""); }
      }
      const missing = !!completedId && !incoming.some((turn) => turn.id === completedId && terminalTurn(turn));
      setHistoryPending(historyIsPending || missing);
      if (historyIsPending || missing) {
        if (attempts.current < 6) { const delay = Math.min(350 * 2 ** attempts.current++, 3000); historyTimer.current = setTimeout(() => void loadHistory(completedId, true), delay); }
        else setHistoryWarning(true);
      } else expectedTurn.current = null;
    } catch (error) { if (identity === requestId.current && !(activeRef.current && error instanceof Error && error.name === "AbortError")) onError(String(error)); }
  }, [api, conversationId, onError]);

  useEffect(() => {
    composerTouched.current = false; answersTouched.current = false; retryId.current = null; optimistic.current.clear(); loadedView.current = false; savedView.current = emptyView(); eventBuffer.current = []; cursor.current = 0;
    completedTurns.current.clear(); expectedTurn.current = null;
    setTurns([]); setQueue([]); setDraft(""); setSkill(""); setAnswers({}); setAnsweredAsync([]); setActiveTurnId(null);
    setHistoryPending(false); setHistoryWarning(false); followBottom.current = true; setFollowing(true);
    if (!conversationId) return;
    void loadHistory();
    let canceled = false;
    void api.request<CodexStatus>("/v1/codex/status").then((value) => { if (!canceled) setStatus(value); }).catch((error) => { if (!canceled) onError(String(error)); });
    void api.request<PendingRequest[]>("/v1/codex/pending").then((value) => { if (!canceled) setPending(Array.isArray(value) ? value : []); }).catch((error) => { if (!canceled) onError(String(error)); });
    return () => {
      canceled = true; requestId.current++;
      if (historyTimer.current) clearTimeout(historyTimer.current);
      if (scrollSaveTimer.current) clearTimeout(scrollSaveTimer.current);
      if (loadedView.current) void api.request(`/v1/conversations/${conversationId}/view`, "PUT", savedView.current).catch(() => undefined);
    };
  }, [api, conversationId, loadHistory, onError]);

  useEffect(() => {
    savedView.current = { ...savedView.current, draft, skill_name: skill, answers };
    if (!conversationId || !loadedView.current) return;
    const timer = setTimeout(() => { void api.request(`/v1/conversations/${conversationId}/view`, "PUT", savedView.current).catch(onError); }, 300);
    return () => clearTimeout(timer);
  }, [api, conversationId, draft, skill, answers, following, onError]);
  useEffect(() => { setTitle(conversation?.title || ""); setEditingTitle(false); }, [conversationId, conversation?.title]);
  useEffect(() => { if (initialDraft && loadedView.current) setDraft((current) => current || initialDraft); }, [initialDraft]);
  useEffect(() => {
    let canceled = false; setAccess(null);
    if (conversationId) void api.request<ChatAccess>(`/v1/conversations/${conversationId}/access`).then((value) => { if (!canceled && value?.mode) setAccess(value); }).catch((error) => { if (!canceled) onError(String(error)); });
    return () => { canceled = true; };
  }, [api, conversationId, item.path, conversation?.active, onError]);
  useEffect(() => {
    const changed = previousAccount.current.availability !== codexHealth.availability || previousAccount.current.label !== codexHealth.account_label;
    const recovered = previousHealth.current !== "connected" && codexHealth.state === "connected";
    previousAccount.current = { availability: codexHealth.availability, label: codexHealth.account_label }; previousHealth.current = codexHealth.state;
    if ((changed || recovered) && conversationId && codexHealth.state === "connected") {
      void api.request<CodexStatus>("/v1/codex/status").then(setStatus).catch((error) => onError(String(error)));
      if (recovered) void loadHistory();
    }
  }, [api, codexHealth.availability, codexHealth.account_label, codexHealth.state, conversationId, loadHistory, onError]);
  useEffect(() => {
    const previous = previousActive.current; previousActive.current = { id: conversationId, active: conversation?.active };
    if (previous.id === conversationId && previous.active && !conversation?.active) void loadHistory(expectedTurn.current || undefined);
  }, [conversationId, conversation?.active, loadHistory]);
  useEffect(() => {
    if (!conversation?.active) return;
    setNow(Date.now()); const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [conversation?.active, activeTurnId]);

  useEffect(() => {
    if (!conversationId) return;
    return subscribeEvents((event) => {
      if (event.kind === "skills.installed") { void api.request<CodexStatus>("/v1/codex/status").then(setStatus).catch(onError); return; }
      if (event.kind === "codex.input_answered" || event.kind === "codex.input_cleared") { setPending((current) => current.filter((entry) => entry.request_id !== event.payload.request_id)); return; }
      if (event.entity_id !== conversationId) return;
      if (event.kind === "chat.updated") { void loadHistory(); return; }
      if (event.kind === "codex.input_requested") { setPending((current) => [...current.filter((entry) => entry.request_id !== event.payload.request_id), event.payload as unknown as PendingRequest]); return; }
      if (event.kind !== "conversation.event" || event.seq <= cursor.current) return;
      eventBuffer.current.push(event); cursor.current = event.seq;
      if (eventBuffer.current.length === 500) void loadHistory();
      setTurns((current) => applyChatEvent(current, event));
      const method = String(event.payload.method); const params = event.payload.params as Record<string, unknown>;
      if (method === "turn/started") { const id = (params.turn as { id?: string })?.id; if (id) setActiveTurnId(id); }
      if (method === "turn/completed") {
        const id = (params.turn as { id?: string })?.id;
        if (id) completedTurns.current.add(id);
        setActiveTurnId(null); void loadHistory(id);
      }
    });
  }, [api, conversationId, loadHistory, onError, subscribeEvents]);

  function restoreAnchor() {
    const target = body.current; const anchor = savedView.current.anchor;
    if (!target || !anchor) return;
    const row = Array.from(target.querySelectorAll<HTMLElement>("[data-chat-item]")).find((node) => node.dataset.chatTurn === anchor.turn_id && node.dataset.chatItem === anchor.item_id);
    if (row) target.scrollTop += row.getBoundingClientRect().top - target.getBoundingClientRect().top - anchor.offset;
  }
  useLayoutEffect(() => {
    if (!body.current) return;
    if (restoring.current) { restoring.current = false; if (!followBottom.current) restoreAnchor(); }
    if (followBottom.current) body.current.scrollTop = body.current.scrollHeight;
    else restoreAnchor();
  }, [turns, pending, queue, historyPending]);
  useEffect(() => {
    const target = body.current; if (!target || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => { if (followBottom.current) target.scrollTop = target.scrollHeight; else restoreAnchor(); });
    observer.observe(target); if (target.firstElementChild) observer.observe(target.firstElementChild);
    return () => observer.disconnect();
  }, [conversationId]);
  function trackScroll() {
    const target = body.current; if (!target) return;
    followBottom.current = target.scrollHeight - target.scrollTop - target.clientHeight <= 24;
    setFollowing(followBottom.current);
    const row = Array.from(target.querySelectorAll<HTMLElement>("[data-chat-item]")).find((node) => node.getBoundingClientRect().bottom > target.getBoundingClientRect().top);
    savedView.current = { ...savedView.current, follow_bottom: followBottom.current, anchor: row ? { turn_id: row.dataset.chatTurn || "", item_id: row.dataset.chatItem || "", offset: row.getBoundingClientRect().top - target.getBoundingClientRect().top } : null };
    if (scrollSaveTimer.current) clearTimeout(scrollSaveTimer.current);
    if (conversationId && loadedView.current) scrollSaveTimer.current = setTimeout(() => { void api.request(`/v1/conversations/${conversationId}/view`, "PUT", savedView.current).catch(() => undefined); }, 300);
  }

  const models = status?.models?.data || []; const defaultModel = models.find((model) => model.isDefault) || models[0];
  const selectedModel = models.find((model) => model.id === conversation?.model_id) || defaultModel;
  const efforts = selectedModel?.supportedReasoningEfforts || [];
  const selectedEffort = conversation?.reasoning_effort || selectedModel?.defaultReasoningEffort || efforts[0]?.reasoningEffort || "medium";
  const skills = Array.from(new Map((status?.skills?.data || []).flatMap((group) => group.skills || []).filter((entry) => entry.enabled !== false && entry.name.startsWith("eforge-")).map((entry) => [entry.name, entry])).values());
  const threadPending = pending.filter((entry) => !entry.params.threadId || entry.params.threadId === conversation?.thread_id);
  const draftKindLabel = item.kind === "scenario" ? "Scenario" : item.kind === "industry_pack" ? "Industry pack" : "Organization pack";
  const isNewDraft = !!conversation?.draft_kind && !conversation.item_id;
  const enabled = codexHealth.state === "connected" && status?.available && status.account_ready !== false && (codexHealth.availability === undefined || codexHealth.availability === "ready");
  const currentMode: SendMode = conversation?.active ? followupMode : "start";
  const modeLabel = (mode: SendMode) => mode === "start" ? "Send message" : mode === "queue" ? "Queue message" : "Steer current work";

  async function updatePreferences(changes: Record<string, string | null>) {
    if (conversationId) try { await api.request(`/v1/conversations/${conversationId}`, "PATCH", changes); } catch (error) { onError(String(error)); }
  }
  async function saveTitle() {
    const value = titleDraft.trim(); if (!conversationId || !value || savingTitle) return;
    setSavingTitle(true);
    try { await api.request(`/v1/conversations/${conversationId}`, "PATCH", { title: value }); setTitle(value); setEditingTitle(false); await onRenamed?.(); }
    catch (error) { onError(String(error)); } finally { setSavingTitle(false); }
  }
  async function send(mode: SendMode = currentMode, suppliedText?: string, messageId?: string) {
    const text = (suppliedText ?? draft).trim(); if (!conversationId || !text || sending || !enabled) {
      if (suppliedText !== undefined) throw new Error("Codex is unavailable. Your answers have not been sent.");
      return;
    }
    const identity = messageId || (retryId.current?.text === text && retryId.current.mode === mode ? retryId.current.id : crypto.randomUUID());
    retryId.current = { text, mode, id: identity }; setSending(true);
    const submittedView = { ...savedView.current };
    try {
      if (suppliedText === undefined) submittedView.pending_message = savedView.current.pending_message = retryId.current;
      // Save the identity before delivery so a reopened composer retries the same claim.
      await api.request(`/v1/conversations/${conversationId}/view`, "PUT", submittedView);
      const entry = await api.request<QueueMessage>(`/v1/conversations/${conversationId}/messages`, "POST", { message_id: identity, text, mode, skill_name: mode === "steer" ? null : skill || null, expected_turn_id: mode === "steer" ? activeTurnId : null });
      if (entry.state === "rejected") throw new Error(entry.error || "Your message was not sent");
      if (entry.state === "uncertain") throw new Error("Codex has not confirmed delivery. Studio will check before sending again.");
      if (currentConversation.current !== conversationId) {
        if (suppliedText === undefined) await api.request(`/v1/conversations/${conversationId}/view`, "PUT", { ...submittedView, draft: "", skill_name: "", pending_message: null });
        return;
      }
      if (entry.state !== "queued" && entry.turn_id) {
        optimistic.current.set(identity, { turnId: entry.turn_id, text });
        setTurns((current) => restoreOptimistic(current));
      }
      if (suppliedText === undefined) {
        if (savedView.current.draft.trim() === text) { setDraft(""); setSkill(""); savedView.current = { ...savedView.current, draft: "", skill_name: "", pending_message: null }; }
        else savedView.current.pending_message = null;
      }
      retryId.current = null;
      if (entry.turn_id) { expectedTurn.current = entry.turn_id; if (!completedTurns.current.has(entry.turn_id)) setActiveTurnId(entry.turn_id); }
      await loadHistory(entry.turn_id && completedTurns.current.has(entry.turn_id) ? entry.turn_id : undefined);
      onDraftSubmitted?.(conversationId);
    } catch (error) { onError(String(error)); if (currentConversation.current === conversationId) await loadHistory(); throw error; }
    finally { setSending(false); setSendMenu(false); }
  }
  async function answerRequest(entry: PendingRequest, result: Record<string, unknown>) {
    await api.request("/v1/codex/reply", "POST", { request_id: entry.request_id, result });
    setPending((current) => current.filter((candidate) => candidate.request_id !== entry.request_id));
    setAnswers((current) => { const next = { ...current }; delete next[String(entry.request_id)]; return next; });
  }
  async function editQueued(entry: QueueMessage) {
    try { await api.request(`/v1/conversations/${conversationId}/messages/${entry.id}`, "PATCH", { text: queueText, skill_name: entry.skill_name || null }); setEditingQueue(null); await loadHistory(); } catch (error) { onError(String(error)); }
  }
  function saveAnswer(key: string, value: Record<string, string>) {
    answersTouched.current = true;
    savedView.current.answers = { ...savedView.current.answers, [key]: { ...savedView.current.answers[key], ...value } };
    setAnswers((current) => ({ ...current, [key]: { ...current[key], ...value } }));
  }
  function renderItem(turn: TimelineTurn, entry: TimelineItem) {
    const text = entry.type === "userMessage" ? userText(entry) : entry.text || "";
    const final = entry.type === "agentMessage" && (entry.phase === "final_answer" || finalItemId(turn) === entry.id);
    const questions = (entry.questions as { title: string; options?: string[] | null }[] | null)?.map((question, index) => ({ id: `${entry.id}-${index}`, question: question.title, options: question.options?.map((label) => ({ label })) }));
    return <div key={entry.id} data-chat-item={entry.id} data-chat-turn={turn.id} className="timeline-entry">
      {entry.type === "userMessage" || entry.type === "agentMessage" ? <>
        {final && terminalTurn(turn) && turn.duration_ms != null && <div className="worked-duration">{turn.status === "completed" ? "Worked for" : turn.status === "failed" ? "Failed after" : "Stopped after"} {formatDuration(turn.duration_ms)}</div>}
        {text && (entry.type === "userMessage" || final ? <div className={`message-row ${entry.type === "userMessage" ? "user" : "agent"}`}><div className="message-bubble"><div className="message-label"><span className="message-author">{entry.type === "userMessage" ? "You" : "Codex"}</span><ChatCopyButton text={text} onError={onError} /></div>{entry.type === "userMessage" ? <p>{text}</p> : <ChatMarkdown text={text} />}</div></div> : <div className="chat-commentary"><ChatMarkdown text={text} /><ChatCopyButton text={text} onError={onError} /></div>)}
        {!!questions?.length && !answeredAsync.includes(entry.id) && answers[entry.id]?.__answered !== "1" && (!answers[entry.id]?.__submissionId || !turns.some((candidate) => candidate.items.some((message) => message.type === "userMessage" && message.clientId === answers[entry.id]?.__submissionId))) && <ChatQuestions key={entry.id} questions={questions} disabled={!enabled || sending || (!!conversation?.active && !activeTurnId)} saved={answers[entry.id]} onChange={(value) => saveAnswer(entry.id, value)} onSubmit={async (value) => { const answer = questions.map((question) => `${question.question}\n${value[question.id].answers.join("\n")}`).join("\n\n"); const identity = savedView.current.answers[entry.id]?.__submissionId || crypto.randomUUID(); saveAnswer(entry.id, { ...savedView.current.answers[entry.id], __submissionId: identity }); await send(conversation?.active ? "steer" : "start", answer, identity); setAnsweredAsync((current) => [...current, entry.id]); saveAnswer(entry.id, { ...savedView.current.answers[entry.id], __answered: "1" }); }} />}
        {final && !!turn.results?.length && <ChatResults results={turn.results} />}
      </> : <ChatActivity items={[entry as ActivityItem]} working={!terminalTurn(turn)} inline />}
    </div>;
  }
  if (!conversation) return <section className="chat-panel"><div className="chat-body"><div className="chat-welcome"><MessageSquareText size={26} /><h2>Select a conversation</h2></div></div></section>;
  const working = [...turns].reverse().find((turn) => !terminalTurn(turn));
  return <section className="chat-panel">
    <div className="chat-topline"><div className="chat-title-area">{editingTitle ? <form className="chat-title-edit" onSubmit={(event) => { event.preventDefault(); void saveTitle(); }}><input autoFocus aria-label="Conversation title" value={titleDraft} maxLength={80} disabled={savingTitle} onChange={(event) => setTitleDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Escape") { setEditingTitle(false); event.preventDefault(); } }} /><button className="icon-button" aria-label="Save conversation title" disabled={!titleDraft.trim() || savingTitle}><Check size={15} /></button><button type="button" className="icon-button" aria-label="Cancel rename" onClick={() => setEditingTitle(false)}><X size={15} /></button></form> : <button className="chat-title-button" aria-label={`Rename conversation ${title}`} title="Rename conversation" onClick={() => { setTitleDraft(title); setEditingTitle(true); }}><strong>{title}</strong><Pencil size={13} /></button>}<span>{item.name}</span></div><div className="chat-pickers"><label>Model<select aria-label="Model" value={conversation.model_id || defaultModel?.id || ""} onChange={(event) => void updatePreferences({ model_id: event.target.value })}>{conversation.model_id && !models.some((model) => model.id === conversation.model_id) && <option value={conversation.model_id} disabled>{conversation.model_id} (unavailable)</option>}{models.map((model) => <option key={model.id} value={model.id}>{model.displayName || model.id}</option>)}</select></label><label>Reasoning<select aria-label="Reasoning" value={selectedEffort} onChange={(event) => void updatePreferences({ reasoning_effort: event.target.value })}>{efforts.map((effort) => <option key={effort.reasoningEffort} value={effort.reasoningEffort}>{effort.reasoningEffort}</option>)}</select></label></div></div>
    {access?.mode === "discussion" && <p className="chat-connection-note" role="status">{access.version ? `Discussing published version ${access.version} — read-only.` : "Read-only discussion."}</p>}{conversation.connection_note && <p className="chat-connection-note" role="status">{conversation.connection_note}</p>}
    <div className="chat-body" ref={body} onScroll={trackScroll}><div className="message-list">
      {!turns.length && !conversation.active && <div className="chat-welcome"><MessageSquareText size={25} /><h2>{isNewDraft ? `Create a ${draftKindLabel.toLowerCase()}` : `Work on ${item.name}`}</h2><p>{access?.mode === "discussion" ? `Ask questions about this ${item.kind === "scenario" ? "scenario" : "pack"}. This conversation can read and explain its contents.` : "Ask Codex to build, revise, or explain this source."}</p></div>}
      {turns.map((turn) => <Fragment key={turn.id}>{turn.items.map((entry) => renderItem(turn, entry))}{failedTurnText(turn.status, turn.error) && <div className="message-row error"><div className="message-bubble" role="alert"><span className="message-author">Codex error</span><p>{failedTurnText(turn.status, turn.error)}</p></div></div>}{terminalTurn(turn) && !finalItemId(turn) && turn.duration_ms != null && <div className="worked-duration">{turn.status === "completed" ? "Worked for" : turn.status === "failed" ? "Failed after" : "Stopped after"} {formatDuration(turn.duration_ms)}</div>}</Fragment>)}
      {(conversation.active || sending) && <p className="working-note"><span className="active-pulse" />{working?.started_at ? `Working for ${formatDuration(now - working.started_at * 1000)}` : codexHealth.state === "connected" ? "Codex is working…" : "Codex connection is uncertain…"}</p>}
      {historyPending && <p className="history-sync" role="status">{historyWarning ? "Conversation history is still unavailable. " : "Syncing conversation history…"}{historyWarning && <button onClick={() => void loadHistory(expectedTurn.current || undefined)}>Retry</button>}</p>}
      {threadPending.map((entry) => <ChatQuestions key={entry.request_id} disabled={codexHealth.state !== "connected"} questions={(entry.params.questions || []) as ChatQuestion[]} saved={answers[String(entry.request_id)]} onChange={(value) => saveAnswer(String(entry.request_id), value)} onSubmit={(value) => answerRequest(entry, { answers: value })} />)}
    </div></div>
    {!following && <button className="jump-latest" onClick={() => { followBottom.current = true; setFollowing(true); savedView.current.follow_bottom = true; if (body.current) body.current.scrollTop = body.current.scrollHeight; }}>Jump to latest <ChevronDown size={14} /></button>}
    {!!queue.length && <div className="chat-queue"><div className="queue-heading"><strong>{queuePaused ? "Queue paused" : "Queued messages"}</strong>{queuePaused && <button onClick={() => void api.request(`/v1/conversations/${conversationId}/queue/resume`, "POST").then(() => loadHistory()).catch(onError)}>Resume queue</button>}</div>{queue.map((entry) => <div className="queue-entry" key={entry.id}>{editingQueue === entry.id ? <><textarea aria-label="Edit queued message" value={queueText} onChange={(event) => setQueueText(event.target.value)} /><button disabled={!queueText.trim()} onClick={() => void editQueued(entry)}>Save</button><button onClick={() => setEditingQueue(null)}>Cancel</button></> : <><span>{entry.text}{entry.error && <small className="error-text">{entry.error}</small>}</span>{entry.state === "queued" ? <><button aria-label="Edit queued message" onClick={() => { setEditingQueue(entry.id); setQueueText(entry.text); }}>Edit</button><button aria-label="Remove queued message" onClick={() => void api.request(`/v1/conversations/${conversationId}/messages/${entry.id}`, "DELETE").then(() => loadHistory()).catch(onError)}>Remove</button></> : <small>{entry.state === "uncertain" ? "Checking delivery…" : "Sending…"}</small>}</>}</div>)}</div>}
    <div className="composer-wrap"><div className="composer"><textarea placeholder={isNewDraft ? `Describe your new ${draftKindLabel.toLowerCase()}…` : `Ask about ${item.name}…`} aria-label="Message to Codex" value={draft} onChange={(event) => { composerTouched.current = true; setDraft(event.target.value); savedView.current.draft = event.target.value; }} onKeyDown={(event) => { if (event.key !== "Enter" || event.shiftKey || event.altKey || event.nativeEvent.isComposing) return; event.preventDefault(); const alternative = /Mac/i.test(navigator.platform) ? event.metaKey : event.ctrlKey; const mode = conversation.active && alternative ? followupMode === "queue" ? "steer" : "queue" : currentMode; void send(mode).catch(() => undefined); }} /><div className="composer-bottom"><div className="composer-options"><select aria-label="Skill for this turn" title="Skills apply to new or queued turns" value={skill} onChange={(event) => { composerTouched.current = true; setSkill(event.target.value); savedView.current.skill_name = event.target.value; }}><option value="">{conversation.thread_id ? "Automatic skill" : `${draftKindLabel} skill`}</option>{skills.map((entry) => <option key={entry.name} value={entry.name}>{entry.name}</option>)}</select><span>Enter to {currentMode === "start" ? "send" : currentMode} · {conversation.active ? "Cmd/Ctrl+Enter for the other mode · " : ""}Shift/Alt+Enter for a new line</span></div><div className="composer-actions">{conversation.active && <button className="interrupt-button" aria-label="Stop Codex turn" onClick={() => void api.request(`/v1/conversations/${conversationId}/interrupt`, "POST").then(() => loadHistory()).catch((error) => onError(String(error)))}><CirclePause size={17} /></button>}<button aria-label={modeLabel(currentMode)} title={modeLabel(currentMode)} disabled={!draft.trim() || sending || !enabled || (currentMode === "steer" && !activeTurnId)} onClick={() => void send().catch(() => undefined)}><ArrowUp size={16} /></button>{conversation.active && <DropdownMenu.Root open={sendMenu} onOpenChange={setSendMenu}><DropdownMenu.Trigger asChild><button aria-label="Choose Queue or Steer"><ChevronDown size={14} /></button></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="send-mode-menu" side="top" align="end" sideOffset={6}><DropdownMenu.Item disabled={!draft.trim() || sending || !enabled} onSelect={() => void send("queue").catch(() => undefined)}>Queue message</DropdownMenu.Item><DropdownMenu.Item disabled={!draft.trim() || sending || !enabled || !activeTurnId} onSelect={() => void send("steer").catch(() => undefined)}>Steer current work</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>}</div></div></div>{codexHealth.state !== "connected" && <p className="chat-unavailable">Codex {codexHealth.state}: {codexHealth.detail}. Use the status dot above to reconnect.</p>}{status && !status.available && codexHealth.state === "connected" && <p className="chat-unavailable">{status.error || "Codex is unavailable"}</p>}{status?.account_ready === false && <p className="chat-unavailable">Sign in to Codex under Settings → Authoring & tools, or use Login in the Codex status dialog, before sending a message.</p>}</div>
  </section>;
}
