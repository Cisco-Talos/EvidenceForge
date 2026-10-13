import { useEffect, useId, useState } from "react";

export interface ChatQuestion { id: string; header?: string; question: string; isSecret?: boolean; options?: { label: string; description?: string }[] | null }
export function ChatQuestions({ questions, saved = {}, onChange, onSubmit, label = "Send answers", disabled = false }: {
  questions: ChatQuestion[]; saved?: Record<string, string>; onChange?: (answers: Record<string, string>) => void;
  onSubmit: (answers: Record<string, { answers: string[] }>) => Promise<void>; label?: string; disabled?: boolean;
}) {
  const groupId = useId();
  const initial = () => Object.fromEntries(questions.flatMap((question) => [[`${question.id}:choice`, saved[`${question.id}:choice`] || question.options?.find((option) => !/^other\b/i.test(option.label))?.label || "__other"], [`${question.id}:text`, saved[`${question.id}:text`] || ""]]));
  const [values, setValues] = useState<Record<string, string>>(initial);
  const [sending, setSending] = useState(false); const [error, setError] = useState("");
  useEffect(() => {
    setValues((current) => {
      const next = initial();
      for (const question of questions.filter((question) => question.isSecret)) {
        next[`${question.id}:text`] = current[`${question.id}:text`] || "";
        next[`${question.id}:choice`] = current[`${question.id}:choice`] || next[`${question.id}:choice`];
      }
      return next;
    });
  }, [questions.map((question) => question.id).join("|"), JSON.stringify(saved)]);
  function update(key: string, value: string) {
    const next = { ...values, [key]: value }; setValues(next);
    onChange?.(Object.fromEntries(Object.entries(next).filter(([name]) => !questions.some((question) => question.isSecret && name.startsWith(`${question.id}:`)))));
  }
  const valid = questions.every((question) => values[`${question.id}:choice`] !== "__other" || !!values[`${question.id}:text`]?.trim());
  async function submit() {
    setSending(true); setError("");
    try { await onSubmit(Object.fromEntries(questions.map((question) => [question.id, { answers: [values[`${question.id}:choice`] === "__other" ? values[`${question.id}:text`].trim() : values[`${question.id}:choice`]] }]))); }
    catch (issue) { setError(String(issue)); }
    finally { setSending(false); }
  }
  return <div className="clarification-card">{questions.map((question) => <fieldset key={question.id} disabled={disabled || sending}><legend>{question.header && <strong>{question.header}: </strong>}{question.question}</legend>{(question.options || []).filter((option) => !/^other\b/i.test(option.label)).map((option) => <label className="clarification-option" key={option.label}><input type="radio" name={`${groupId}-${question.id}`} checked={values[`${question.id}:choice`] === option.label} onChange={() => update(`${question.id}:choice`, option.label)} /><span><strong>{option.label}</strong>{option.description && <small>{option.description}</small>}</span></label>)}{!!question.options?.length && <label className="clarification-option"><input type="radio" name={`${groupId}-${question.id}`} checked={values[`${question.id}:choice`] === "__other"} onChange={() => update(`${question.id}:choice`, "__other")} /><span>Other</span></label>}{values[`${question.id}:choice`] === "__other" && <input aria-label={`Your answer: ${question.question}`} type={question.isSecret ? "password" : "text"} value={values[`${question.id}:text`] || ""} onChange={(event) => update(`${question.id}:text`, event.target.value)} />}</fieldset>)}{error && <p role="alert">{error}</p>}<button className="button-primary" disabled={!valid || disabled || sending} onClick={() => void submit()}>{sending ? "Sending…" : label}</button></div>;
}
