import type { ReactElement } from "react";
import { Check, LoaderCircle, TriangleAlert, X } from "lucide-react";
import type { OperationState } from "./ScenarioStates";
import { ActionShortcut, type ObjectAction } from "./ObjectActions";

export type StepTone = "ok" | "warn" | "err" | "info" | "todo";
export type StepId = "author" | "environment" | "validate" | "generate" | "evaluate";

export interface PipelineStep { id: StepId; label: string; tone: StepTone; detail: string; status: string }

const tones: Record<OperationState["state"], StepTone> = { success: "ok", warning: "warn", error: "err", working: "info", stale: "warn", none: "todo" };

/** Errors cover failed, stopped and cancelled jobs; name which one happened. */
function endedLabel(detail: string): string {
  return /\bstopped\b/.test(detail) ? "Stopped" : /\bcancelled\b/.test(detail) ? "Cancelled" : "Failed";
}

function score(detail: string): string | undefined {
  return detail.match(/·\s*(\d+)\/100/)?.[1];
}

/**
 * Translate the existing operation states into the five readiness steps. This adds no status
 * logic of its own: every tone comes from `scenarioStates`/`environmentState`.
 */
export function readinessSteps({ starter, conversations, authoring, environment, states }: {
  starter: boolean; conversations: number; authoring: boolean; environment: OperationState; states: OperationState[];
}): PipelineStep[] {
  const [validation, generation, evaluation] = states;
  const warnings = Number(validation.detail.match(/with (\d+) warning/)?.[1] || 0);
  const errors = Number(validation.detail.match(/^(\d+) validation error/)?.[1] || 0);
  const evaluationScore = score(evaluation.detail);
  const author: PipelineStep = starter
    ? { id: "author", label: "Author", tone: "todo", status: "Not started", detail: "Continue the conversation to write this scenario." }
    : authoring ? { id: "author", label: "Author", tone: "info", status: "Codex working", detail: "An authoring turn is in progress." }
      : { id: "author", label: "Author", tone: "ok", status: conversations ? `${conversations} ${conversations === 1 ? "conversation" : "conversations"}` : "Authored", detail: "The scenario source exists." };
  const statusFor = {
    environment: { ok: "Ready", warn: "Check", err: "Needs attention", info: "Checking…", todo: "Not checked" },
    validate: { ok: "Valid", warn: validation.state === "stale" ? "Stale" : warnings ? `${warnings} ${warnings === 1 ? "warning" : "warnings"}` : "Warnings", err: errors ? `${errors} ${errors === 1 ? "error" : "errors"}` : "Invalid", info: "Validating…", todo: "Not validated" },
    generate: { ok: "Generated", warn: generation.state === "stale" ? "Stale" : "Inputs unverified", err: endedLabel(generation.detail), info: "Generating…", todo: "Not run" },
    evaluate: { ok: evaluationScore ? `Passed · ${evaluationScore}` : "Passed", warn: evaluation.state === "stale" ? "Stale" : evaluationScore ? `Evaluated · ${evaluationScore}` : "Evaluated", err: evaluation.detail.startsWith("Failed acceptance") ? "Failed acceptance" : endedLabel(evaluation.detail), info: "Evaluating…", todo: "Not run" },
  };
  const step = (id: Exclude<StepId, "author">, label: string, state: OperationState): PipelineStep => {
    const tone = tones[state.state];
    return { id, label, tone, status: statusFor[id][tone], detail: state.detail };
  };
  return [author, step("environment", "Environment", environment), step("validate", "Validate", validation), step("generate", "Generate", generation), step("evaluate", "Evaluate", evaluation)];
}

export interface NextStepActions {
  author: ObjectAction; environment: ObjectAction; validate: ObjectAction; fix: ObjectAction;
  generate: ObjectAction; viewRun: ObjectAction; export?: ObjectAction;
}

/** The single most useful action for the current readiness, in pipeline order. */
export function nextStep(steps: PipelineStep[], actions: NextStepActions, hasFindings: boolean): ObjectAction | null {
  const tone = Object.fromEntries(steps.map((entry) => [entry.id, entry.tone])) as Record<StepId, StepTone>;
  if (tone.author === "todo") return actions.author;
  if (tone.environment === "err") return actions.environment;
  if (tone.validate === "info" || tone.generate === "info" || tone.evaluate === "info") return tone.validate === "info" ? null : actions.viewRun;
  if (tone.validate === "err") return hasFindings ? actions.fix : actions.validate;
  if (tone.validate === "todo" || (tone.validate === "warn" && steps[2].status === "Stale")) return actions.validate;
  if (tone.generate !== "ok") return actions.generate;
  if (tone.evaluate !== "ok") return actions.viewRun;
  return actions.export || null;
}

const stepIcons: Record<StepTone, (props: { size: number }) => ReactElement> = {
  ok: ({ size }) => <Check size={size} />, warn: ({ size }) => <TriangleAlert size={size} />, err: ({ size }) => <X size={size} />,
  info: ({ size }) => <LoaderCircle size={size} className="spinning" />, todo: () => <span className="step-dot" />,
};

/** The workspace's readiness strip: five labeled steps and the one next action. */
export function ReadinessPipeline({ steps, next, hint, onStep }: {
  steps: PipelineStep[]; next: ObjectAction | null; hint?: string; onStep: (step: StepId) => void;
}) {
  return <section className="readiness" aria-label="Readiness">
    <ol className="readiness-steps">{steps.map((entry, index) => {
      const Icon = stepIcons[entry.tone];
      return <li key={entry.id} className={`readiness-step tone-${entry.tone}`}>
        {index > 0 && <span className={`readiness-connector ${steps[index - 1].tone === "ok" ? "done" : ""}`} aria-hidden="true" />}
        <button type="button" title={entry.detail} aria-label={`${entry.label}: ${entry.status}`} onClick={() => onStep(entry.id)}>
          <span className="readiness-icon" aria-hidden="true"><Icon size={13} /></span>
          <span className="readiness-copy"><strong>{entry.label}</strong><small>{entry.status}</small></span>
        </button>
      </li>;
    })}</ol>
    {next && <div className="readiness-next"><ActionShortcut action={next} primary className="readiness-action" />{hint && <small>{hint}</small>}</div>}
  </section>;
}
