import type { ReactElement } from "react";
import { Check, LoaderCircle, Network, TriangleAlert, X } from "lucide-react";
import type { OperationState } from "./ScenarioStates";
import { ActionShortcut, type ObjectAction } from "./ObjectActions";

export type StepTone = "ok" | "warn" | "err" | "info" | "todo" | "neutral";
export type StepId = "author" | "environment" | "validate" | "visualize" | "generate" | "evaluate";

export interface PipelineStep { id: StepId; label: string; tone: StepTone; detail: string; status: string }

const tones: Record<OperationState["state"], Exclude<StepTone, "neutral">> = { success: "ok", warning: "warn", error: "err", working: "info", stale: "warn", none: "todo" };

/** Errors cover failed, stopped and cancelled jobs; name which one happened. */
function endedLabel(detail: string): string {
  return /\bstopped\b/.test(detail) ? "Stopped" : /\bcancelled\b/.test(detail) ? "Cancelled" : "Failed";
}

function score(detail: string): string | undefined {
  return detail.match(/·\s*(\d+)\/100/)?.[1];
}

/**
 * Translate the existing operation states into readiness steps and include the diagram review.
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
  const step = (id: keyof typeof statusFor, label: string, state: OperationState): PipelineStep => {
    const tone = tones[state.state];
    return { id, label, tone, status: statusFor[id][tone], detail: state.detail };
  };
  return [
    author,
    step("environment", "Environment", environment),
    step("validate", "Validate", validation),
    { id: "visualize", label: "Visualize", tone: "neutral", status: "Review diagram", detail: "Open the network diagram for review." },
    step("generate", "Generate", generation),
    step("evaluate", "Evaluate", evaluation),
  ];
}

export interface NextStepActions {
  author: ObjectAction; environment: ObjectAction; validate: ObjectAction; fix: ObjectAction;
  visualize: ObjectAction; generate: ObjectAction; viewRun: ObjectAction; export?: ObjectAction;
  /** Evaluate the latest completed run; `reevaluate` retries an evaluation job that failed. */
  evaluate: ObjectAction; reevaluate: ObjectAction;
}

/** The single most useful action for the current readiness, in pipeline order. */
export function nextStep(steps: PipelineStep[], actions: NextStepActions, hasFindings: boolean, diagramOpened = false): ObjectAction | null {
  const byId = Object.fromEntries(steps.map((entry) => [entry.id, entry])) as Record<StepId, PipelineStep>;
  const { author, environment, validate, generate, evaluate } = byId;
  if (author.tone === "todo") return actions.author;
  if (environment.tone === "err") return actions.environment;
  if (validate.tone === "info" || generate.tone === "info" || evaluate.tone === "info") return validate.tone === "info" ? null : actions.viewRun;
  if (validate.tone === "err") return hasFindings ? actions.fix : actions.validate;
  if (validate.tone === "todo" || validate.status === "Stale") return actions.validate;
  if (!diagramOpened && (generate.tone === "todo" || generate.status === "Stale")) return actions.visualize;
  if (generate.tone !== "ok") return actions.generate;
  if (evaluate.tone === "todo" || evaluate.status === "Stale") return actions.evaluate;
  // A failed acceptance is a real result: re-running gives the same answer, so show the scorecard.
  if (evaluate.tone === "err" && evaluate.status !== "Failed acceptance") return actions.reevaluate;
  if (evaluate.tone !== "ok") return actions.viewRun;
  return actions.export || null;
}

const stepIcons: Record<StepTone, (props: { size: number }) => ReactElement> = {
  ok: ({ size }) => <Check size={size} />, warn: ({ size }) => <TriangleAlert size={size} />, err: ({ size }) => <X size={size} />,
  info: ({ size }) => <LoaderCircle size={size} className="spinning" />, todo: () => <span className="step-dot" />,
  neutral: ({ size }) => <Network size={size} />,
};

/**
 * The workspace's readiness strip and its next action. Environment stays in `steps` so
 * an environment problem can still be the promoted action.
 */
export function ReadinessPipeline({ steps: allSteps, next, hint, onStep }: {
  steps: PipelineStep[]; next: ObjectAction | null; hint?: string; onStep: (step: StepId) => void;
}) {
  const steps = allSteps.filter((entry) => entry.id !== "environment");
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
