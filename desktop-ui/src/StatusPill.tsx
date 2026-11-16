import { Tooltip } from "radix-ui";
import { CheckCircle2, CircleMinus, Clock3, LoaderCircle, TriangleAlert, XCircle } from "lucide-react";
import type { OperationState } from "./ScenarioStates";

export type StatusTone = "ok" | "warn" | "err" | "info" | "neutral";

const toneIcons = { ok: CheckCircle2, warn: TriangleAlert, err: XCircle, info: LoaderCircle, neutral: CircleMinus };

/** The one Studio status indicator: a tone, an icon and a 1–3 word label, with optional detail on hover. */
export function StatusPill({ tone, label, detail, icon = true, spinning = tone === "info", ariaLabel }: {
  tone: StatusTone; label: string; detail?: string; icon?: boolean; spinning?: boolean;
  /** Accessible name when the visible label needs context, e.g. "Generation: completed…". */
  ariaLabel?: string;
}) {
  const Icon = tone === "neutral" && label.toLowerCase().includes("stale") ? Clock3 : toneIcons[tone];
  const pill = <span className={`status-pill tone-${tone}`} aria-label={ariaLabel || (detail ? `${label}: ${detail}` : undefined)} tabIndex={detail ? 0 : undefined}>
    {icon && <Icon size={12} aria-hidden="true" className={spinning ? "spinning" : undefined} />}<span>{label}</span>
  </span>;
  if (!detail) return pill;
  return <Tooltip.Root>
    <Tooltip.Trigger asChild>{pill}</Tooltip.Trigger>
    <Tooltip.Portal><Tooltip.Content className="state-tooltip" sideOffset={6}>{detail}<Tooltip.Arrow className="state-tooltip-arrow" /></Tooltip.Content></Tooltip.Portal>
  </Tooltip.Root>;
}

const jobTones: Record<string, StatusTone> = {
  completed: "ok", running: "info", queued: "neutral", paused: "warn", failed: "err", stopped: "neutral", cancelled: "neutral", interrupted: "warn",
};

/** Status of a generation or evaluation job, e.g. "Running", "Completed". */
export function JobStatusPill({ status, detail }: { status: string; detail?: string }) {
  const key = status.toLowerCase();
  return <StatusPill tone={jobTones[key] || "neutral"} label={status.charAt(0).toUpperCase() + status.slice(1)} detail={detail} spinning={key === "running"} />;
}

/**
 * Collapse validation, generation and evaluation into the single most useful status for a row:
 * active work first, then failures, then the furthest completed stage.
 */
export function summarizeStates(states: OperationState[]): { tone: StatusTone; label: string; detail: string } {
  const [validation, generation, evaluation] = states;
  const detail = states.map((state) => `${state.label}: ${state.detail}`).join("\n");
  const working = states.find((state) => state.state === "working");
  if (working) return { tone: "info", label: `${working.label === "Validation" ? "Validating" : working.label === "Generation" ? "Generating" : "Evaluating"}`, detail };
  const failed = states.find((state) => state.state === "error");
  if (failed) {
    const label = failed.label === "Validation" ? "Invalid" : failed.label === "Evaluation" && failed.detail.startsWith("Failed acceptance") ? "Failed acceptance" : `${failed.label} failed`;
    return { tone: "err", label, detail };
  }
  const score = evaluation?.detail.match(/·\s*(\d+)\/100/)?.[1];
  if (evaluation?.state === "success") return { tone: "ok", label: score ? `Passed · ${score}` : "Passed", detail };
  if (evaluation?.state === "warning") return { tone: "warn", label: score ? `Evaluated · ${score}` : "Evaluated", detail };
  if (generation?.state === "success") return { tone: "ok", label: "Generated", detail };
  if (generation?.state === "warning") return { tone: "warn", label: "Inputs unverified", detail };
  if (validation?.state === "warning") {
    const count = Number(validation.detail.match(/with (\d+) warning/)?.[1] || 0);
    return { tone: "warn", label: count ? `${count} ${count === 1 ? "warning" : "warnings"}` : "Warnings", detail };
  }
  if (validation?.state === "success") return { tone: "ok", label: "Valid", detail };
  if (validation?.state === "stale") return { tone: "neutral", label: "Stale", detail };
  return { tone: "neutral", label: "Not validated", detail };
}
