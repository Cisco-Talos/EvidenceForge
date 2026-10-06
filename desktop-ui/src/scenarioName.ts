/** Match the authored Scenario name contract, with Studio's input length limit. */
export function scenarioNameError(name: string): string | null {
  if (!name) return "Enter a scenario name.";
  if (name.length > 80) return "Use 80 characters or fewer.";
  if (!/^[A-Za-z0-9_-]+$/.test(name)) return "Use letters, numbers, hyphens, or underscores; no spaces.";
  return null;
}
