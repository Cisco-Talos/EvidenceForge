export function packNameError(value: string): string | null {
  if (!value) return "Enter a pack name.";
  if (value.length > 80) return "Use 80 characters or fewer.";
  if (!/^[a-z0-9]/.test(value)) return "Start with a lowercase letter or digit.";
  if (!/^[a-z0-9][a-z0-9-]*$/.test(value)) return "Use lowercase letters, digits, and hyphens only.";
  return null;
}
