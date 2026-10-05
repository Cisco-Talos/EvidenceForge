export type FieldSchema = {
  type?: string; title?: string; description?: string; enum?: unknown[]; const?: unknown;
  default?: unknown; items?: FieldSchema; anyOf?: FieldSchema[]; oneOf?: FieldSchema[];
  $ref?: string; properties?: Record<string, FieldSchema>; required?: string[];
  additionalProperties?: FieldSchema | boolean; propertyNames?: FieldSchema;
  patternProperties?: Record<string, FieldSchema>;
  format?: string; pattern?: string; minLength?: number; maxLength?: number;
  minimum?: number; maximum?: number; exclusiveMinimum?: number; exclusiveMaximum?: number;
  minItems?: number; maxItems?: number; minProperties?: number;
  "x-asset-choices"?: string; "x-asset-custom"?: boolean; "x-asset-enum"?: string[];
};

export function resolveSchema(raw: FieldSchema, document: Record<string, unknown>, value?: unknown): FieldSchema {
  const { $ref, ...rest } = raw;
  const schema = $ref ? { ...((document.$defs as Record<string, FieldSchema> | undefined)?.[$ref.split("/").pop()!] || {}), ...rest } : rest;
  const variants = (schema.anyOf || schema.oneOf)?.filter((entry) => entry.type !== "null");
  if (variants?.length) {
    const options = variants.map((entry) => resolveSchema(entry, document, value));
    const matching = options.find((entry) => entry.properties && Object.entries(entry.properties).some(([key, field]) => field.const !== undefined && field.const === (value as Record<string, unknown> | undefined)?.[key]));
    return { ...schema, ...(matching || options[0]) };
  }
  return schema;
}

export function choicesFor(schema: FieldSchema): string[] | undefined {
  if (schema.enum) return schema.enum.map(String);
  const alternatives = schema.pattern?.match(/^\^\(([^)]+)\)\$$/)?.[1];
  return alternatives && alternatives.split("|").every((entry) => /^[a-zA-Z0-9_-]+$/.test(entry)) ? alternatives.split("|") : undefined;
}

export function labelFor(name: string, schema?: FieldSchema): string {
  return schema?.title || name.replace(/_/g, " ").replace(/^./, (first) => first.toUpperCase());
}

export function seedValue(raw: FieldSchema, document: Record<string, unknown>): unknown {
  const schema = resolveSchema(raw, document);
  if (schema.const !== undefined) return schema.const;
  if (schema.default !== undefined && schema.default !== null) return structuredClone(schema.default);
  if (schema.type === "object" || schema.properties) {
    return Object.fromEntries(Object.entries(schema.properties || {}).filter(([name, field]) => schema.required?.includes(name) || (field.default !== undefined && field.default !== null)).map(([name, field]) => [name, seedValue(field, document)]));
  }
  if (schema.type === "array") return [];
  if (schema.type === "boolean") return false;
  return "";
}

export function fieldErrors(raw: FieldSchema, document: Record<string, unknown>, value: unknown, path = "", required = true): string[] {
  const schema = resolveSchema(raw, document, value);
  const nullable = (raw.anyOf || raw.oneOf)?.some((entry) => entry.type === "null");
  const name = path || "Asset";
  if (value === undefined || value === null || value === "") return required && !nullable ? [`${name} is required.`] : [];
  const errors: string[] = [];
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) errors.push(`${name} needs at least ${schema.minLength} characters.`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errors.push(`${name} allows at most ${schema.maxLength} characters.`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${name} has an invalid format.`);
    if (schema.format === "date" && !/^\d{4}-\d{2}-\d{2}$/.test(value)) errors.push(`${name} needs a date.`);
    if (schema.format === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) errors.push(`${name} needs a valid email address.`);
  }
  if ((schema.type === "number" || schema.type === "integer") && typeof value === "number") {
    if (!Number.isFinite(value) || (schema.type === "integer" && !Number.isInteger(value))) errors.push(`${name} needs a valid ${schema.type}.`);
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${name} must be at least ${schema.minimum}.`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${name} must be at most ${schema.maximum}.`);
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) errors.push(`${name} must be greater than ${schema.exclusiveMinimum}.`);
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) errors.push(`${name} must be less than ${schema.exclusiveMaximum}.`);
  }
  const options = choicesFor(schema);
  if (options && !options.includes(String(value))) errors.push(`${name} must be one of the available choices.`);
  if (Array.isArray(value)) {
    if (schema.minItems && value.length < schema.minItems) errors.push(`${name} needs at least ${schema.minItems} item(s).`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${name} allows at most ${schema.maxItems} item(s).`);
    value.forEach((entry, index) => errors.push(...fieldErrors(schema.items || {}, document, entry, `${name} ${index + 1}`)));
  } else if (typeof value === "object") {
    const entries = value as Record<string, unknown>;
    if (schema.minProperties && Object.keys(entries).length < schema.minProperties) errors.push(`${name} needs at least one entry.`);
    for (const [key, child] of Object.entries(schema.properties || {})) errors.push(...fieldErrors(child, document, entries[key], `${path ? path + " / " : ""}${labelFor(key, child)}`, schema.required?.includes(key) || false));
    for (const [key, child] of Object.entries(entries)) {
      if (schema.properties?.[key]) continue;
      const patterned = Object.entries(schema.patternProperties || {}).find(([pattern]) => new RegExp(pattern).test(key));
      const childSchema = patterned?.[1] || (typeof schema.additionalProperties === "object" ? schema.additionalProperties : undefined);
      if (schema.patternProperties && !patterned) errors.push(`${name} / ${key} has an invalid entry name.`);
      if (childSchema) errors.push(...fieldErrors(childSchema, document, child, `${name} / ${key}`));
    }
  }
  return errors;
}
