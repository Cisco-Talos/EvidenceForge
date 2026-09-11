# Output format definitions (developer-only)

This is not a project-overlay authoring reference. Installed output-format definitions are
engine-owned because emitters, parsers, evaluation rules, output targets, sidecars, and security
contracts must agree on their schemas.

Package format YAML lives under `src/evidenceforge/config/formats/`, including Windows, Sysmon,
eCAR, Zeek protocol/file/SMB views, proxy/web, IDS, and syslog formats. Query the live CLI or package
directory rather than relying on a fixed format count in skill text.

Use the scenario skill to select supported output formats and the evaluate skill to inspect their
quality. A request to add or change a format is a source-code development task. For an authorized
developer change, update the definition, renderer/emitter, parser, evaluator expectations,
documentation, and round-trip tests together.

Do not place format YAML under `.eforge/config`, expose it through a pack, or treat a copied package
file as a supported project override.
