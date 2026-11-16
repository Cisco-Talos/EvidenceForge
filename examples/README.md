# Example scenarios

This is the offline example collection included in Python distributions and Studio.
The collection is intentionally empty until reviewed examples are contributed.

Each example is an immutable published scenario under the `evidenceforge` publisher:

```text
examples/<scenario-name>/<version>/
  release.json
  source/scenario.yaml
  source/ENVIRONMENT.md          # when supplied by authoring
  source/...                    # includes, email corpora, research and other authored assets
  dependencies/...
  configuration/...
```

Use the existing publication tools; do not construct or edit release receipts manually.
For unusually long identifiers, use the storage directory name produced by publication.

## Contributing an example

1. Author and validate a scenario using the normal scenario workflow. Work in an isolated
   authoring workspace with the explicitly configured `evidenceforge` publisher.
2. Include all authored companions in the managed draft's `source/` directory. Keep generated
   logs, generated ground truth and checkpoints outside that source directory.
3. Publish the draft with `eforge scenario publish <draft-path> --project-root <authoring-workspace>`.
   Resolve errors and review any warnings before accepting them through the existing workflow.
4. Copy the entire published release directory into `examples/<scenario-name>/<version>/`,
   including its receipt, source tree, dependencies and configuration.
5. Submit the content through normal review and CI. Discovery and packaging are automatic;
   no scenario registration code is needed. Ship it in the next authorized product release.

Publish another scenario version to revise an example. Never change a distributed version.
Do not include generated datasets or secrets in this collection. Required inputs and dependencies
must work offline without references to the author's filesystem.

## Using the collection without Studio

In a checkout, browse this directory. Installed Python packages contain the same files at
`evidenceforge/_data/examples/` beneath the installation's site-packages directory. For example,
`uv run python -c 'from evidenceforge.examples import examples_directory; print(examples_directory())'`
prints the location in the selected Python environment.

Copy a complete release folder to a writable location to browse or generate from its
`source/scenario.yaml`. To create an editable copy, use the existing
`eforge scenario draft <source/scenario.yaml> --publisher <your-publisher>` operation in your
authoring workspace. Published examples remain immutable. Set up your publisher through the
existing publisher workflow before publication. Native authoring skills use the same files.

Portable `.efscenario` exports can also be shared and imported through the existing scenario
import workflow. Older Studio versions do not download examples added to later releases.
