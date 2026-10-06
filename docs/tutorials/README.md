# Tutorials

Tutorials are guided learning paths for someone new to FAS.

## First local analysis

Install FAS, inspect the environment, analyze an authorized project, and inspect the result:

    python -m pip install -e ".[dev]"
    fas doctor --format json
    fas tools --format json
    fas analyze ./path-to-project --format json
    fas status <analysis-id> --format json
    fas findings <analysis-id> --format json
    fas report <analysis-id> --format json

The important boundary is: observation ≠ evidence ≠ finding ≠ verdict.

FAS preserves this separation so a tool signal is not silently promoted into a security conclusion.

## Remediation verification

Follow [How to verify a remediation](../how-to/verify-remediation.md). Focus on original snapshot identity, supporting and contradicting evidence, changed graph relationships, original attack-path accounting, residual paths, required checks, and the final evidence-backed verdict.

## AI-assisted investigation

Read [AI-assisted investigation](../explanation/ai-investigation.md) before using model-assisted workflows. The safe loop is hypothesis → evidence request → deterministic collection → verified evidence → reassessment.
