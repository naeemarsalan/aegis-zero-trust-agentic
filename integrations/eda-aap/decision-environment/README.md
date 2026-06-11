# Decision Environment — Agent Remediation

## TL;DR — Default DE is sufficient

The `agent-remediation` rulebook uses only:

- `ansible.eda.webhook` (local-dev fallback source)
- `ansible.eda.event_stream` (production; built in)
- `run_job_template` action (built in to EDA engine)

All of these are present in the **default DE** that ships with AAP 2.6
(`de-supported-rhel9`).  You do **not** need to build or push a custom DE
unless you extend this rulebook with additional event sources.

## When to build a custom DE

Build `de.yml` if you add sources that require extra Python packages, e.g.:

- `ansible.eda.kafka` (requires `aiokafka`)
- `ansible.eda.aws_sqs_queue` (requires `boto3`)
- Any community collection not included in `de-supported`

## Build and push (if needed)

```bash
# Requires ansible-builder >= 3.x and podman
ansible-builder build \
  -f integrations/eda-aap/decision-environment/de.yml \
  -t oci.arsalan.io/nvidia-ida/agent-remediation-de:dev \
  --container-runtime podman

podman push oci.arsalan.io/nvidia-ida/agent-remediation-de:dev
```

Then in `setup.sh` or the AAP UI, set the rulebook activation's
`decision_environment` to the pushed image URL.

## Base image registry auth

```bash
podman login registry.redhat.io
# Use your Red Hat subscription credentials or a registry service account.
```
