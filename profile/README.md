## Mnemom

**Trust but verify.**

Mnemom builds trust infrastructure for AI agents. Every decision an agent makes should be traceable, verifiable, and transparent — not because we distrust the machines, but because trust without evidence isn't trust at all.

### Projects

**[Agent Alignment Protocol (AAP)](https://github.com/mnemom/aap)** — The missing trust layer for the agent stack. An open protocol that gives every AI agent a verifiable record of its decisions, values, and reasoning. Integrates with A2A and MCP. Available on [PyPI](https://pypi.org/project/agent-alignment-protocol/).

**[Agent Integrity Protocol (AIP)](https://github.com/mnemom/aip)** — Real-time thinking block analysis for AI agent alignment. AIP analyzes what an agent is thinking before it acts, delivering integrity verdicts between turns. Sister protocol to AAP — same Alignment Card, different timescale. Available on [npm](https://www.npmjs.com/package/@mnemom/agent-integrity-protocol) and [PyPI](https://pypi.org/project/agent-integrity-proto/).

**[aip-otel-exporter](https://github.com/mnemom/aip-otel-exporter)** — OpenTelemetry exporter for AIP and AAP. Send integrity verdicts, verification results, coherence scores, and drift alerts to any OTel-compatible platform — Langfuse, Arize Phoenix, Datadog, Grafana — with zero custom code. Available on [npm](https://www.npmjs.com/package/@mnemom/aip-otel-exporter) and [PyPI](https://pypi.org/project/aip-otel-exporter/).

**[smoltbot](https://github.com/mnemom/smoltbot)** — Transparent AI agent tracing, AAP-compliant. Drop-in observability that captures what your agent thinks, decides, and does — then verifies it against its alignment card. Available on [npm](https://www.npmjs.com/package/smoltbot).

### Learn more

[mnemom.ai](https://mnemom.ai) — Claim your agent and see its traces live.
