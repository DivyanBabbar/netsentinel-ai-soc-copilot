# NetSentinel: AI SOC Copilot

An LLM + RAG assistant that triages network security logs and proposes response actions for a human to approve.

**Status: early prototype.** The demo works, but retrieval is small and actions are simulated. See [Limitations](#limitations) and [docs/roadmap.md](docs/roadmap.md).

## What it does
1. Takes network logs (SSH auth, firewall, DNS, flow logs).
2. Retrieves relevant entries from a small playbook of attack techniques (RAG).
3. Sends logs + retrieved context to an LLM, which returns severity, attack type, evidence, technique IDs and proposed actions.
4. Shows proposed actions (block IP, open ticket, isolate host...) that an analyst approves. Approved actions are only written to an on-page log.

## Run the demo
`demo/index.html` was built for the Claude artifact runtime, where the AI call is provided by the host page (`claude.use("sample")`). Outside that runtime, retrieval works but the AI step will report that AI is unavailable. The roadmap replaces this with a standalone Python backend.

## Design notes
- **Retrieval:** keyword matching with idf weighting over 8 hand-written entries.
- **Untrusted input:** logs are treated as data in the prompt and all model output is rendered as plain text (no HTML injection).
- **Human in the loop:** nothing runs without approval.

## Limitations
- Knowledge base is tiny and hand-written, not real MITRE ATT&CK data.
- Retrieval is keyword-based, not embeddings.
- Automation is simulated; no real firewall or ticketing integration.
- No evaluation yet, so no accuracy claims are made.
- Sample logs are synthetic and use documentation IP ranges.

## Roadmap
See [docs/roadmap.md](docs/roadmap.md).

## License
MIT
