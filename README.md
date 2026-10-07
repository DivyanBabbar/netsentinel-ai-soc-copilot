# NetSentinel: AI SOC Copilot

An LLM + RAG assistant that triages network security logs and proposes response actions that a human approves.

**Status: working prototype, partly verified.** Core logic and tests run offline. The API layer has been run locally end to end except for the live model call. Live LLM evaluation has not been run. See [docs/eval.md](docs/eval.md) and [docs/roadmap.md](docs/roadmap.md) for exactly what is and is not done.

## How it works
1. **Sanitize and flag** the logs (control characters stripped, delimiter tags removed, injection patterns flagged).
2. **Retrieve** the most relevant ATT&CK-style techniques from the knowledge base with BM25.
3. **Triage** with an LLM: logs go in as untrusted data, playbook context as reference.
4. **Validate** everything the model returns: JSON shape, severity, technique IDs (unknown ones are flagged), and each proposed action.
5. **Approve** - actions require explicit approval. Live mode additionally requires DRY_RUN=false and a private ACTION_APPROVAL_TOKEN sent in the X-Action-Approval-Token header. Keep that token in a trusted operator tool; never put it in the browser demo.

Architecture diagram and threat model: [docs/architecture.md](docs/architecture.md).

## Quick start (Windows PowerShell)
```powershell
git clone https://github.com/DivyanBabbar/netsentinel-ai-soc-copilot.git
cd netsentinel-ai-soc-copilot
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt   # requirements.txt plus httpx, needed only for the API tests

# Tests and offline evaluation (no API key needed)
python -m unittest discover -s tests -t .
python -m eval.run_eval --mode retrieval
python -m eval.run_eval --mode guard

# Run the service
$env:ANTHROPIC_API_KEY = "your-key"
uvicorn netsentinel.api:app --reload
```
Linux/macOS: use `source .venv/bin/activate` and `export ANTHROPIC_API_KEY=...`.

Try it:
```powershell
$body = @{ logs = "Failed password for root from 203.0.113.45`nFailed password for admin from 203.0.113.45`nAccepted password for deploy from 203.0.113.45" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/triage -ContentType "application/json" -Body $body
```
Interactive docs at `http://127.0.0.1:8000/docs`. Configuration variables are listed in `.env.example`.

## Repository layout
| Path | Purpose |
|---|---|
| `netsentinel/retriever.py` | BM25 retrieval (standard library) |
| `netsentinel/triage.py` | Prompting, model call, output validation |
| `netsentinel/guard.py` | Log sanitizing and injection flags |
| `netsentinel/actions.py` | Action allowlist, validation, dry-run execution, Slack notify |
| `netsentinel/api.py` | FastAPI service |
| `knowledge_base/` | Curated technique data and attribution |
| `scripts/ingest_attack.py` | Convert the full MITRE ATT&CK bundle (run on the real file; BM25 over the full matrix retrieves worse than the curated set, see docs/eval.md) |
| `eval/` | Labeled data and evaluation runner |
| `tests/` | Unit tests |
| `demo/index.html` | Original single-page demo for the Claude artifact runtime |

## Limitations
- Retrieval is keyword-based over 20 techniques, not embeddings over the full matrix.
- Real containment (firewall, IAM, EDR) is not connected; only Slack notifications are implemented.
- Evaluation data is small and synthetic. No accuracy claims are made. LLM results are not yet recorded.
- Injection heuristics are a tripwire; the real defenses are output validation and explicit approval.
- Live actions stay disabled unless a private operator token is configured; keep it out of browser code and client-side logs.

## License and attribution
MIT. MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation; technique text here is a paraphrase.
