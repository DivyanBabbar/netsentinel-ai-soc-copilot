# Roadmap

Checked items are done. No metric goes in this repo until it has been measured.

- [x] Single-page demo: retrieval, LLM triage, approval flow (`demo/index.html`)
- [x] Python package: BM25 retrieval, triage pipeline, output validation, FastAPI service
- [x] Curated 20-technique knowledge base with attribution
- [x] Action allowlist, target validation, protected targets, dry-run default, human approval endpoint
- [x] Slack webhook for ticket/on-call notifications (implemented, not yet tested against a live webhook)
- [x] Unit tests (standard library only), offline evaluation modes, and a GitHub Actions workflow that runs them
- [x] Labeled dataset (17 synthetic samples) and 6 injection cases
- [ ] Run LLM triage and injection evaluation with a real API key and record results in `docs/eval.md`
- [x] Run the API end to end locally with uvicorn: health, approval gate, dry-run, protected targets, allowlist and target validation behave as designed. Found and fixed a bare 500 on `/triage` when the model cannot be reached (now 503). The live model call itself is still untested. API tests added (`tests/test_api.py`).
- [x] Load full MITRE ATT&CK with `scripts/ingest_attack.py`: ran on the real file (697 techniques). Plain BM25 over the full matrix retrieves much worse than the curated 20, so the curated set stays the default (numbers in `docs/eval.md`)
- [ ] Embedding-based retrieval, compared against BM25 on the same dataset
- [ ] 50+ labeled samples including real logs
- [ ] Real containment integration (firewall or EDR API), still behind approval
- [ ] Web UI served by the backend
- [ ] Demo video and screenshots
