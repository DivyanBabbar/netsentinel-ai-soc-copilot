# Roadmap

Checked items are done. No metric goes in this repo until it has been measured.

- [x] Single-page demo: retrieval, LLM triage, approval flow (`demo/index.html`)
- [x] Python package: BM25 retrieval, triage pipeline, output validation, FastAPI service
- [x] Curated 20-technique knowledge base with attribution
- [x] Action allowlist, target validation, protected targets, dry-run default, human approval endpoint
- [x] Slack webhook for ticket/on-call notifications (implemented, not yet tested against a live webhook)
- [x] Unit tests (27, standard library only) and offline evaluation modes
- [x] Labeled dataset (17 synthetic samples) and 6 injection cases
- [ ] Run LLM triage and injection evaluation with a real API key and record results in `docs/eval.md`
- [ ] Run the API end to end in a full environment and fix whatever breaks
- [ ] Load full MITRE ATT&CK with `scripts/ingest_attack.py` (written, not yet run on the real file)
- [ ] Embedding-based retrieval, compared against BM25 on the same dataset
- [ ] 50+ labeled samples including real logs
- [ ] Real containment integration (firewall or EDR API), still behind approval
- [ ] Web UI served by the backend
- [ ] Demo video and screenshots
