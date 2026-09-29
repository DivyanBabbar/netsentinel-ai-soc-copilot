# Roadmap

Checked items are done. Do not add metrics here until they are measured.

- [x] Single-page demo: retrieval, LLM triage, approval flow
- [ ] Python backend (FastAPI) with a vector store (Chroma or FAISS) and real embeddings
- [ ] Load real MITRE ATT&CK data as the knowledge base
- [ ] Run on real logs (public dataset such as CIC-IDS2017, Zeek/Suricata samples, or a home lab)
- [ ] Labeled evaluation set (30-50 samples): triage accuracy, hallucination rate, retrieval hit rate, with vs without RAG
- [ ] Prompt-injection tests: attacker-controlled text inside logs, document results
- [ ] Real automation via webhook (Slack or ticketing), keeping human approval
- [ ] Architecture diagram and short demo video in README
