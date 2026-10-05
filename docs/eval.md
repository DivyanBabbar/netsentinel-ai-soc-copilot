# Evaluation

Run from the repository root (see README for setup).

| Mode | Command | Needs API key |
|---|---|---|
| Retrieval | `python -m eval.run_eval --mode retrieval` | no |
| Injection heuristic | `python -m eval.run_eval --mode guard` | no |
| LLM triage, with vs without RAG | `python -m eval.run_eval --mode triage` | yes |
| LLM injection resistance | `python -m eval.run_eval --mode injection` | yes |

## Data
- `eval/dataset.jsonl`: 17 synthetic labeled log samples (13 attacks, 4 benign). Labels were written by the project author and are a judgment call, especially severity.
- `eval/injection_cases.jsonl`: 6 logs with planted instructions.
- A technique counts as a match if the ID family matches (`T1110` and `T1110.003` are the same family).

## Results so far (offline modes only)
| Check | Result | How to read it |
|---|---|---|
| Retrieval hit@1 | 10 / 13 | Top result was the right technique family |
| Retrieval hit@3 | 13 / 13 | Right family was in the top three |
| Injection heuristic | flagged 6 / 6 attack cases, 0 / 17 false alarms | Patterns were written while looking at these cases, so this is optimistic |

**These numbers are a sanity check, not a benchmark.** The knowledge base, the logs and the labels were all written by the same person, and the set is tiny. Treat them as "the pipeline works", not "the pipeline is accurate".

## Full ATT&CK vs the curated knowledge base (measured October 2026)
Same 13 attack samples, same BM25 retriever, different knowledge bases. Reproduce:
```bash
python scripts/ingest_attack.py enterprise-attack.json knowledge_base/attack_full.json
python -m eval.run_eval --mode retrieval --kb knowledge_base/attack_full.json
# and with --skip-pre-attack on the ingest step for the third row
```
| Knowledge base | Techniques | hit@1 | hit@3 |
|---|---|---|---|
| Curated (default) | 20 | 10 / 13 | 13 / 13 |
| Full ATT&CK, `ingest_attack.py` output | 697 | 1 / 13 | 2 / 13 |
| Full ATT&CK with `--skip-pre-attack` | 601 | 2 / 13 | 5 / 13 |

How to read it: plain BM25 over the whole matrix retrieves much worse than the small curated set. The curated set was written next to this dataset, so its 13 / 13 is optimistic, and 13 samples is tiny. What this does support is that "load full ATT&CK" is not a drop-in upgrade, and that embedding-based retrieval (see the roadmap) is worth trying. The curated set stays the default.

LLM triage and LLM injection results: **not run yet.** Add them here after running the two commands above with a real key, and record the model name and date.

## Making the evaluation credible
1. Grow the dataset to 50+ samples and include real logs (public datasets such as CIC-IDS2017, or a home lab).
2. Have someone else label the data, or label twice and measure agreement.
3. Replace the synthetic injection cases with a larger, more varied set that was not used to write the heuristics.
