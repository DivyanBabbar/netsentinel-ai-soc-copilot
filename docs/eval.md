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

LLM triage and LLM injection results: **not run yet.** Add them here after running the two commands above with a real key, and record the model name and date.

## Making the evaluation credible
1. Grow the dataset to 50+ samples and include real logs (public datasets such as CIC-IDS2017, or a home lab).
2. Have someone else label the data, or label twice and measure agreement.
3. Replace the synthetic injection cases with a larger, more varied set that was not used to write the heuristics.
