# Evals
Goal: measure how often operator + agent matches an expert's decision.

`cases.jsonl` – one object per line:
`{"cve": "...", "context": {...}, "expert_priority": 1-5, "expert_action": "...", "acceptable_actions": ["..."]}`

Metrics: rank agreement (Spearman) on priority, action accuracy, review-flag precision/recall.
Target for the MVP: 20 cases.
