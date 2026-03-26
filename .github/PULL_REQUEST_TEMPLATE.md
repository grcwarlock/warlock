## Summary
<!-- What does this PR do? One or two sentences. -->

## Changes
<!-- List files changed and why. -->
- `path/to/file.py` -- Description of change

## Testing
- [ ] `pytest tests/` passes (509+ baseline)
- [ ] `ruff check warlock/` passes
- [ ] `ruff format --check warlock/` passes
- [ ] Demo seed produces expected numbers (165/0/589/~5475/373852)
- [ ] No new security vulnerabilities introduced
- [ ] QA gate passes (`./scripts/qa.sh`)

## Demo Verification
<!-- If you changed pipeline, models, connectors, normalizers, seed, or config: -->
```
Connectors succeeded:   351
Connectors failed:      0
Raw events collected:   589
Findings normalized:    ~5,475
Controls mapped:        373,852
```

## Related
<!-- Link to backlog items, issues, or context. e.g., H-12, PG-1, closes #123 -->
