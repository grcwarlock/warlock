# Warlock TODO

Items identified from v1 ZIP comparison (2026-03-19). Not blocking — operational/documentation quality.

## Medium Priority

- [ ] **DEPLOYMENT_GUIDE.md** — Port and update the 765-line production ops guide from v1 (cron scheduling, Lambda packaging, Docker/ECS, alerting setup, troubleshooting). Currently only have DEMO.md for local use.
- [ ] **CHANGELOG.md** — Create release history. v1 had 142 lines of changelog.
- [ ] **CONTRIBUTING.md** — Create contribution guidelines (branching, PR process, code style, test requirements).
- [ ] **Wire FedRAMP/HIPAA/CMMC/GDPR framework checks to event_types** — The 4 new framework YAMLs load but don't produce active control mappings because their checks don't reference connector event_types. Need to author the event_type + resource_type mappings for each control.
- [ ] **Crosswalks with confidence scores** — The v1 `config/crosswalks.yaml` (873 lines) has `confidence: "high/medium/low"` and notes per mapping. Our crosswalks.yaml has edges but no confidence metadata.

## Low Priority

- [ ] **demo_exports/** — Pre-generated sample audit packages, executive summaries, POA&M exports for showing output without running the platform.
- [ ] **docs/architecture-diagram.html** — Visual architecture diagram from v1.
- [ ] **Warlock_Technical_Documentation.pdf** — 1.3MB technical doc from v1. Review for reusable content.
- [ ] **Celery integration** — v1 had `celery_app.py` + `docker-compose.celery.yaml` as an alternative task queue. The repo has Redis/Kafka/SQS in `pipeline/queue.py` but no Celery option.
- [ ] **nltk CVE remediation** — `nltk 3.9.3` has CVE-2026-33230 and CVE-2026-33231. Pin to patched version when available, or isolate the RAG module as an optional extra.
