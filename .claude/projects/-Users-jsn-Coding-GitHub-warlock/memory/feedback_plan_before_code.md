---
name: Plan before code for each phase
description: Each data lake phase needs a detailed implementation plan reviewed by code-reviewer + grc-unicorn before coding starts
type: feedback
---

Never jump from completing one phase to coding the next without writing a detailed implementation plan first.

**Why:** User and I agreed on approach A — write Phase N plan, implement it, then plan Phase N+1 based on validated learnings. I violated this after Phase 0 by writing a 30-line skeleton and immediately dispatching implementers for Phase 1. The Phase 0 plan was 1,259 lines of detail. Phase 1 deserved the same.

**How to apply:** After completing any phase, the next step is ALWAYS: (1) write detailed plan at same fidelity as Phase 0 plan, (2) review with code-reviewer + grc-unicorn agents, (3) present to user for approval, (4) only then execute. If user says "just go" — still write the plan, just don't wait for approval before executing.
