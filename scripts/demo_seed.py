#!/usr/bin/env python3
"""Seed a full-stack demo environment with all 351 connectors.

No real credentials or API keys needed. 351 mock connectors produce realistic
events from cloud, IAM, EDR, SIEM, scanners, ITSM, code security, DLP, backup,
physical security, and more. All events flow through the real pipeline
(collect -> normalize -> map -> assess) exercising every normalizer (352),
every assertion (101), and every framework (14).

Implementation is split under ``scripts/seed_impl/`` for maintainability; this
file remains the CLI entry and re-exports ``CONNECTOR_CONFIGS`` for
``warlock connectors``.

Usage:
    python scripts/demo_seed.py          # seed + run pipeline (~7s)
    warlock coverage                     # compliance summary across 14 frameworks
    warlock findings                     # ~5,475 findings from 165 sources
    warlock results --status non_compliant
    warlock sources                      # 351 connectors + 351 normalizers
    warlock systems                      # 5 system profiles
    warlock issues                       # compliance issues
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure warlock package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.seed_impl.connector_config_lists import CONNECTOR_CONFIGS
from scripts.seed_impl.main import main

__all__ = ["CONNECTOR_CONFIGS", "main"]


if __name__ == "__main__":
    main()
