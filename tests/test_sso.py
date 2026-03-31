"""SSO / OIDC role mapping (GAP-077 companion tests)."""

from __future__ import annotations

import json


def test_resolve_sso_role_default_without_mapping():
    from types import SimpleNamespace

    from warlock.api import sso as sso_mod

    settings = SimpleNamespace(
        sso_default_role="viewer",
        sso_groups_claim="",
        sso_role_mapping="{}",
    )
    assert sso_mod._resolve_sso_role({"email": "a@b.com"}, settings) == "viewer"


def test_resolve_sso_role_from_groups_mapping():
    from types import SimpleNamespace

    from warlock.api import sso as sso_mod

    mapping = {"GRC-Admins": "admin", "GRC-Viewers": "viewer"}
    settings = SimpleNamespace(
        sso_default_role="viewer",
        sso_groups_claim="groups",
        sso_role_mapping=json.dumps(mapping),
    )
    claims = {"groups": ["GRC-Admins"]}
    assert sso_mod._resolve_sso_role(claims, settings) == "admin"


def test_resolve_sso_role_invalid_json_falls_back():
    from types import SimpleNamespace

    from warlock.api import sso as sso_mod

    settings = SimpleNamespace(
        sso_default_role="auditor",
        sso_groups_claim="groups",
        sso_role_mapping="not-json",
    )
    assert sso_mod._resolve_sso_role({"groups": ["x"]}, settings) == "auditor"
