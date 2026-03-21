"""Tests for data lake infrastructure."""

import os
import pytest


class TestLakeConfig:
    def test_lake_disabled_by_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_enabled is False

    def test_lake_path_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_path == "lake"

    def test_lake_catalog_type_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_catalog_type == "sqlite"
