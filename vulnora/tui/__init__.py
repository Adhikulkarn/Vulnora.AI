"""
Textual TUI module for Vulnora AI.

Provides the interactive, keyboard-driven terminal user interface
for real-time security inspection, surgical remediation, and pre-push guarding.
"""

from __future__ import annotations

from vulnora.tui.app import VulnoraTUIApp, launch_tui
from vulnora.tui.widgets import (
    ApiKeyModal,
    CodeDiffTabs,
    FindingsListView,
    ImmunityMetricsPanel,
    SentinelMascotPanel,
)

__all__ = [
    "VulnoraTUIApp",
    "launch_tui",
    "SentinelMascotPanel",
    "ImmunityMetricsPanel",
    "FindingsListView",
    "CodeDiffTabs",
    "ApiKeyModal",
]
