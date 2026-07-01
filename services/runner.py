"""
runner.py — Person B owns this file.

Executes the selected tools and collects all their findings.

Picks between mock mode (TOOL_MOCK_MODE=true, default) and
real mode (TOOL_MOCK_MODE=false, needs Kali binaries installed).

Each tool is called for every surface item (JS file or endpoint)
that came from the Mapper context. If no surface was passed,
tools run against the raw target URL.

A single tool failure never crashes the whole request — the error
is logged and that tool returns [] for that item.
"""

import logging
import os

from tools.mock_tools import MOCK_TOOL_MAP
from tools.wrappers import REAL_TOOL_MAP

logger = logging.getLogger("agent-analyst.runner")

MOCK_MODE = os.getenv("TOOL_MOCK_MODE", "true").lower() == "true"

ALLOWED_TOOLS = [
    "httpx", "trufflehog", "secretfinder", "linkfinder",
    "gitleaks", "git_secrets", "mapextractor", "jshole",
    "nuclei_passive", "httpx_enrichment",
]


def _get_tool_fn(tool_name: str):
    """Return the right function for the tool based on mock/real mode."""
    tool_map = MOCK_TOOL_MAP if MOCK_MODE else REAL_TOOL_MAP
    return tool_map.get(tool_name)


def _build_surface(target: str, context_data: dict) -> list[str]:
    """
    Build the list of URLs/files to analyze.
    Prefers what Mapper discovered; falls back to the raw target.
    """
    surface = []
    surface.extend(context_data.get("js_files", []))
    surface.extend(context_data.get("urls", []))
    # endpoints are paths like /api/users — prefix with target
    for ep in context_data.get("endpoints", []):
        if ep.startswith("http"):
            surface.append(ep)
        else:
            surface.append(target.rstrip("/") + ep)

    if not surface:
        surface = [target]

    return surface


def run_tools(tool_names: list[str], target: str, context_data: dict) -> list[dict]:
    """
    Run each selected tool against each surface item.
    Returns a flat list of all findings across all tools and items.
    """
    # Enforce allowlist — never run a tool not in our list
    safe_tools = [t for t in tool_names if t in ALLOWED_TOOLS]
    if len(safe_tools) < len(tool_names):
        blocked = set(tool_names) - set(safe_tools)
        logger.warning("Blocked tools not in allowlist: %s", blocked)

    surface = _build_surface(target, context_data)
    logger.info("Running %d tool(s) across %d surface item(s)", len(safe_tools), len(surface))
    logger.info("Mode: %s", "MOCK" if MOCK_MODE else "REAL")

    all_findings = []

    for tool_name in safe_tools:
        fn = _get_tool_fn(tool_name)
        if fn is None:
            logger.warning("No implementation found for tool: %s", tool_name)
            continue

        for item in surface:
            try:
                results = fn(item, context_data)
                if results:
                    all_findings.extend(results)
                    logger.info("%s found %d finding(s) on %s", tool_name, len(results), item)
            except Exception as e:
                # One tool failing on one item should NOT crash everything
                logger.error("%s failed on %s: %s", tool_name, item, e)

    logger.info("Total findings: %d", len(all_findings))
    return all_findings
