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

def run_tool(tool_name: str, target: str, context_data: dict) -> list[dict]:
    """
    Run a single tool across the available surface.
    """

    if tool_name not in ALLOWED_TOOLS:
        logger.warning("Blocked tool not in allowlist: %s", tool_name)
        return []

    fn = _get_tool_fn(tool_name)
    if fn is None:
        logger.warning("No implementation found for tool: %s", tool_name)
        return []

    surface = _build_surface(target, context_data)
    findings = []

    for item in surface:
        try:
            results = fn(item, context_data)
            if results:
                findings.extend(results)
        except Exception as e:
            logger.error("%s failed on %s: %s", tool_name, item, e)

    logger.info("%s produced %d findings", tool_name, len(findings))
    return findings   


def run_tools(tool_names: list[str], target: str, context_data: dict) -> list[dict]:
    all_findings = []

    for tool in tool_names:
        all_findings.extend(
            run_tool(tool, target, context_data)
        )

    return all_findings