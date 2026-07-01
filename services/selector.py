"""
selector.py — Person B owns this file.

Decides which tools to run based on the natural-language prompt.

Uses Ollama (local LLM) to interpret the prompt and return a list
of tool names. If Ollama is not running or times out, falls back
to simple keyword rules so the agent always works.

ALLOWED tools for agent-analyst (the allowlist):
    trufflehog, secretfinder, linkfinder, gitleaks, git_secrets,
    mapextractor, jshole, nuclei_passive, httpx_enrichment, httpx
"""

import json
import logging
import os
import socket
import urllib.error
import urllib.request

logger = logging.getLogger("agent-analyst.selector")

OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

ALLOWED_TOOLS = [
    "trufflehog",
    "secretfinder",
    "linkfinder",
    "gitleaks",
    "git_secrets",
    "mapextractor",
    "jshole",
    "nuclei_passive",
    "httpx_enrichment",
    "httpx",
]

# Used by Ollama so it knows what tools exist
TOOL_DESCRIPTIONS = """
trufflehog      - scans files for leaked secrets (AWS keys, GitHub tokens, API keys)
secretfinder    - scans JavaScript files for API keys, tokens, passwords
linkfinder      - extracts hidden API endpoints and routes from JavaScript files
gitleaks        - detects secrets inside git repositories using pattern matching
git_secrets     - checks source code for accidentally committed credentials
mapextractor    - extracts exposed JavaScript source maps (.js.map files)
jshole          - detects known vulnerable JavaScript libraries (e.g. old jQuery)
nuclei_passive  - runs passive Nuclei templates (exposed panels, config issues)
httpx_enrichment - collects HTTP metadata like headers, status codes, redirects
httpx           - verifies the target is alive and reachable
"""


def _ask_ollama(prompt: str) -> list[str] | None:
    """
    Ask the local Ollama model which tools to run.
    Returns a list of tool names, or None if Ollama is unavailable.
    """
    system_message = """You are a security tool selector.

Return ONLY a JSON array.

Allowed tools:
[
"trufflehog",
"secretfinder",
"linkfinder",
"gitleaks",
"git_secrets",
"mapextractor",
"jshole",
"nuclei_passive",
"httpx_enrichment",
"httpx"
]

Always include "httpx".

Do not explain your reasoning.
Do not output markdown.
"""

    user_message = prompt

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": user_message,
        "system": system_message,
        "stream": False,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode())
            raw = result.get("response", "").strip()
            raw = raw.replace("```json", "").replace("```", "").strip()
            # Parse the JSON array Ollama returned
            tool_list = json.loads(raw)

            # Validate — only keep tools in our allowlist
            valid = [t for t in tool_list if t in ALLOWED_TOOLS]

            if valid:
                logger.info("Ollama selected tools: %s", valid)
                return valid

    except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
        logger.warning("Ollama unavailable or timed out (%s). Using keyword fallback.", e)
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Could not parse Ollama response: %s — using keyword fallback", e)

    return None


def _keyword_fallback(prompt: str) -> list[str]:
    """
    Simple keyword-based tool selection used when Ollama is unavailable.
    No AI needed — just check what words are in the prompt.
    """
    prompt_lower = prompt.lower()
    selected = set()

    if any(w in prompt_lower for w in ["secret", "credential", "token", "key", "password", "leak"]):
        selected.update(["trufflehog", "gitleaks", "secretfinder", "git_secrets"])

    if any(w in prompt_lower for w in ["javascript", "js", "script", "bundle"]):
        selected.update(["linkfinder", "secretfinder", "jshole"])

    if any(w in prompt_lower for w in ["endpoint", "api", "route", "path", "url"]):
        selected.update(["linkfinder", "mapextractor"])

    if any(w in prompt_lower for w in ["sourcemap", "source map", ".map"]):
        selected.update(["mapextractor"])

    if any(w in prompt_lower for w in ["passive", "header", "misconfig", "panel", "exposed"]):
        selected.update(["nuclei_passive", "httpx_enrichment"])

    if any(w in prompt_lower for w in ["library", "vulnerable", "outdated", "cve"]):
        selected.update(["jshole"])

    if not selected:
        # Default: run the full passive suite
        selected.update([t for t in ALLOWED_TOOLS if t != "httpx"])

    # Always include httpx for liveness check
    selected.add("httpx")

    result = list(selected)
    logger.info("Keyword fallback selected tools: %s", result)
    return result


def select_tools(prompt: str) -> list[str]:
    """
    Main entry point. Tries Ollama first, falls back to keywords.
    Always returns a non-empty list of allowlisted tool names.
    """
    tools = _ask_ollama(prompt)
    if tools:
        # Make sure httpx is always included even if Ollama forgot it
        if "httpx" not in tools:
            tools.insert(0, "httpx")
        return tools

    return _keyword_fallback(prompt)
