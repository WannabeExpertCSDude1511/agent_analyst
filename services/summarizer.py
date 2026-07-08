"""
summarizer.py

Uses the project's existing Ollama endpoint to convert the Analyst's
raw findings into a concise handoff for the next agent (Prober).

The summary is meant for another LLM, not for an end user.
"""

import json
import logging
import os
import socket
import urllib.error
import urllib.request

logger = logging.getLogger("agent-analyst.summarizer")

OLLAMA_URL = os.getenv("OLLAMA_URL", "https://api.ollama.ai")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


def summarize_findings(findings: list[dict], context_data: dict) -> str:
    """
    Generate an LLM summary of the passive analysis results.

    Parameters
    ----------
    findings:
        Normalized findings from all passive tools.

    context_data:
        Parsed Mapper context (js_files, endpoints, urls).

    Returns
    -------
    str
        Concise summary for the next agent.
    """

    if not findings:
        return (
            "Passive analysis completed. No significant findings were detected. "
            "Continue probing any endpoints and assets discovered by Mapper."
        )

    system_message = """
You are the Analyst agent in a multi-agent penetration testing workflow.

Your output will be consumed by the Prober agent.

Summarize the passive analysis.

Focus on:
- Important discoveries
- Interesting attack surface
- Suspected weaknesses
- Recommended probing priorities

Do NOT list every finding.
Do NOT output JSON.
Keep the response under 150 words.
"""

    user_message = f"""
Mapper Context:

{json.dumps(context_data, indent=2)}

Passive Findings:

{json.dumps(findings, indent=2)}
"""

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "system": system_message,
        "prompt": user_message,
        "stream": False,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.getenv('OLLAMA_API_KEY', '')}",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode())

        summary = result.get("response", "").strip()

        if summary:
            return summary

    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        logger.warning("Ollama summarization unavailable: %s", e)

    except Exception as e:
        logger.warning("Failed to summarize findings: %s", e)

    # Fallback summary
    return (
        f"Passive analysis identified {len(findings)} finding(s). "
        "Review the findings and prioritize active verification."
    )
