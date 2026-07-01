"""
task_service.py — Person B owns this file.

This is the single integration point between your work (Person B)
and Praneet's work (Person A).

Praneet's routes.py calls exactly ONE thing:
    TaskService.execute(request)

And gets back:
    {
        "agent_id": "agent-analyst",
        "status":   "completed",
        "response": {
            "summary":  "...",
            "findings": [...]
        }
    }

Everything else (parser, selector, runner, aggregator) is internal
to this service. Praneet never touches those files.
"""

import logging
import traceback

from services.parser      import parse_context
from services.selector    import select_tools
from services.runner      import run_tools
from services.aggregator  import aggregate

logger = logging.getLogger("agent-analyst.task_service")

AGENT_ID = "agent-analyst"


class TaskService:

    @staticmethod
    def execute(request) -> dict:
        """
        Main entry point. Accepts the FastAPI request object (or any
        object with .prompt, .target, .context attributes).

        Returns the full API response dict.
        """
        try:
            target = request.target
            logger.info("New task | target=%s | prompt=%s", target, request.prompt[:80])

            # Step 1: parse what Mapper sent us
            context_data = parse_context(request.context or {})
            logger.info("Surface from context: %s", context_data)

            # Step 2: use Ollama (or keyword fallback) to pick tools
            tools = select_tools(request.prompt)
            logger.info("Selected tools: %s", tools)

            # Step 3: run the tools and collect findings
            findings = run_tools(tools, target, context_data)

            # Step 4: build summary + structured response
            response_body = aggregate(findings)

            return {
                "agent_id": AGENT_ID,
                "status":   "completed",
                "response": response_body,
            }

        except Exception as e:
            logger.error("Task failed: %s\n%s", e, traceback.format_exc())
            return {
                "agent_id": AGENT_ID,
                "status":   "failed",
                "response": {
                    "error":   str(e),
                    "summary": "Task failed due to an internal error.",
                    "findings": [],
                },
            }
